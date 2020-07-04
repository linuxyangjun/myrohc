/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	date: 2020/4/22
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/types.h>


#include "../rohc_common.h"
#include "../rohc_packet.h"
#include "../rohc_cid.h"
#include "../rohc_profile.h"
#include "../lsb.h"
#include "../rohc_ipid.h"
#include "../rohc_bits_encode.h"
#include "../profile/tcp_packet.h"
#include "../profile/tcp_profile.h"


#include "rohc_decomp.h"
#include "rohc_decomp_wlsb.h"
#include "rohc_decomp_packet.h"
#include "decomp_tcp.h"
#include "decomp_tcp_clist.h"
static void tcp_recover_net_header_dump(struct sk_buff *skb,int cid,u32 msn)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	u8 *addr;
	int i,len;
	u32 *opt;
	//if(cid != 0)
	//	return;
	iph = ip_hdr(skb);
	rohc_pr(ROHC_DTCP,"DECOMP_TCP cid : %d msn:%d,totoal_length:%d\n",cid,msn,skb->len);
	rohc_pr(ROHC_DTCP,"ipid=%d,id_off_msn=%u,tos=%d,ttl=%d,iphl=%d,pro=%d,tot_len=%d,fragof=%x,check=%x\n",ntohs(iph->id),ntohs(iph->id) - msn,iph->tos,iph->ttl,iph->ihl,iph->protocol,ntohs(iph->tot_len),iph->frag_off,iph->check);
	addr = (u8 *)&iph->saddr;
	rohc_pr(ROHC_DTCP,"ipsrc:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	addr = (u8 *)&iph->daddr;
	rohc_pr(ROHC_DTCP,"ipdst:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	tcph = tcp_hdr(skb);
	rohc_pr(ROHC_DTCP,"dport=%d,sport=%d,doff=%d,check=%x\n",ntohs(tcph->source),ntohs(tcph->dest),tcph->doff,tcph->check);
	rohc_pr(ROHC_DTCP,"res1=%d\n",tcph->res1);
	rohc_pr(ROHC_DTCP,"seq=%x,ack_seq=%x\n",ntohl(tcph->seq),ntohl(tcph->ack_seq));
	rohc_pr(ROHC_DTCP,"fin=%d,syn=%d,rst=%d,psh=%d,ack=%d,urg=%d,ece=%d,cwr=%d\n",tcph->fin,tcph->syn,tcph->rst,tcph->psh,tcph->ack,tcph->urg,tcph->ece,tcph->cwr);
	rohc_pr(ROHC_DTCP,"win=%d,urg_ptr=%d\n",ntohs(tcph->window),ntohs(tcph->urg_ptr));

	opt  =  (u32 *)(tcph + 1);
	len = (tcph->doff * 4 - sizeof(struct tcphdr)) / 4;
	rohc_pr(ROHC_DTCP,"tcp option length:%d \n",len * 4);
	for(i = 0 ; i < len ;i++,opt++){
		rohc_pr(ROHC_DTCP,"[%d] 0x%08x\n",i,*opt);
	}

}
static bool ecn_is_carryed(struct decomp_tcp_context *d_tcp_context)
{
	struct last_decomped_tcp_common *co_ref;
	struct decomp_tcp_common_update *co_update;
	bool ecn_used;
	co_ref = &d_tcp_context->co_ref;
	co_update = &d_tcp_context->co_update;
	if(analyze_field_is_carryed(&co_update->ecn_used))
		ecn_used = co_update->ecn_used.value;
	else
		ecn_used = co_ref->ecn_used;
	return ecn_used;
}
static inline void tcp_ecn_decode(u8 ecn,struct tcphdr *tcph)
{
	#define	ECE_BIT (1 << 0)
	#define	CWR_BIT	(1 << 1)
	if(ecn & ECE_BIT)
		tcph->ece = 1;
	else
		tcph->ece = 0;

	if(ecn & CWR_BIT)
		tcph->cwr = 1;
	else
		tcph->cwr = 0;
}
static inline void tcp_rsf_decode(u8 rsf_index,struct analyze_field *fin,struct analyze_field *syn,struct analyze_field *rst)
{

	switch(rsf_index){
		case 0:
			/*fin ,syn and rst are all zero*/
			decomp_fill_analyze_field(fin,0);
			decomp_fill_analyze_field(syn,0);
			decomp_fill_analyze_field(rst,0);
			break;
		case 1:
			/*rst only*/
			decomp_fill_analyze_field(rst,1);
			decomp_fill_analyze_field(fin,0);
			decomp_fill_analyze_field(syn,0);
			break;
		case 2:
			/*only syn*/
			decomp_fill_analyze_field(syn,1);
			decomp_fill_analyze_field(fin,0);
			decomp_fill_analyze_field(rst,0);
			break;
		case 3:
			/*only fin*/
			decomp_fill_analyze_field(fin,1);
			decomp_fill_analyze_field(syn,0);
			decomp_fill_analyze_field(rst,0);
			break;
		default:
			rohc_pr(rohc_err,"not only one bit rsf_index:%x\n",rsf_index);
			break;
	}

}
static inline void tcp_rsf_decode_full(u8 rsf,struct analyze_field *fin,struct analyze_field *syn,struct analyze_field *rst)
{
#define	FIN_BIT		(1 << 0)
#define	SYN_BIT		(1 << 1)
#define	RST_BIT		(1 << 2)
	if(rsf & FIN_BIT)
		decomp_fill_analyze_field(fin,1);
	else
		decomp_fill_analyze_field(fin,0);
	if(rsf & SYN_BIT)
		decomp_fill_analyze_field(syn,1);
	else
		decomp_fill_analyze_field(syn,0);
	if(rsf & RST_BIT)
		decomp_fill_analyze_field(rst,1);
	else
		decomp_fill_analyze_field(rst,0);
}
/*the follow inline analyze function must change each field value to cpu byte order */

static inline int tcp_ip_field_vari_length_32_analyze(u8 *from,struct wlsb_analyze_field *field,u8 ind)
{
	int analyze_len;
	u32 encode_v;
	switch(ind){
		case 0:
			analyze_len = 0;
			break;
		case 1:
			encode_v = *from;
			analyze_len = 1;
			decomp_wlsb_fill_analyze_field_contain_p(field,encode_v,8,63,true);
			break;
		case 2:
			/*big endian*/
			encode_v = *from;
			from++;
			encode_v = (encode_v << 8) | (*from);
			analyze_len = 2;
			decomp_wlsb_fill_analyze_field_contain_p(field,encode_v,16,16383,true);
			break;
		case 3:
			encode_v = *(u32 *)from;
			/*network byte oder,it is the original value*/
			analyze_len = 4;
			decomp_wlsb_fill_analyze_field(field,encode_v,32,false);
			break;
	}
	return analyze_len;
}
static inline int tcp_ip_field_static_or_irreg16_analyze(u8 *from,struct analyze_field *field ,u8 ind)
{
	int len;
	u16 encode_v;
	if(!ind)
		len = 0;
	else{
		/*keep network byte order*/
		memcpy(&encode_v,from,2);
		decomp_fill_analyze_field(field,encode_v);
		len = 2;
	}
	return len;
}

static inline int tcp_ip_field_static_or_irreg16_analyze_to_cpu(u8 *from,struct analyze_field *field,u8 ind)
{
	int len;
	u16 encode_v;
	if(!ind)
		len = 0;
	else{
		memcpy(&encode_v,from,2);
		/*change to cpu byte order*/
		encode_v = ntohs(encode_v);
		decomp_fill_analyze_field(field,encode_v);
		len = 2;
	}
	return len;
}
static inline int tcp_ip_wlsb_field_static_or_irreg16_analyze(u8 *from,struct wlsb_analyze_field *field ,u8 ind)
{
	int len;
	u16 encode_v;
	if(!ind)
		len = 0;
	else{
		/*keep network byte order*/
		memcpy(&encode_v,from,2);
		decomp_wlsb_fill_analyze_field(field,encode_v,16,false);
		len = 2;
	}
	return len;
}
static inline int tcp_ip_field_static_or_irreg8_analyze(u8 *from,struct analyze_field *field,u8 ind)
{
	int len;
	if(!ind)
		len = 0;
	else{
		decomp_fill_analyze_field(field,*from);
		len = 1;
	}
	return len;
}


static inline int tcp_ip_wlsb_field_static_or_irreg32_analyze(u8 *from,struct wlsb_analyze_field *field,u8 ind)
{
	int len;
	u32 encode_v;
	if(!ind)
		len = 0;
	else{
		/*keep network byte order*/
		memcpy(&encode_v,from,4);
		decomp_wlsb_fill_analyze_field(field,encode_v,32,false);
		len = 4;
	}
	return len;
}
static inline u8 tcp_iph_obain_vesion(struct tcp_iph_update *iph_update,struct last_decomped_iph_ref *iph_ref,bool is_inner)
{
	struct tcp_iph_analyze_fields *iph_analyze_fields;
	struct iphdr *iph;
	u8 version;
	if(is_inner){
		iph_analyze_fields = &iph_update->inner_iph_analyze_fields;
		iph = &iph_ref->inner_iph;
	}else{
		iph_analyze_fields = &iph_update->iph_analyze_fields;
		iph = &iph_ref->iph;
	}
	if(iph_analyze_fields->ip_version_update)
		version = iph_analyze_fields->ip_version;
	else
		version = iph->version;
	return version;
}

static inline bool has_inner_iph(struct tcp_iph_update *iph_update,struct last_decomped_iph_ref *iph_ref)
{
	return !!(iph_update->has_inner_iph || iph_ref->has_inner_iph);
}

static inline enum ip_id_behavior tcp_iph_obain_new_ipid_bh(struct tcp_iph_update *iph_update,struct last_decomped_iph_ref *iph_ref,bool is_inner)
{
	enum ip_id_behavior ipid_bh;
	struct analyze_field *new_ip_id_bh;


	if(is_inner){
		new_ip_id_bh = &iph_update->new_inner_ipid_bh;
		if(analyze_field_is_carryed(new_ip_id_bh))
			ipid_bh = (enum ip_id_behavior)new_ip_id_bh->value;
		else
			ipid_bh = iph_ref->inner_ipid_bh;
	}else{
		new_ip_id_bh = &iph_update->new_ipid_bh;
		if(analyze_field_is_carryed(new_ip_id_bh))
			ipid_bh = (enum ip_id_behavior)new_ip_id_bh->value;
		else
			ipid_bh = iph_ref->ipid_bh;
	}
	return ipid_bh;
}
static inline bool tcp_iph_has_one_seq_ipid(struct decomp_tcp_iph_context *ip_context)
{
	struct tcp_iph_update *new_iph_update;
	struct last_decomped_iph_ref *iph_ref;
	struct analyze_field *new_ip_id_bh,*new_inner_ip_id_bh;

	enum ip_id_behavior ipid_bh,inner_ipid_bh;
	bool retval = false;
	new_iph_update = &ip_context->update_by_packet;
	iph_ref = &ip_context->iph_ref;
	if(has_inner_iph(new_iph_update,iph_ref)){
		if(rohc_iph_is_v4(tcp_iph_obain_vesion(new_iph_update,iph_ref,true))){
			new_inner_ip_id_bh = &new_iph_update->new_inner_ipid_bh;
			if(analyze_field_is_carryed(new_inner_ip_id_bh))
				inner_ipid_bh = (enum ip_id_behavior)new_inner_ip_id_bh->value;
			else
				inner_ipid_bh = iph_ref->inner_ipid_bh;
			if(!ip_id_is_random_or_zero(inner_ipid_bh))
				retval = true;
		}else if(rohc_iph_is_v4(tcp_iph_obain_vesion(new_iph_update,iph_ref,false))){
			new_ip_id_bh = &new_iph_update->new_ipid_bh;
			if(analyze_field_is_carryed(new_ip_id_bh))
				ipid_bh = (enum ip_id_behavior)new_ip_id_bh->value;
			else
				ipid_bh = iph_ref->ipid_bh;
			if(!ip_id_is_random_or_zero(ipid_bh))
				retval = true;
		}
	}else{
		if(rohc_iph_is_v4(tcp_iph_obain_vesion(new_iph_update,iph_ref,false))){
			new_ip_id_bh = &new_iph_update->new_ipid_bh;
			if(analyze_field_is_carryed(new_ip_id_bh))
				ipid_bh = (enum ip_id_behavior)new_ip_id_bh->value;
			else
				ipid_bh = iph_ref->ipid_bh;
			if(!ip_id_is_random_or_zero(ipid_bh))
				retval = true;
		}
	}
	return retval;
}

static inline void ip_fill_inner_iph_field_full(struct tcp_iph_update *iph_update,struct last_decomped_iph_ref *iph_ref,u32 value,int type,bool is_full)
{
	struct tcp_iph_dynamic_fields *dynamic_fields;
	if(has_inner_iph(iph_update,iph_ref)){
		if(rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,true)))
			dynamic_fields = &iph_update->inner_iph_analyze_fields.ipv4_analyze_fields.dynamic_fields;
		else
			dynamic_fields = &iph_update->inner_iph_analyze_fields.ipv6_analyze_fields.dynamic_fields;
	}else{
		if(rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,false)))
			dynamic_fields = &iph_update->iph_analyze_fields.ipv4_analyze_fields.dynamic_fields;
		else
			dynamic_fields = &iph_update->iph_analyze_fields.ipv6_analyze_fields.dynamic_fields;
	}
	switch(type){
		case ANALYZE_IP_FIELD_DSCP:
			decomp_fill_analyze_field(&dynamic_fields->dscp,value);
			break;
		case ANALYZE_IP_FIELD_TTL_HL:
			if(is_full)
				decomp_wlsb_fill_analyze_field(&dynamic_fields->ttl_hl,value,8,false);
			else
				decomp_wlsb_fill_analyze_field(&dynamic_fields->ttl_hl,value,3,true);
			break;
		case ANALYZE_IP_FIELD_DF:
			rohc_pr(ROHC_DTCP,"fill df:%d\n",value);
			decomp_fill_analyze_field(&dynamic_fields->df,value);
			break;
		case ANALYZE_IP_FIELD_IPID_BH:
			decomp_fill_analyze_field(&dynamic_fields->ipid_bh,value);
			break;
		case ANALYZE_IP_FIELD_ECN:
			decomp_fill_analyze_field(&dynamic_fields->ecn,value);
			break;

	}

}
static inline struct wlsb_analyze_field * ip_pick_iph_seq_ipid_field(struct tcp_iph_update *iph_update,struct last_decomped_iph_ref *iph_ref)
{
	struct wlsb_analyze_field *ipid_field;
	if(has_inner_iph(iph_update,iph_ref)){
		if(rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,true))){
			if(!ip_id_is_random_or_zero(tcp_iph_obain_new_ipid_bh(iph_update,iph_ref,true)))
				ipid_field = &iph_update->new_inner_ipid;
			else
				ipid_field = NULL;
		}else if(rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,false)) && \
			 !ip_id_is_random_or_zero(tcp_iph_obain_new_ipid_bh(iph_update,iph_ref,false)))
			ipid_field = &iph_update->new_ipid;
		else
			ipid_field = NULL;
	}else{
		if(rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,false)) && \
		   !ip_id_is_random_or_zero(tcp_iph_obain_new_ipid_bh(iph_update,iph_ref,false)))
			ipid_field = &iph_update->new_ipid;
		else
			ipid_field = NULL;
	}
	return ipid_field;
}
int decomp_tcp_analyze_co_common(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *decomp_hdr;
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcp_iph_context *ip_context;
	struct decomp_tcph_context *tcp_context;
	struct decomp_tcph_options_context *opt_context;

	struct decomp_tcph_update *tcph_update;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;

	struct tcp_iph_dynamic_fields *iph_dynamic_fields;
	struct tcp_iph_analyze_fields *new_iph_analyze_fields;

	struct tcph_dynamic_fields *tcph_dynamic_fields;
	struct wlsb_analyze_field *ipid;

	struct profile_tcp_co_common *co_common;
	enum rohc_cid_type cid_type;
	bool analyze_full;
	int analyze_len = 0;
	int call_len;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	ip_context = &d_tcp_context->ip_context;
	tcp_context = &d_tcp_context->tcp_context;
	iph_ref = &ip_context->iph_ref;
	iph_update = &ip_context->update_by_packet;
	tcph_update = &tcp_context->update_by_packet;
	new_iph_analyze_fields = &iph_update->iph_analyze_fields;

	cid_type = context->decompresser->cid_type;
	decomp_hdr = skb->data + pkt_info->decomped_hdr_len;
	if(cid_type == CID_TYPE_SMALL){
		co_common = (struct profile_tcp_co_common *)decomp_hdr;
		analyze_full = true;
	}else{
		if(analyze_first)
			co_common = (struct profile_tcp_co_common *)decomp_hdr;
		else
			co_common = (struct profile_tcp_co_common *)(decomp_hdr - 1);
		analyze_full = false;
	}
	if(analyze_first){
		if(has_inner_iph(iph_update,iph_ref)){
			new_iph_analyze_fields->outer_ttl_hl_carryed = !!co_common->ttl_hl;
		}
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	tcph_dynamic_fields = &tcph_update->analyze_fields.dynamic_fields;
	/*tcp header flags*/
	decomp_wlsb_fill_analyze_field(&tcph_dynamic_fields->msn,co_common->msn,4,true);
	tcp_rsf_decode(co_common->rsf,&tcph_dynamic_fields->fin,&tcph_dynamic_fields->syn,&tcph_dynamic_fields->rst);
	decomp_fill_analyze_field(&tcph_dynamic_fields->psh,co_common->push);
	decomp_fill_analyze_field(&tcph_dynamic_fields->ack,co_common->ack);
	decomp_fill_analyze_field(&tcph_dynamic_fields->urg,co_common->urg);

	/*ipv4 header ip id behavior*/
	if(has_inner_iph(iph_update,iph_ref)){
		if(rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,true)))
			decomp_fill_analyze_field(&iph_update->new_inner_ipid_bh,co_common->ipid_bh);
	}else{
		if(rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,false)))
			decomp_fill_analyze_field(&iph_update->new_ipid_bh,co_common->ipid_bh);
	}
	decomp_fill_analyze_field(&d_tcp_context->co_update.ecn_used,co_common->ecn_used);
	ip_fill_inner_iph_field_full(iph_update,iph_ref,co_common->df,ANALYZE_IP_FIELD_DF,true);
	rohc_pr(ROHC_DTCP,"df=%d\n",co_common->df);
	analyze_len += sizeof(struct profile_tcp_co_common) -  1;
	decomp_hdr += analyze_len;
	/*next fields is dyname exsit fields*/
	/*field 1.tcp seq*/
	call_len = tcp_ip_field_vari_length_32_analyze(decomp_hdr,&tcph_dynamic_fields->seq,co_common->seq_ind);
	decomp_hdr += call_len;
	analyze_len += call_len;
	/*field.2 tcp ack_seq */
	call_len = tcp_ip_field_vari_length_32_analyze(decomp_hdr,&tcph_dynamic_fields->ack_seq,co_common->ack_seq_ind);
	decomp_hdr += call_len;
	analyze_len += call_len;

	/*field.3 ack stride*/
	call_len = tcp_ip_field_static_or_irreg16_analyze_to_cpu(decomp_hdr,&tcph_dynamic_fields->ack_stride,co_common->ack_stride_ind);
	decomp_hdr += call_len;
	analyze_len += call_len;
	/*filed.4 tcp window*/
	call_len = tcp_ip_wlsb_field_static_or_irreg16_analyze(decomp_hdr,&tcph_dynamic_fields->window,co_common->win_ind);
	decomp_hdr += call_len;
	analyze_len += call_len;
	/*filed.5 ipid*/
	ipid = ip_pick_iph_seq_ipid_field(iph_update,iph_ref);
	if(ipid){
		if(co_common->ip_id_ind){
			decomp_wlsb_fill_analyze_field(ipid,*(u16 *)decomp_hdr,16,false);
			analyze_len += 2;
			decomp_hdr += 2;
		}else{
			decomp_wlsb_fill_analyze_field(ipid,*decomp_hdr,8,true);
			analyze_len += 1;
			decomp_hdr += 1;
		}
	}
	/*filed.6 urg ptr*/
	call_len = tcp_ip_field_static_or_irreg16_analyze(decomp_hdr,&tcph_dynamic_fields->urg_ptr,co_common->urg_ind);
	decomp_hdr += call_len;
	analyze_len += call_len;
	/*field.7 dscp*/
	if(co_common->dscp_ind){
		ip_fill_inner_iph_field_full(iph_update,iph_ref,*decomp_hdr,ANALYZE_IP_FIELD_DSCP,true);
		decomp_hdr++;
		analyze_len++;
	}
	/*filed.8 ttl_hl*/
	if(co_common->inner_ttl_hl){
		ip_fill_inner_iph_field_full(iph_update,iph_ref,*decomp_hdr,ANALYZE_IP_FIELD_TTL_HL,true);
		decomp_hdr++;
		analyze_len++;
	}
	if(co_common->list_ind){
		pkt_info->decomped_hdr_len += analyze_len;
		analyze_len = 0;
		opt_context = &d_tcp_context->opt_context;
		retval = tcp_options_analyze_clist(opt_context,skb,pkt_info);
		if(retval){
			rohc_pr(ROHC_DTCP,"analyze tcp option compressed list failed\n");
		}
	}

out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int decomp_tcp_analyze_rnd1(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *decomp_hdr;
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcph_update *tcph_update;
	struct tcph_dynamic_fields *dynamic_fields;
	struct profile_tcp_rnd1 *rnd1;
	enum rohc_cid_type cid_type;
	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	tcph_update = &d_tcp_context->tcp_context.update_by_packet;
	cid_type = context->decompresser->cid_type;
	decomp_hdr = skb->data + pkt_info->decomped_hdr_len;
	dynamic_fields = &tcph_update->analyze_fields.dynamic_fields;

	if(cid_type == CID_TYPE_SMALL){
		rnd1 = (struct profile_tcp_rnd1 *)decomp_hdr;
		analyze_full = true;
	}else{
		if(analyze_first)
			rnd1 = (struct profile_tcp_rnd1 *)decomp_hdr;
		else
			rnd1 = (struct profile_tcp_rnd1 *)(decomp_hdr - 1);
		analyze_full = false;
	}
	if(analyze_first){
		decomp_wlsb_fill_analyze_field_contain_p(&dynamic_fields->seq,rnd1->seq0,2,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(18),true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_analyze_field_append_bits(&dynamic_fields->seq,rnd1->seq1,8,true);
	decomp_wlsb_analyze_field_append_bits(&dynamic_fields->seq,rnd1->seq2,8,true);
	decomp_wlsb_fill_analyze_field(&dynamic_fields->msn,rnd1->msn,4,true);
	decomp_fill_analyze_field(&dynamic_fields->psh,rnd1->push);
	analyze_len += sizeof(struct profile_tcp_rnd1) - 1;

out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int decomp_tcp_analyze_rnd2(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *decomp_hdr;
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcph_update *tcph_update;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct profile_tcp_rnd2 *rnd2;
	enum rohc_cid_type cid_type;
	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	tcph_update = &d_tcp_context->tcp_context.update_by_packet;
	new_tcph_dynamic = &tcph_update->analyze_fields.dynamic_fields;
	cid_type = context->decompresser->cid_type;

	decomp_hdr = skb->data + pkt_info->decomped_hdr_len;
	if(cid_type == CID_TYPE_SMALL){
		rnd2 = (struct profile_tcp_rnd2 *)decomp_hdr;
		analyze_full = true;
	}else{
		if(analyze_first)
			rnd2 = (struct profile_tcp_rnd2 *)decomp_hdr;
		else
			rnd2 = (struct profile_tcp_rnd2 *)(decomp_hdr - 1);
		analyze_full = false;
	}
	if(analyze_first){
		decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->seq_scaled,rnd2->seq_scaled,4,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->msn,rnd2->msn,4,true);
	decomp_fill_analyze_field(&new_tcph_dynamic->psh,rnd2->push);
	/*crc check*/

	analyze_len += sizeof(struct profile_tcp_rnd2) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int decomp_tcp_analyze_rnd3(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *decomp_hdr;
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcph_update *tcph_update;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct profile_tcp_rnd3 *rnd3;

	enum rohc_cid_type cid_type;
	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	tcph_update = &d_tcp_context->tcp_context.update_by_packet;
	new_tcph_dynamic = &tcph_update->analyze_fields.dynamic_fields;

	cid_type = context->decompresser->cid_type;
	decomp_hdr = skb->data + pkt_info->decomped_hdr_len;

	if(cid_type == CID_TYPE_SMALL){
		rnd3 = (struct profile_tcp_rnd3 *)decomp_hdr;
		analyze_full = true;
	}else{
		if(analyze_first)
			rnd3 = (struct profile_tcp_rnd3 *)decomp_hdr;
		else
			rnd3 = (struct profile_tcp_rnd3 *)(decomp_hdr - 1);
		analyze_full = false;
	}
	if(analyze_first){
		decomp_wlsb_fill_analyze_field_contain_p(&new_tcph_dynamic->ack_seq,rnd3->ack_seq0,7,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(15),true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_analyze_field_append_bits(&new_tcph_dynamic->ack_seq,rnd3->ack_seq1,8,true);
	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->msn,rnd3->msn,4,true);
	decomp_fill_analyze_field(&new_tcph_dynamic->psh,rnd3->push);
	/*check crc*/

	analyze_len += sizeof(struct profile_tcp_rnd3) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int decomp_tcp_analyze_rnd4(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *decomp_hdr;
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcph_update *tcph_update;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct profile_tcp_rnd4 *rnd4;
	enum rohc_cid_type cid_type;
	bool analyze_full;

	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	tcph_update = &d_tcp_context->tcp_context.update_by_packet;
	new_tcph_dynamic = &tcph_update->analyze_fields.dynamic_fields;

	decomp_hdr = skb->data + pkt_info->decomped_hdr_len;
	cid_type = context->decompresser->cid_type;

	if(cid_type == CID_TYPE_SMALL){
		rnd4 = (struct profile_tcp_rnd4 *)decomp_hdr;
		analyze_full = true;
	}else{
		if(analyze_first)
			rnd4 = (struct profile_tcp_rnd4 *)decomp_hdr;
		else
			rnd4 = (struct profile_tcp_rnd4 *)(decomp_hdr - 1);
		analyze_full = false;
	}

	if(analyze_first){
		decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->ack_seq_scaled,rnd4->ack_seq_scaled,4,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->msn,rnd4->msn,4,true);
	decomp_fill_analyze_field(&new_tcph_dynamic->psh,rnd4->push);
	/*crc check */


	analyze_len += sizeof(struct profile_tcp_rnd4) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int decomp_tcp_analyze_rnd5(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *decomp_hdr;
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcph_update *tcph_update;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct profile_tcp_rnd5 *rnd5;
	enum rohc_cid_type cid_type;
	bool analyze_full;

	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	tcph_update = &d_tcp_context->tcp_context.update_by_packet;
	new_tcph_dynamic = &tcph_update->analyze_fields.dynamic_fields;

	decomp_hdr = skb->data + pkt_info->decomped_hdr_len;
	cid_type = context->decompresser->cid_type;

	if(cid_type == CID_TYPE_SMALL){
		rnd5 = (struct profile_tcp_rnd5 *)decomp_hdr;
		analyze_full = true;
	}else{
		if(analyze_first)
			rnd5 = (struct profile_tcp_rnd5 *)decomp_hdr;
		else
			rnd5 = (struct profile_tcp_rnd5 *)(decomp_hdr - 1);
		analyze_full = false;
	}

	if(analyze_first){
		decomp_fill_analyze_field(&new_tcph_dynamic->psh,rnd5->push);
		decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->msn,rnd5->msn,4,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_fill_analyze_field_contain_p(&new_tcph_dynamic->seq,rnd5->seq0,5,ROHC_LSB_TCP_K_RSHIFT_1_TO_P(14),true);
	decomp_wlsb_analyze_field_append_bits(&new_tcph_dynamic->seq,rnd5->seq1,8,true);
	decomp_wlsb_analyze_field_append_bits(&new_tcph_dynamic->seq,rnd5->seq2,1,true);

	decomp_wlsb_fill_analyze_field_contain_p(&new_tcph_dynamic->ack_seq,rnd5->ack_seq0,7,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(15),true);
	decomp_wlsb_analyze_field_append_bits(&new_tcph_dynamic->ack_seq,rnd5->ack_seq1,8,true);

	analyze_len += sizeof(struct profile_tcp_rnd5) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}


int decomp_tcp_analyze_rnd6(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *decomp_hdr;
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcph_update *tcph_update;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct profile_tcp_rnd6 *rnd6;
	enum rohc_cid_type cid_type;
	bool analyze_full;

	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	tcph_update = &d_tcp_context->tcp_context.update_by_packet;
	new_tcph_dynamic = &tcph_update->analyze_fields.dynamic_fields;

	decomp_hdr = skb->data + pkt_info->decomped_hdr_len;
	cid_type = context->decompresser->cid_type;

	if(cid_type == CID_TYPE_SMALL){
		rnd6 = (struct profile_tcp_rnd6 *)decomp_hdr;
		analyze_full = true;
	}else{
		if(analyze_first)
			rnd6 = (struct profile_tcp_rnd6 *)decomp_hdr;
		else
			rnd6 = (struct profile_tcp_rnd6 *)(decomp_hdr - 1);
		analyze_full = false;
	}

	if(analyze_first){
		decomp_fill_analyze_field(&new_tcph_dynamic->psh,rnd6->push);
		analyze_len = 1;
	}

	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_fill_analyze_field_contain_p(&new_tcph_dynamic->ack_seq,ntohs(rnd6->ack_seq),16,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(16),true);
	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->msn,rnd6->msn,4,true);
	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->seq_scaled,rnd6->seq_scaled,4,true);

	analyze_len += sizeof(struct profile_tcp_rnd6) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}


int decomp_tcp_analyze_rnd7(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *decomp_hdr;
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcph_update *tcph_update;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct profile_tcp_rnd7 *rnd7;
	enum rohc_cid_type cid_type;
	bool analyze_full;

	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	tcph_update = &d_tcp_context->tcp_context.update_by_packet;
	new_tcph_dynamic = &tcph_update->analyze_fields.dynamic_fields;

	decomp_hdr = skb->data + pkt_info->decomped_hdr_len;
	cid_type = context->decompresser->cid_type;

	if(cid_type == CID_TYPE_SMALL){
		rnd7 = (struct profile_tcp_rnd7 *)decomp_hdr;
		analyze_full = true;
	}else{
		if(analyze_first)
			rnd7 = (struct profile_tcp_rnd7 *)decomp_hdr;
		else
			rnd7 = (struct profile_tcp_rnd7 *)(decomp_hdr - 1);
		analyze_full= false;
	}

	if(analyze_first){
		decomp_wlsb_fill_analyze_field_contain_p(&new_tcph_dynamic->ack_seq,rnd7->ack_seq0,2,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(18),true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;

	decomp_wlsb_analyze_field_append_bits(&new_tcph_dynamic->ack_seq,rnd7->ack_seq1,8,true);
	decomp_wlsb_analyze_field_append_bits(&new_tcph_dynamic->ack_seq,rnd7->ack_seq2,8,true);

	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->window,rnd7->window,16,false);

	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->msn,rnd7->msn,4,true);
	decomp_fill_analyze_field(&new_tcph_dynamic->psh,rnd7->push);

	analyze_len += sizeof(struct profile_tcp_rnd7) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}


int decomp_tcp_analyze_rnd8(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *decomp_hdr;
	struct decomp_tcp_context *d_tcp_context;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;
	struct decomp_tcph_options_context *opt_context;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct profile_tcp_rnd8 *rnd8;

	bool analyze_full;
	int list_ind;
	enum rohc_cid_type cid_type;
	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	iph_update  = &d_tcp_context->ip_context.update_by_packet;
	iph_ref = &d_tcp_context->ip_context.iph_ref;

	new_tcph_dynamic = &d_tcp_context->tcp_context.update_by_packet.analyze_fields.dynamic_fields;
	decomp_hdr = skb->data + pkt_info->decomped_hdr_len;

	if(cid_type == CID_TYPE_SMALL){
		decomp_hdr += pkt_info->cid_len;
		rnd8 = (struct profile_tcp_rnd8 *)(decomp_hdr);
		list_ind = rnd8->list_ind;
		tcp_rsf_decode(rnd8->rsf,&new_tcph_dynamic->fin,&new_tcph_dynamic->syn,&new_tcph_dynamic->rst);
		analyze_len += pkt_info->cid_len;
	}else{
		rnd8 = (struct profile_tcp_rnd8 *)decomp_hdr;
		list_ind = rnd8->list_ind;
		tcp_rsf_decode(rnd8->rsf,&new_tcph_dynamic->fin,&new_tcph_dynamic->syn,&new_tcph_dynamic->rst);
		decomp_hdr += (1 + pkt_info->cid_len);
		rnd8 = (struct profile_tcp_rnd8 *)(decomp_hdr - 1);
		analyze_len += pkt_info->cid_len;
	}
	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->msn,rnd8->msn0,1,true);
	decomp_wlsb_analyze_field_append_bits(&new_tcph_dynamic->msn,rnd8->msn1,3,true);
	decomp_fill_analyze_field(&new_tcph_dynamic->psh,rnd8->push);
	ip_fill_inner_iph_field_full(iph_update,iph_ref,rnd8->ttl_hl,ANALYZE_IP_FIELD_TTL_HL,false);
	decomp_fill_analyze_field(&d_tcp_context->co_update.ecn_used,rnd8->ecn_used);

	decomp_wlsb_fill_analyze_field_contain_p(&new_tcph_dynamic->seq,ntohs(rnd8->seq),16,ROHC_LSB_TCP_K_RSHIFT_0_TO_P(16),true);
	decomp_wlsb_fill_analyze_field_contain_p(&new_tcph_dynamic->ack_seq,ntohs(rnd8->ack_seq),16,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(16),true);
	analyze_len += sizeof(struct profile_tcp_rnd8);
	pkt_info->decomped_hdr_len += analyze_len;
	/*next field is list option compressed list*/
	if(list_ind){
		retval = tcp_options_analyze_clist(opt_context,skb,pkt_info);
	}
	return retval;
}

int decomp_tcp_analyze_seq1(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct decomp_tcp_context *d_tcp_context;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct wlsb_analyze_field *seq_ipid;
	struct profile_tcp_seq1 *seq1;
	enum rohc_cid_type cid_type;
	bool analyze_full;

	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	iph_update = &d_tcp_context->ip_context.update_by_packet;
	iph_ref = &d_tcp_context->ip_context.iph_ref;

	new_tcph_dynamic = &d_tcp_context->tcp_context.update_by_packet.analyze_fields.dynamic_fields;

	seq_ipid = ip_pick_iph_seq_ipid_field(iph_update,iph_ref);
	BUG_ON(!seq_ipid);

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	cid_type = context->decompresser->cid_type;
	if(cid_type == CID_TYPE_SMALL){
		seq1 = (struct profile_tcp_seq1 *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			seq1 = (struct profile_tcp_seq1 *)analyze_data;
		else
			seq1 = (struct profile_tcp_seq1 *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		seq_ipid = ip_pick_iph_seq_ipid_field(iph_update,iph_ref);
		decomp_wlsb_fill_analyze_field(seq_ipid,seq1->ipid_off,4,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_fill_analyze_field_contain_p(&new_tcph_dynamic->seq,ntohs(seq1->seq),16,ROHC_LSB_TCP_K_RSHIFT_1_TO_P(16),true);
	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->msn,seq1->msn,4,true);
	decomp_fill_analyze_field(&new_tcph_dynamic->psh,seq1->push);
	analyze_len += sizeof(struct profile_tcp_seq1) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;


}

int decomp_tcp_analyze_seq2(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct decomp_tcp_context *d_tcp_context;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct wlsb_analyze_field *seq_ipid;
	struct profile_tcp_seq2 *seq2;

	enum rohc_cid_type cid_type;
	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	iph_update = &d_tcp_context->ip_context.update_by_packet;
	iph_ref = &d_tcp_context->ip_context.iph_ref;
	new_tcph_dynamic = &d_tcp_context->tcp_context.update_by_packet.analyze_fields.dynamic_fields;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	cid_type = context->decompresser->cid_type;
	seq_ipid = ip_pick_iph_seq_ipid_field(iph_update,iph_ref);

	if(cid_type == CID_TYPE_SMALL){
		seq2 = (struct profile_tcp_seq2 *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			seq2 = (struct profile_tcp_seq2 *)analyze_data;
		else
			seq2 = (struct profile_tcp_seq2 *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		decomp_wlsb_fill_analyze_field(seq_ipid,seq2->ipid_off0,3,true);
		analyze_len = 1;
	}

	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_analyze_field_append_bits(seq_ipid,seq2->ipid_off1,4,true);
	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->seq_scaled,seq2->seq_scaled,4,true);
	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->msn,seq2->msn,4,true);
	decomp_fill_analyze_field(&new_tcph_dynamic->psh,seq2->push);

	analyze_len += sizeof(struct profile_tcp_seq2) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int decomp_tcp_analyze_seq3(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct decomp_tcp_context *d_tcp_context;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct wlsb_analyze_field *seq_ipid;
	struct profile_tcp_seq3 *seq3;

	enum rohc_cid_type cid_type;
	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	iph_update = &d_tcp_context->ip_context.update_by_packet;
	iph_ref = &d_tcp_context->ip_context.iph_ref;
	new_tcph_dynamic = &d_tcp_context->tcp_context.update_by_packet.analyze_fields.dynamic_fields;

	cid_type = context->decompresser->cid_type;
	analyze_data  = skb->data + pkt_info->decomped_hdr_len;

	if(cid_type == CID_TYPE_SMALL){
		seq3 = (struct profile_tcp_seq3 *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			seq3 = (struct profile_tcp_seq3 *)analyze_data;
		else
			seq3 = (struct profile_tcp_seq3 *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		seq_ipid = ip_pick_iph_seq_ipid_field(iph_update,iph_ref);
		decomp_wlsb_fill_analyze_field(seq_ipid,seq3->ipid_off,4,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_fill_analyze_field_contain_p(&new_tcph_dynamic->ack_seq,ntohs(seq3->ack_seq),16,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(16),true);
	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->msn,seq3->msn,4,true);
	decomp_fill_analyze_field(&new_tcph_dynamic->psh,seq3->push);
	analyze_len += sizeof(struct profile_tcp_seq3) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}


int decomp_tcp_analyze_seq4(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct decomp_tcp_context *d_tcp_context;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct wlsb_analyze_field *seq_ipid;
	struct profile_tcp_seq4 *seq4;

	enum rohc_cid_type cid_type;
	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	iph_update = &d_tcp_context->ip_context.update_by_packet;
	iph_ref = &d_tcp_context->ip_context.iph_ref;
	new_tcph_dynamic = &d_tcp_context->tcp_context.update_by_packet.analyze_fields.dynamic_fields;

	cid_type = context->decompresser->cid_type;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(cid_type == CID_TYPE_SMALL){
		seq4 = (struct profile_tcp_seq4 *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			seq4 = (struct profile_tcp_seq4 *)analyze_data;
		else
			seq4 = (struct profile_tcp_seq4 *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		seq_ipid = ip_pick_iph_seq_ipid_field(iph_update,iph_ref);
		BUG_ON(!seq_ipid);
		decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->ack_seq_scaled,seq4->ack_seq_scaled,4,true);
		decomp_wlsb_fill_analyze_field(seq_ipid,seq4->ipid_off,3,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->msn,seq4->msn,4,true);
	decomp_fill_analyze_field(&new_tcph_dynamic->psh,seq4->push);

	analyze_len += sizeof(struct profile_tcp_seq4) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}


int decomp_tcp_analyze_seq5(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct decomp_tcp_context *d_tcp_context;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct wlsb_analyze_field *seq_ipid;
	struct profile_tcp_seq5 *seq5;

	enum rohc_cid_type cid_type;
	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	iph_update = &d_tcp_context->ip_context.update_by_packet;
	iph_ref = &d_tcp_context->ip_context.iph_ref;
	new_tcph_dynamic = &d_tcp_context->tcp_context.update_by_packet.analyze_fields.dynamic_fields;

	cid_type = context->decompresser->cid_type;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(cid_type == CID_TYPE_SMALL){
		seq5 = (struct profile_tcp_seq5 *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			seq5 = (struct profile_tcp_seq5 *)analyze_data;
		else
			seq5 = (struct profile_tcp_seq5 *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		seq_ipid = ip_pick_iph_seq_ipid_field(iph_update,iph_ref);
		decomp_wlsb_fill_analyze_field(seq_ipid,seq5->ipid_off,4,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_fill_analyze_field_contain_p(&new_tcph_dynamic->ack_seq,ntohs(seq5->ack_seq),16,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(16),true);
	decomp_wlsb_fill_analyze_field_contain_p(&new_tcph_dynamic->seq,ntohs(seq5->seq),16,ROHC_LSB_TCP_K_RSHIFT_1_TO_P(16),true);

	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->msn,seq5->msn,4,true);
	decomp_fill_analyze_field(&new_tcph_dynamic->psh,seq5->push);

	analyze_len += sizeof(struct profile_tcp_seq5) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int decomp_tcp_analyze_seq6(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct decomp_tcp_context *d_tcp_context;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct wlsb_analyze_field *seq_ipid;
	struct profile_tcp_seq6 *seq6;

	enum rohc_cid_type cid_type;
	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	iph_update = &d_tcp_context->ip_context.update_by_packet;
	iph_ref = &d_tcp_context->ip_context.iph_ref;
	new_tcph_dynamic = &d_tcp_context->tcp_context.update_by_packet.analyze_fields.dynamic_fields;

	cid_type = context->decompresser->cid_type;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(cid_type == CID_TYPE_SMALL){
		seq6 = (struct profile_tcp_seq6 *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			seq6 = (struct profile_tcp_seq6 *)analyze_data;
		else
			seq6 = (struct profile_tcp_seq6 *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->seq_scaled,seq6->seq_scaled0,3,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_analyze_field_append_bits(&new_tcph_dynamic->seq_scaled,seq6->seq_scaled1,1,true);
	seq_ipid = ip_pick_iph_seq_ipid_field(iph_update,iph_ref);
	decomp_wlsb_fill_analyze_field(seq_ipid,seq6->ipid_off,7,true);

	decomp_wlsb_fill_analyze_field_contain_p(&new_tcph_dynamic->ack_seq,ntohs(seq6->ack_seq),16,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(16),true);

	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->msn,seq6->msn,4,true);
	decomp_fill_analyze_field(&new_tcph_dynamic->psh,seq6->push);

	analyze_len += sizeof(struct profile_tcp_seq6) - 1;

out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int decomp_tcp_analyze_seq7(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct decomp_tcp_context *d_tcp_context;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct wlsb_analyze_field *seq_ipid;
	struct profile_tcp_seq7 *seq7;

	enum rohc_cid_type cid_type;
	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	iph_update = &d_tcp_context->ip_context.update_by_packet;
	iph_ref = &d_tcp_context->ip_context.iph_ref;
	new_tcph_dynamic = &d_tcp_context->tcp_context.update_by_packet.analyze_fields.dynamic_fields;

	cid_type = context->decompresser->cid_type;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(cid_type == CID_TYPE_SMALL){
		seq7 = (struct profile_tcp_seq7 *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			seq7 = (struct profile_tcp_seq7 *)analyze_data;
		else
			seq7 = (struct profile_tcp_seq7 *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->window,seq7->win0,4,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_analyze_field_append_bits(&new_tcph_dynamic->window,seq7->win1,8,true);
	decomp_wlsb_analyze_field_append_bits(&new_tcph_dynamic->window,seq7->win2,3,true);

	seq_ipid = ip_pick_iph_seq_ipid_field(iph_update,iph_ref);
	decomp_wlsb_fill_analyze_field(seq_ipid,seq7->ipid_off,5,true);

	decomp_wlsb_fill_analyze_field_contain_p(&new_tcph_dynamic->ack_seq,ntohs(seq7->ack_seq),16,ROHC_LSB_TCP_K_RSHIFT_1_TO_P(16),true);
	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->msn,seq7->msn,4,true);
	decomp_fill_analyze_field(&new_tcph_dynamic->psh,seq7->push);

	analyze_len += sizeof(struct profile_tcp_seq7) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}


int decomp_tcp_analyze_seq8(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct decomp_tcp_context *d_tcp_context;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct wlsb_analyze_field *seq_ipid;
	struct profile_tcp_seq8 *seq8;

	enum rohc_cid_type cid_type;
	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	iph_update = &d_tcp_context->ip_context.update_by_packet;
	iph_ref = &d_tcp_context->ip_context.iph_ref;
	new_tcph_dynamic = &d_tcp_context->tcp_context.update_by_packet.analyze_fields.dynamic_fields;

	cid_type = context->decompresser->cid_type;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(cid_type == CID_TYPE_SMALL){
		seq8 = (struct profile_tcp_seq8 *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			seq8 = (struct profile_tcp_seq8 *)analyze_data;
		else
			seq8 = (struct profile_tcp_seq8 *)(analyze_data - 1);
		analyze_full = false;
	}

	if(analyze_first){
		seq_ipid = ip_pick_iph_seq_ipid_field(iph_update,iph_ref);
		decomp_wlsb_fill_analyze_field(seq_ipid,seq8->ipid_off,4,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_fill_analyze_field(&new_tcph_dynamic->msn,seq8->msn,4,true);
	decomp_fill_analyze_field(&new_tcph_dynamic->psh,seq8->push);
	ip_fill_inner_iph_field_full(iph_update,iph_ref,seq8->ttl_hl,ANALYZE_IP_FIELD_TTL_HL,false);
	decomp_fill_analyze_field(&d_tcp_context->co_update.ecn_used,seq8->ecn_used);


	decomp_wlsb_fill_analyze_field_contain_p(&new_tcph_dynamic->ack_seq,seq8->ack_seq0,7,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(15),true);
	decomp_wlsb_analyze_field_append_bits(&new_tcph_dynamic->ack_seq,seq8->ack_seq1,8,true);

	tcp_rsf_decode(seq8->rsf,&new_tcph_dynamic->fin,&new_tcph_dynamic->syn,&new_tcph_dynamic->rst);
	decomp_wlsb_fill_analyze_field_contain_p(&new_tcph_dynamic->seq,seq8->seq0,6,ROHC_LSB_TCP_K_RSHIFT_1_TO_P(14),true);
	decomp_wlsb_analyze_field_append_bits(&new_tcph_dynamic->seq,seq8->seq1,8,true);
	analyze_len += sizeof(struct profile_tcp_seq8) - 1;
	if(seq8->list_ind){
		pkt_info->decomped_hdr_len += analyze_len;
		analyze_len = 0;
		retval = tcp_options_analyze_clist(&d_tcp_context->opt_context,skb,pkt_info);
		if(retval){
			rohc_pr(ROHC_DTCP,"profile tcp context-%d analyze compressed list failed\n",context->cid);
		}
	}
out:
	pkt_info->decomped_hdr_len += analyze_len;
}


static inline int ip_analyze_static_field(u8 *analyze_data,struct tcp_iph_analyze_fields *iph_analyze_fields,u8 *pr_nh)
{
	int analyze_len;

	struct profile_tcp_ipv4_static *ipv4_static;
	struct tcp_ipv4h_static_fields *ipv4_static_fields;
	ipv4_static = (struct profile_tcp_ipv4_static *)analyze_data;
	if(!ipv4_static->version){

		ipv4_static_fields = &iph_analyze_fields->ipv4_analyze_fields.static_fields;
		iph_analyze_fields->ip_version = 4;
		iph_analyze_fields->ip_version_update = true;
		ipv4_static_fields->protocol = ipv4_static->protocol;
		ipv4_static_fields->saddr = ipv4_static->saddr;
		ipv4_static_fields->daddr = ipv4_static->daddr;
		*pr_nh = ipv4_static_fields->protocol;
		ipv4_static_fields->update = true;
		analyze_len = sizeof(struct profile_tcp_ipv4_static);
	}else{
		rohc_pr(ROHC_DTCP,"profile tcp now not support analyze ipv6 static field");
	}
	return analyze_len;
}
int decomp_tcp_analyze_ip_static_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcp_iph_context *ip_context;
	struct tcp_iph_update *iph_update;
	struct tcp_iph_analyze_fields *iph_analyze_fields;

	u8 pr_nh;
	int call_len;
	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	ip_context = &d_tcp_context->ip_context;
	iph_update = &ip_context->update_by_packet;
	iph_analyze_fields = &iph_update->iph_analyze_fields;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	call_len = ip_analyze_static_field(analyze_data,iph_analyze_fields,&pr_nh);
	analyze_data += call_len;
	analyze_len += call_len;
	if(pr_nh == IPPROTO_IPIP || pr_nh == IPPROTO_IPV6){
		iph_update->has_inner_iph = true;
		iph_analyze_fields = &iph_update->inner_iph_analyze_fields;
		call_len = ip_analyze_static_field(analyze_data,iph_analyze_fields,&pr_nh);
		if(pr_nh == IPPROTO_IPIP || pr_nh == IPPROTO_IPV6){
			pr_err("profile-tcp cid-%d has too many ip header when analyze ip static chain\n",context->cid);
			retval = -EPERM;
			goto out;
		}
		analyze_len += call_len;
	}
	pkt_info->decomped_hdr_len += analyze_len;
out:
	return retval;
}

static inline int ip_analyze_dyamic_field(u8 *analyze_data,struct tcp_iph_analyze_fields *analyze_fields,bool is_ipv4)
{
	struct tcp_iph_dynamic_fields *dynamic_fields;
	struct profile_tcp_ipv4_dynamic *ipv4_dynamic;
	int analyze_len = 0;
	if(is_ipv4){
		ipv4_dynamic = (struct profile_tcp_ipv4_dynamic *)analyze_data;
		dynamic_fields = &analyze_fields->ipv4_analyze_fields.dynamic_fields;
		decomp_fill_analyze_field(&dynamic_fields->ipid_bh,ipv4_dynamic->ipid_bh);
		decomp_fill_analyze_field(&dynamic_fields->ecn,ipv4_dynamic->ecn_flags);
		decomp_fill_analyze_field(&dynamic_fields->dscp,ipv4_dynamic->dscp);
		decomp_fill_analyze_field(&dynamic_fields->df,ipv4_dynamic->df);
		decomp_wlsb_fill_analyze_field(&dynamic_fields->ttl_hl,ipv4_dynamic->ttl_hl,8,false);
		analyze_len = sizeof(struct profile_tcp_ipv4_dynamic);
		if(!ip_id_is_zero(ipv4_dynamic->ipid_bh)){
			analyze_data += analyze_len;
			/*keep network byte order*/
			decomp_wlsb_fill_analyze_field(&dynamic_fields->ipid,*(u16 *)analyze_data,16,false);
			analyze_len += 2;
		}
	}else{
		pr_err("profile tcp isn't support ipv6 now\n");
	}
	return analyze_len;
}
int decomp_tcp_analyze_ip_dynamic_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcp_iph_context *ip_context;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;
	struct tcp_iph_analyze_fields *iph_analyze_fields;
	int call_len;
	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	ip_context = &d_tcp_context->ip_context;
	iph_update = &ip_context->update_by_packet;
	iph_ref = &ip_context->iph_ref;

	iph_analyze_fields = &iph_update->iph_analyze_fields;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	call_len = ip_analyze_dyamic_field(analyze_data,iph_analyze_fields,rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,false)));
	analyze_data += call_len;
	analyze_len += call_len;
	if(has_inner_iph(iph_update,iph_ref)){
		iph_analyze_fields = &iph_update->inner_iph_analyze_fields;
		call_len = ip_analyze_dyamic_field(analyze_data,iph_analyze_fields,rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,true)));
		analyze_len += call_len;
	}
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int decomp_tcp_analyze_tcp_static_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcph_context *tcp_context;
	struct tcph_static_fields *static_fields;
	struct profile_tcp_static *tcp_static;

	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	tcp_context = &d_tcp_context->tcp_context;
	static_fields = &tcp_context->update_by_packet.analyze_fields.static_fields;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	tcp_static = (struct profile_tcp_static *)analyze_data;

	static_fields->sport = tcp_static->sport;
	static_fields->dport = tcp_static->dport;
	static_fields->update = true;

	pkt_info->decomped_hdr_len += sizeof(struct profile_tcp_static);;
	return 0;
}

int decomp_tcp_analyze_tcp_dynamic_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcph_context *tcp_context;
	struct tcph_dynamic_fields *dynamic_fields;
	struct profile_tcp_dynamic *tcp_dynamic;
	int call_len;
	int analyze_len = 0;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	tcp_context = &d_tcp_context->tcp_context;
	dynamic_fields = &tcp_context->update_by_packet.analyze_fields.dynamic_fields;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	tcp_dynamic = (struct profile_tcp_dynamic *)analyze_data;
	decomp_fill_analyze_field(&dynamic_fields->res1,tcp_dynamic->res);
	decomp_fill_analyze_field(&d_tcp_context->co_update.ecn_used,tcp_dynamic->ecn_used);
	tcp_rsf_decode_full(tcp_dynamic->rsf,&dynamic_fields->fin,&dynamic_fields->syn,&dynamic_fields->rst);
	decomp_fill_analyze_field(&dynamic_fields->psh,tcp_dynamic->push);
	decomp_fill_analyze_field(&dynamic_fields->ack,tcp_dynamic->ack);
	decomp_fill_analyze_field(&dynamic_fields->urg,tcp_dynamic->urg);
	decomp_fill_analyze_field(&dynamic_fields->ecn,tcp_dynamic->ecn);

	decomp_wlsb_fill_analyze_field(&dynamic_fields->msn,ntohs(tcp_dynamic->msn),16,false);
	rohc_pr(ROHC_DTCP,"ana msn=%d,ori_msn=%d\n",dynamic_fields->msn.encode_v,htons(tcp_dynamic->msn));
	/*tcp header seq ,keep network byte order when isn't compressed*/
	decomp_wlsb_fill_analyze_field(&dynamic_fields->seq,tcp_dynamic->seq,32,false);

	/*tcp header window,keep network byte oder when isn't compressed*/
	decomp_wlsb_fill_analyze_field(&dynamic_fields->window,tcp_dynamic->window,16,false);

	/*tcp header checsum ,should keep network byte oder,because it isn't be compressed */
	decomp_fill_analyze_field(&dynamic_fields->check,tcp_dynamic->check);

	analyze_len += sizeof(struct profile_tcp_dynamic);
	analyze_data += analyze_len;
	/*next fields is dynamic exist*/
	/*field.1 tcp header ack seq*/

	if(tcp_dynamic->ack_zero)
		decomp_wlsb_fill_analyze_field(&dynamic_fields->ack_seq,0,32,false);
	else{
		call_len = tcp_ip_wlsb_field_static_or_irreg32_analyze(analyze_data,&dynamic_fields->ack_seq,!tcp_dynamic->ack_zero);
		analyze_len += call_len;
		analyze_data += call_len;
	}
	/*field.2 tcp header urg ptr*/
	if(tcp_dynamic->urg_zero)
		decomp_fill_analyze_field(&dynamic_fields->urg_ptr,0);
	else{
		call_len = tcp_ip_field_static_or_irreg16_analyze(analyze_data,&dynamic_fields->urg_ptr,!tcp_dynamic->urg_zero);
		analyze_len += call_len;
		analyze_data += call_len;
	}
	/*field.3 ack stride*/
	call_len = tcp_ip_field_static_or_irreg16_analyze_to_cpu(analyze_data,&dynamic_fields->ack_stride,tcp_dynamic->ack_stride_ind);
	analyze_data += call_len;
	analyze_len += call_len;

	pkt_info->decomped_hdr_len += analyze_len;
	rohc_pr(ROHC_DTCP,"tcp cid-%d ananlyze total length is %d excepet list\n",context->cid,pkt_info->decomped_hdr_len);
	/*field.4 tcp option list*/
	retval = tcp_options_analyze_clist(&d_tcp_context->opt_context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DTCP,"profile tcp analyze compressed list failed after tcp dynamic\n");
	}
	return retval;
}

int decomp_tcp_analyze_tcp_irr_chain(struct decomp_tcp_context *d_tcp_context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct tcph_dynamic_fields *new_tcph_dynamic;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;

	int analyze_len = 0;
	int retval = 0;

	iph_update = &d_tcp_context->ip_context.update_by_packet;
	iph_ref = &d_tcp_context->ip_context.iph_ref;
	new_tcph_dynamic = &d_tcp_context->tcp_context.update_by_packet.analyze_fields.dynamic_fields;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	/*filed.1 ecn if ecn used*/
	if(ecn_is_carryed(d_tcp_context)){
		ip_fill_inner_iph_field_full(iph_update,iph_ref,BYTE_BITS_2(*analyze_data,6),ANALYZE_IP_FIELD_ECN,true);
		decomp_fill_analyze_field(&new_tcph_dynamic->res1,BYTE_BITS_4(*analyze_data,2));
		decomp_fill_analyze_field(&new_tcph_dynamic->ecn,BYTE_BITS_2(*analyze_data,0));
		analyze_data++;
		analyze_len++;
	}
	/*field.2 tcp header checksum,keep network byte order*/
	decomp_fill_analyze_field(&new_tcph_dynamic->check,*(u16 *)analyze_data);
	analyze_len += 2;
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int decomp_tcp_analyze_ip_irr_chain(struct decomp_tcp_context *d_tcp_context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;

	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;
	struct tcp_iph_dynamic_fields *iph_dynamic_fields,*inner_iph_dynamic_fields;
	int analyze_len = 0;
	int retval = 0;

	iph_update = &d_tcp_context->ip_context.update_by_packet;
	iph_ref = &d_tcp_context->ip_context.iph_ref;
	if(rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,false)))
		iph_dynamic_fields = &iph_update->iph_analyze_fields.ipv4_analyze_fields.dynamic_fields;
	else
		iph_dynamic_fields = &iph_update->iph_analyze_fields.ipv6_analyze_fields.dynamic_fields;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	/*filed.1 outer ip id if ipid behavior is random*/
	if(rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,false)) && \
	   ip_id_is_random(tcp_iph_obain_new_ipid_bh(iph_update,iph_ref,false))){
		decomp_wlsb_fill_analyze_field(&iph_update->new_ipid,*(u16 *)analyze_data,16,false);
		analyze_len += 2;
		analyze_data += 2;
	}
	/*field.2 outer ip header ecn and dscp if contains two ip header*/
	if(has_inner_iph(iph_update,iph_ref) && ecn_is_carryed(d_tcp_context)){
		decomp_fill_analyze_field(&iph_dynamic_fields->dscp,BYTE_BITS_6(*analyze_data,2));
		decomp_fill_analyze_field(&iph_dynamic_fields->ecn,BYTE_BITS_2(*analyze_data,0));
		analyze_data++;
		analyze_len++;
	}
	/*field.3 outer ip header ttlhl if context contains two ip header*/
	if(has_inner_iph(iph_update,iph_ref) && iph_update->iph_analyze_fields.outer_ttl_hl_carryed){
		decomp_wlsb_fill_analyze_field(&iph_dynamic_fields->ttl_hl,*analyze_data,8,false);
		analyze_data++;
		analyze_len++;
	}
	/*field.4 inner ip header ipid if ip-id behavior is random*/
	if(has_inner_iph(iph_update,iph_ref) && \
	   rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,true)) && \
	   ip_id_is_random(tcp_iph_obain_new_ipid_bh(iph_update,iph_ref,true))){
		decomp_wlsb_fill_analyze_field(&iph_update->new_inner_ipid,*(u16 *)analyze_data,16,false);
		analyze_len += 2;
	}
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}


static inline int  decode_ipv4_header(struct tcp_ipv4h_analyze_fields *analyze_fields,struct iphdr *new_iph,struct iphdr *iph_ref,struct rohc_decomp_wlsb *ttl_hl_wlsb,struct rohc_decomp_wlsb *ip_id_wlsb,enum ip_id_behavior ipid_bh,u32 msn)
{
	struct tcp_ipv4h_static_fields *ipv4_static;
	struct tcp_iph_dynamic_fields *iph_dynamic;
	struct wlsb_analyze_field *ipid,*ttl_hl;

	u16 frag_off;
	u16 new_ipid_v;
	u8 dscp,ecn;
	u32 ipid_off,ttl_hl_v;
	int retval = 0;
	ipv4_static = &analyze_fields->static_fields;
	iph_dynamic = &analyze_fields->dynamic_fields;
	ttl_hl = &iph_dynamic->ttl_hl;
	ipid = &iph_dynamic->ipid;
	/*decode static field */
	if(ipv4_static->update){
		new_iph->protocol = ipv4_static->protocol;
		new_iph->saddr = ipv4_static->saddr;
		new_iph->daddr = ipv4_static->daddr;
		new_iph->version = 4;
	}else{
		new_iph->protocol = iph_ref->protocol;
		new_iph->saddr = iph_ref->saddr;
		new_iph->daddr = iph_ref->daddr;
		new_iph->version = iph_ref->version;
	}

	/*decode dynamic fields*/
	if(analyze_field_is_carryed(&iph_dynamic->df)){
		if(iph_dynamic->df.value)
			frag_off = IP_DF;
		else
			frag_off = 0;
		new_iph->frag_off = htons(frag_off);
	}else
		new_iph->frag_off = iph_ref->frag_off;
	if(analyze_field_is_carryed(&iph_dynamic->dscp))
		dscp = iph_dynamic->dscp.value & 0x3f;
	else
		dscp = iph_ref->tos >> 2;
	if(analyze_field_is_carryed(&iph_dynamic->ecn))
		ecn = iph_dynamic->ecn.value & 0x3;
	else
		ecn = 0;
	new_iph->tos = (dscp << 6) | ecn;

	if(decomp_wlsb_analyze_field_is_carryed(ttl_hl)){
		if(!ttl_hl->is_comp)
			new_iph->ttl = ttl_hl->encode_v & 0xff;
		else{
			/*only the ttl of the inner ip header when context contains two ip header or
			 * the ttl of the outer ip header when context contains only one ip header
			 */
			/*lsb decode*/
			if(rohc_decomp_lsb_decode(ttl_hl_wlsb,ttl_hl->encode_bits,ROHC_LSB_TCP_TTL_HL,ttl_hl->encode_v,&ttl_hl_v,false)){
			rohc_pr(ROHC_DTCP,"profile tcp decode ttlhl by wlsb failed\n");
			retval = -EFAULT;
			goto out;

			}else{
				new_iph->ttl = ttl_hl_v;
			}
		}
	}else
		new_iph->ttl = iph_ref->ttl;
	/*decode ipid*/
	if(ip_id_is_zero(ipid_bh))
		new_iph->id = 0;
	else if(ip_id_is_random(ipid_bh)){
		if(!decomp_wlsb_analyze_field_is_carryed(ipid) || ipid->is_comp){
			rohc_pr(rohc_err,"profile tcp the random ipv4 header  ipid carred-%d,is_comp-%d",decomp_wlsb_analyze_field_is_carryed(ipid),ipid->is_comp);
			retval = -EFAULT;
			goto out;
		}
		new_iph->id = ipid->encode_v & 0xffff;
	}else{
		if(unlikely(!decomp_wlsb_analyze_field_is_carryed(ipid))){
			rohc_pr(rohc_err,"profile tcp sequential ipv4 header ipid is not be carred\n");
			retval = -EFAULT;
			goto out;
		}
		if(!ipid->is_comp)
			new_iph->id = ipid->encode_v & 0xffff;
		else{
			if(rohc_decomp_lsb_decode(ip_id_wlsb,ipid->encode_bits,ROHC_LSBC_TCP_IPID_K_TO_P(ipid->encode_bits),ipid->encode_v,&ipid_off,false)){
				rohc_pr(rohc_err,"profile tcp decode ipid failed by lsb algorithm\n");
				retval = -EFAULT;
				goto out;
			}else{
				new_ipid_v = ipid_off + msn;
				if(!ip_id_is_nbo(ipid_bh))
					new_ipid_v = __swab16(new_ipid_v);
				/*change to network byte*/
				new_iph->id = htons(new_ipid_v);
			}
		}
		rohc_pr(ROHC_DTCP,"profile tcp decode new ipid = %d\n",ntohs(new_iph->id));
	}
out:
	return retval;
}
int decomp_tcp_decode_ip_header(struct decomp_tcp_iph_context *ip_context,struct rohc_decomp_pkt_hdr_info *pkt_info,u32 msn)
{
	struct iphdr *decode_iph,*old_iph;
	struct ipv6hdr *decode_ipv6h,*old_ipv6h;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;
	struct tcp_iph_analyze_fields *analyze_fields;
	struct tcp_decode_iph *to_decode_iphs;
	int retval;

	iph_update = &ip_context->update_by_packet;
	iph_ref = &ip_context->iph_ref;
	to_decode_iphs = &iph_update->decoded_iphs;

	if(rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,false))){
		decode_iph = &to_decode_iphs->iph;
		old_iph = &iph_ref->iph;
		retval = decode_ipv4_header(&iph_update->iph_analyze_fields.ipv4_analyze_fields,decode_iph,old_iph,ip_context->inner_ttl_hl_wlsb,ip_context->ipid_wlsb,tcp_iph_obain_new_ipid_bh(iph_update,iph_ref,false),msn);
		if(retval)
			goto out;
	}else{
		//ipv6 decode.
	}

	if(has_inner_iph(iph_update,iph_ref)){
		if(rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,true))){
			decode_iph = &to_decode_iphs->inner_iph;
			old_iph = &iph_ref->inner_iph;
			retval = decode_ipv4_header(&iph_update->inner_iph_analyze_fields.ipv4_analyze_fields,decode_iph,old_iph,ip_context->inner_ttl_hl_wlsb,ip_context->inner_ipid_wlsb,tcp_iph_obain_new_ipid_bh(iph_update,iph_ref,false),msn);
		}
	}
out:
	return retval;
}

static inline void decode_tcp_header_flag(struct analyze_field *ana_field,struct tcphdr *tcph,struct tcphdr *old_tcph,int flag_field)
{
	switch(flag_field){
		case DECOMP_TCP_FIELD_ACK_F:
			if(analyze_field_is_carryed(ana_field))
				tcph->ack = ana_field->value;
			else
				tcph->ack = old_tcph->ack;
			break;
		case DECOMP_TCP_FIELD_FIN_F:
			if(analyze_field_is_carryed(ana_field))
				tcph->fin = ana_field->value;
			else
				tcph->fin = old_tcph->fin;
			break;
		case DECOMP_TCP_FIELD_SYN_F:
			if(analyze_field_is_carryed(ana_field))
				tcph->syn = ana_field->value;
			else
				tcph->syn = old_tcph->syn;
			break;
		case DECOMP_TCP_FIELD_RST_F:
			if(analyze_field_is_carryed(ana_field))
				tcph->rst = ana_field->value;
			else
				tcph->rst = old_tcph->rst;
			break;
		case DECOMP_TCP_FIELD_URG_F:
			if(analyze_field_is_carryed(ana_field))
				tcph->urg = ana_field->value;
			else
				tcph->urg = old_tcph->urg;
			break;
		case DECOMP_TCP_FIELD_RES_F:
			if(analyze_field_is_carryed(ana_field))
				tcph->res1 = ana_field->value & 0xf;
			else
				tcph->res1 = old_tcph->res1;
			break;
	}
}
int decomp_tcp_decode_tcp_header(struct decomp_tcph_context *tcp_context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct sk_buff *skb;
	struct tcphdr *decode_tcph,*old_tcph;
	struct decomp_tcph_update *tcph_update;
	struct last_decomped_tcph_ref *tcph_ref;
	struct tcph_static_fields *tcph_static;
	struct tcph_dynamic_fields *tcph_dynamic;
	struct tcp_decode_tcph *to_decode_tcph;
	struct wlsb_analyze_field *seq_field,*seq_scaled_field;
	struct wlsb_analyze_field *ack_seq_field,*ack_seq_scaled_field;
	struct wlsb_analyze_field *win_field,*msn_field;
	u32 seq_factor,seq_residue;
	u32 ack_stride,ack_seq_residue;
	u32 seq,ack_seq;
	u32 seq_scaled,ack_seq_scaled;
	u32 window,msn;
	int retval = 0;

	skb = pkt_info->skb;
	tcph_update = &tcp_context->update_by_packet;
	tcph_ref = &tcp_context->tcph_ref;

	to_decode_tcph = &tcph_update->decode_tcph;
	tcph_static = &tcph_update->analyze_fields.static_fields;
	tcph_dynamic = &tcph_update->analyze_fields.dynamic_fields;

	decode_tcph = &to_decode_tcph->tcph;
	old_tcph = &tcph_ref->tcph;
	/*tcp packet payload len*/

	seq_factor = skb->len - pkt_info->decomped_hdr_len;
	/*decode static part*/
	if(tcph_static->update){
		decode_tcph->source = tcph_static->sport;
		decode_tcph->dest = tcph_static->dport;
	}else{
		decode_tcph->source = old_tcph->source;
		decode_tcph->dest = old_tcph->dest;
	}

	/*decode dynamic part*/
	/*first decode tcp header flags*/
	decode_tcp_header_flag(&tcph_dynamic->fin,decode_tcph,old_tcph,DECOMP_TCP_FIELD_FIN_F);

	decode_tcp_header_flag(&tcph_dynamic->syn,decode_tcph,old_tcph,DECOMP_TCP_FIELD_SYN_F);

	decode_tcp_header_flag(&tcph_dynamic->rst,decode_tcph,old_tcph,DECOMP_TCP_FIELD_RST_F);

	decode_tcp_header_flag(&tcph_dynamic->res1,decode_tcph,old_tcph,DECOMP_TCP_FIELD_RES_F);
	decode_tcp_header_flag(&tcph_dynamic->ack,decode_tcph,old_tcph,DECOMP_TCP_FIELD_ACK_F);
	decode_tcp_header_flag(&tcph_dynamic->urg,decode_tcph,old_tcph,DECOMP_TCP_FIELD_URG_F);

	/*decode urg ptr*/
	if(analyze_field_is_carryed(&tcph_dynamic->urg_ptr))
		decode_tcph->urg_ptr = tcph_dynamic->urg_ptr.value & 0xffff;
	else
		decode_tcph->urg_ptr = old_tcph->urg_ptr;

	/*decode ecn flags*/
	if(analyze_field_is_carryed(&tcph_dynamic->ecn))
		tcp_ecn_decode(tcph_dynamic->ecn.value & 0x3,decode_tcph);
	else{
		/*ecn flags  not be carryed*/
		decode_tcph->ece = 0;
		decode_tcph->cwr = 0;
	}
	if(!analyze_field_is_carryed(&tcph_dynamic->psh)){
		rohc_pr(rohc_err,"tcp push flags should be carryed every packet\n");
		retval = -EFAULT;
		goto out;
	}else
		decode_tcph->psh = tcph_dynamic->psh.value;

	/*decode the tcp heade checksum*/
	if(!analyze_field_is_carryed(&tcph_dynamic->check)){
		rohc_pr(rohc_err,"tcp header checksum should be carryed every packet\n");
		retval = -EFAULT;
		goto out;
	}else{
		decode_tcph->check = tcph_dynamic->check.value & 0xffff;
	}

	/*decode tcp header sequential*/
	seq_scaled_field = &tcph_dynamic->seq_scaled;
	seq_field = &tcph_dynamic->seq;
	if(decomp_wlsb_analyze_field_is_carryed(seq_scaled_field)){

		if(rohc_decomp_lsb_decode(tcp_context->seq_scaled_wlsb,seq_scaled_field->encode_bits,ROHC_LSB_TCP_SEQ_SCALED_P,seq_scaled_field->encode_v,&seq_scaled,false)){
			rohc_pr(ROHC_DTCP,"profile tcp decode tcp seq scaled failed by wlsb\n");
			retval = -EFAULT;
			goto out;
		}else{
			if(!seq_factor){
				rohc_pr(ROHC_DTCP,"seq scaled is %d after decode when tcp payload len is zero\n",seq_scaled);
				seq = tcph_ref->seq_residue;
			}else{
				seq = seq_factor * seq_scaled + tcph_ref->seq_residue;
			}
			decomp_wlsb_fill_analyze_field(seq_scaled_field,seq_scaled,32,false);
			decode_tcph->seq = htonl(seq);
		}
	}else if(decomp_wlsb_analyze_field_is_carryed(seq_field)){
		if(!seq_field->is_comp)
			seq = ntohl(seq_field->encode_v);
		else{
			if(rohc_decomp_lsb_decode(tcp_context->seq_wlsb,seq_field->encode_bits,seq_field->encode_p,seq_field->encode_v,&seq,false)){
				rohc_pr(ROHC_DTCP,"profile tcp decode tcp seq failed by wlsb\n");
				retval = -EFAULT;
				goto out;
			}
		}
		/*the scaling factor and residue needs to be recalculate when the sequential
		 * is received
		 */
		if(/*seq_factor*/1){
			tcp_field_scaling(seq_factor,&seq_scaled,seq,&seq_residue);
			decomp_wlsb_fill_analyze_field(seq_scaled_field,seq_scaled,32,false);
			decomp_fill_analyze_field(&tcph_dynamic->seq_residue,seq_residue);
		}
		seq = htonl(seq);
		decode_tcph->seq = seq;
	}else{
		/*tcp header seq not update*/
		decode_tcph->seq = old_tcph->seq;
		/*
		tcp_field_scaling(seq_factor,&seq_scaled,ntohl(decode_tcph->seq),&seq_residue);
		decomp_wlsb_fill_analyze_field(seq_scaled_field,seq_scaled,32,false);
		decomp_fill_analyze_field(&tcph_dynamic->seq_residue,seq_residue);
		*/
	}

	if(analyze_field_is_carryed(&tcph_dynamic->ack_stride))
		ack_stride = tcph_dynamic->ack_stride.value & 0xffff;
	else
		ack_stride = tcph_ref->ack_stride;
	ack_seq_scaled_field = &tcph_dynamic->ack_seq_scaled;
	ack_seq_field = &tcph_dynamic->ack_seq;
	if(decomp_wlsb_analyze_field_is_carryed(ack_seq_scaled_field)){
		if(rohc_decomp_lsb_decode(tcp_context->ack_seq_scaled_wlsb,ack_seq_scaled_field->encode_bits,ROHC_LSB_TCP_ACK_SEQ_SCALED_P,ack_seq_scaled_field->encode_v,&ack_seq_scaled,false)){
			rohc_pr(ROHC_DTCP,"profile tcp decode tcp ack seq scaled failed by wlsb\n");
			retval = -EFAULT;
			goto out;
		}else{
			if(!ack_stride){
				rohc_pr(ROHC_DTCP,"ack seq scaled is %d after decode when ack stride is zero\n",ack_seq_scaled);
				ack_seq = tcph_ref->ack_seq_residue;
			}else{
				ack_seq = ack_stride * ack_seq_scaled + tcph_ref->ack_seq_residue;
			}
			decomp_wlsb_fill_analyze_field(ack_seq_scaled_field,ack_seq_scaled,32,false);
			decode_tcph->ack_seq = htonl(ack_seq);
		}
	}else if(decomp_wlsb_analyze_field_is_carryed(ack_seq_field)){
		if(!ack_seq_field->is_comp)
			ack_seq = ntohl(ack_seq_field->encode_v);
		else{
			if(rohc_decomp_lsb_decode(tcp_context->ack_seq_wlsb,ack_seq_field->encode_bits,ack_seq_field->encode_p,ack_seq_field->encode_v,&ack_seq,false)){
				rohc_pr(ROHC_DTCP,"profile tcp decode ack seq by wlsb failed\n");
				retval = -EFAULT;
			}
		}
		/*the scaling factor and residue needs to be recalculate when the ack sequential
		 * is received
		 */
		if(/*ack_stride*/1){
			tcp_field_scaling(ack_stride,&ack_seq_scaled,ack_seq,&ack_seq_residue);
			decomp_wlsb_fill_analyze_field(ack_seq_scaled_field,ack_seq_scaled,32,false);
			decomp_fill_analyze_field(&tcph_dynamic->ack_seq_residue,ack_seq_residue);
		}
		decode_tcph->ack_seq = htonl(ack_seq);
	}else{
		decode_tcph->ack_seq = old_tcph->ack_seq;
	}

	/*decode the window*/
	win_field = &tcph_dynamic->window;
	if(decomp_wlsb_analyze_field_is_carryed(win_field)){
		if(!win_field->is_comp)
			window = win_field->encode_v & 0xffff;
		else{
			if(rohc_decomp_lsb_decode(tcp_context->window_wlsb,win_field->encode_bits,ROHC_LSB_TCP_K_RSHIFT_1_TO_P(win_field->encode_bits),win_field->encode_v,&window,false)){
				rohc_pr(ROHC_DTCP,"profile tcp decode tcp window failed\n");
				retval = -EFAULT;
				goto out;
			}
			window = htons((u16)window);
		}
		decode_tcph->window = window & 0xffff;
	}else
		decode_tcph->window = old_tcph->window;

out:
	return retval;
}

static int decomp_tcp_decode_msn(struct decomp_tcph_context *tcp_context)
{
	struct tcph_dynamic_fields *tcph_dynamic;
	struct wlsb_analyze_field *msn_field;
	struct tcp_decode_tcph *to_decode_tcph;
	u32 msn;
	int retval = 0;

	tcph_dynamic = &tcp_context->update_by_packet.analyze_fields.dynamic_fields;
	to_decode_tcph = &tcp_context->update_by_packet.decode_tcph;
	msn_field = &tcph_dynamic->msn;
	if(decomp_wlsb_analyze_field_is_carryed(msn_field)){
		if(!msn_field->is_comp)
			to_decode_tcph->new_msn = msn_field->encode_v & 0xffff;
		else{
			if(rohc_decomp_lsb_decode(tcp_context->msn_wlsb,msn_field->encode_bits,ROHC_LSB_TCP_MSN_P,msn_field->encode_v,&msn,false)){
				rohc_pr(ROHC_DTCP,"profile tcp decode msn failed\n");
				retval = -EFAULT;
				goto out;
			}
			to_decode_tcph->new_msn = msn;
		}
	}else
		pr_err("profile tcp: msn should be carryed in every packet\n");
	rohc_pr(ROHC_DTCP,"tcp  msn = %d\n",to_decode_tcph->new_msn);
out:
	return retval;
}

int decomp_tcp_decode_packet_header(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcp_iph_context *ip_context;
	struct decomp_tcph_context *tcp_context;
	struct decomp_tcph_options_context *opt_context;

	int retval;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	ip_context = &d_tcp_context->ip_context;
	tcp_context = &d_tcp_context->tcp_context;
	opt_context = &d_tcp_context->opt_context;
	/*because decoding ipid requires MSN,so decode msn firstly*/

	retval = decomp_tcp_decode_msn(tcp_context);
	if(retval)
		goto out;
	d_tcp_context->debug_msn = tcp_context->update_by_packet.decode_tcph.new_msn;
	retval = decomp_tcp_decode_ip_header(ip_context,pkt_info,tcp_context->update_by_packet.decode_tcph.new_msn);
	if(retval)
		goto out;
	retval = decomp_tcp_decode_tcp_header(tcp_context,pkt_info);
	if(retval)
		goto out;
	retval = tcp_options_decode(opt_context,pkt_info,&tcp_context->update_by_packet.decode_tcph.tcph);
out:
	return retval;
}

static inline void rebuild_ipv4_header(struct iphdr *decode_iph,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool is_inner)
{
	struct iphdr *new_iph;
	new_iph = (struct iphdr *)skb_tail_pointer(decomp_skb);
	if(is_inner)
		skb_set_inner_network_header(decomp_skb,decomp_skb->len);
	else
		skb_set_network_header(decomp_skb,decomp_skb->len);
	memcpy(new_iph,decode_iph,sizeof(struct iphdr));
	/*rohc is not support ip options*/
	new_iph->ihl = 5;
	skb_put(decomp_skb,sizeof(struct iphdr));
	pkt_info->rebuild_hdr_len += sizeof(struct iphdr);

}
static inline void rebuild_ipv6_header(struct ipv6hdr *decode_ipv6h,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{

}
int decomp_tcp_rebuild_ip_header(struct decomp_tcp_iph_context *ip_context,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct iphdr *decode_iph;
	struct ipv6hdr *decode_ipv6h;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;

	iph_update = &ip_context->update_by_packet;
	iph_ref = &ip_context->iph_ref;
	if(rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,false))){
		decode_iph = &iph_update->decoded_iphs.iph;
		rebuild_ipv4_header(decode_iph,decomp_skb,pkt_info,false);
	}else{
		//TODO .ipv6
	}

	if(has_inner_iph(iph_update,iph_ref)){
		if(rohc_iph_is_v4(tcp_iph_obain_vesion(iph_update,iph_ref,true))){
			decode_iph = &iph_update->decoded_iphs.inner_iph;
			rebuild_ipv4_header(decode_iph,decomp_skb,pkt_info,true);
		}else{
			//TODO.ipv6
		}
	}

	return 0;
}
/*tcp header rebuild contains pure tcp header and options*/

int decomp_tcp_rebuild_tcp_header(struct decomp_tcph_context *tcp_context,struct decomp_tcph_options_context *opt_context,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct tcphdr *decode_tcph,*new_tcph;
	int opts_total_len;
	int retval = 0;
	new_tcph = (struct tcphdr *)skb_tail_pointer(decomp_skb);
	skb_set_transport_header(decomp_skb,decomp_skb->len);
	decode_tcph = &tcp_context->update_by_packet.decode_tcph.tcph;
	memcpy(new_tcph,decode_tcph,sizeof(struct tcphdr));
	skb_put(decomp_skb,sizeof(struct tcphdr));
	pkt_info->rebuild_hdr_len += sizeof(struct tcphdr);
	/*rebuild options if present*/
	tcp_option_rebuild(opt_context,decomp_skb,pkt_info,&opts_total_len);
	/*fill the total length of tcp header*/
	if((opts_total_len + sizeof(struct tcphdr)) % 4){
		rohc_pr(ROHC_DTCP,"error tcp header total length:%d\n",opts_total_len + sizeof(struct tcphdr));
		retval = -EFAULT;
		goto out;
	}
	new_tcph->doff = (opts_total_len + sizeof(struct tcphdr)) / 4;
out:
	return retval;
}


static inline enum rohc_packet_type adjust_seq_packet_type(const u8 *analyze_data)
{
	enum rohc_packet_type packet_type;
	if(rohc_packet_is_seq1(analyze_data))
		packet_type = ROHC_PACKET_TYPE_SEQ1;
	else if(rohc_packet_is_seq2(analyze_data))
		packet_type = ROHC_PACKET_TYPE_SEQ2;
	else if(rohc_packet_is_seq3(analyze_data))
		packet_type = ROHC_PACKET_TYPE_SEQ3;
	else if(rohc_packet_is_seq4(analyze_data))
		packet_type = ROHC_PACKET_TYPE_SEQ4;
	else if(rohc_packet_is_seq5(analyze_data))
		packet_type = ROHC_PACKET_TYPE_SEQ5;
	else if(rohc_packet_is_seq6(analyze_data))
		packet_type = ROHC_PACKET_TYPE_SEQ6;
	else if(rohc_packet_is_seq7(analyze_data))
		packet_type = ROHC_PACKET_TYPE_SEQ7;
	else if(rohc_packet_is_seq8(analyze_data))
		packet_type = ROHC_PACKET_TYPE_SEQ8;
	else{
		packet_type = ROHC_PACKET_TYPE_UNDECIDE;
		rohc_pr(ROHC_DTCP,"profile tcp can't adjust the packet tyep:%x",*analyze_data);
	}
	return packet_type;
}

static inline enum rohc_packet_type adjust_rnd_packet_type(const u8 *analyze_data)
{
	enum rohc_packet_type packet_type;
	if(rohc_packet_is_rnd1(analyze_data))
		packet_type = ROHC_PACKET_TYPE_RND1;
	else if(rohc_packet_is_rnd2(analyze_data))
		packet_type = ROHC_PACKET_TYPE_RND2;
	else if(rohc_packet_is_rnd3(analyze_data))
		packet_type = ROHC_PACKET_TYPE_RND3;
	else if(rohc_packet_is_rnd4(analyze_data))
		packet_type = ROHC_PACKET_TYPE_RND4;
	else if(rohc_packet_is_rnd5(analyze_data))
		packet_type = ROHC_PACKET_TYPE_RND5;
	else if(rohc_packet_is_rnd6(analyze_data))
		packet_type = ROHC_PACKET_TYPE_RND6;
	else if(rohc_packet_is_rnd7(analyze_data))
		packet_type = ROHC_PACKET_TYPE_RND7;
	else if(rohc_packet_is_rnd8(analyze_data))
		packet_type = ROHC_PACKET_TYPE_RND8;
	else{
		packet_type = ROHC_PACKET_TYPE_UNDECIDE;
		rohc_pr(ROHC_DTCP,"profile can't adjust the packet type:%x\n",*analyze_data);
	}
	return packet_type;
}
enum rohc_packet_type decomp_tcp_adjust_packet_type(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcp_iph_context *ip_context;

	enum rohc_packet_type packet_type;
	enum rohc_cid_type cid_type;
	bool is_seq;
	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;

	ip_context = &d_tcp_context->ip_context;

	is_seq = tcp_iph_has_one_seq_ipid(ip_context);
	cid_type = context->decompresser->cid_type;

	if(cid_type == CID_TYPE_SMALL)
		analyze_data = skb->data + pkt_info->decomped_hdr_len + pkt_info->cid_len;
	else
		analyze_data = skb->data + pkt_info->decomped_hdr_len;

	/*fist adjust whether it is a package carrying ipid behavior*/
	if(rohc_packet_is_co_common(analyze_data))
		packet_type = ROHC_PACKET_TYPE_CO_COMMON;
	else{
		if(is_seq)
			packet_type = adjust_seq_packet_type(analyze_data);
		else
			packet_type = adjust_rnd_packet_type(analyze_data);
	}
	if(!context->cid)
		rohc_pr(ROHC_DTCP,"profile tcp adjust the packet_type=%d\n",packet_type);
	return packet_type;
}

int decomp_tcp_analyze_irr_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcph_options_context *opt_context;
	int retval;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	opt_context = &d_tcp_context->opt_context;

	retval = decomp_tcp_analyze_ip_irr_chain(d_tcp_context,skb,pkt_info);

	if(retval){
		rohc_pr(rohc_err,"profile tcp context-%d analyze ip irr chain failed\n",context->cid);
		goto out;
	}
	retval = decomp_tcp_analyze_tcp_irr_chain(d_tcp_context,skb,pkt_info);
	if(retval){
		rohc_pr(rohc_err,"profile tcp context-%d analyze tcp irr chain failed\n",context->cid);
		goto out;
	}
	retval = tcp_options_analyze_irr_chain(opt_context,skb,pkt_info);
	if(retval){
		rohc_pr(rohc_err,"profile tcp context-%d analyze tcp option irr chain failed\n",context->cid);
	}
out:
	return retval;
}

int decomp_tcp_analyze_co_header(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct sk_buff *decomp_skb;
	int (*analyze_co_func)(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first);
	enum rohc_packet_type packet_type;
	enum rohc_cid_type cid_type;
	int retval = 0;

	decomp_skb = context->decomp_skb;

	BUG_ON(decomp_skb->len);
	/*copy the ether header.
	 */
	if(context->decomp_eth_hdr){
		memcpy(decomp_skb->data,skb->data,sizeof(struct ethhdr));
		pkt_info->rebuild_hdr_len = sizeof(struct ethhdr);
		skb_put(decomp_skb,sizeof(struct ethhdr));
	}
	packet_type = pkt_info->packet_type;
	switch(packet_type){
		case ROHC_PACKET_TYPE_CO_COMMON:
			analyze_co_func = decomp_tcp_analyze_co_common;
			break;
		case ROHC_PACKET_TYPE_RND1:
			analyze_co_func = decomp_tcp_analyze_rnd1;
			break;
		case ROHC_PACKET_TYPE_RND2:
			analyze_co_func = decomp_tcp_analyze_rnd2;
			break;
		case ROHC_PACKET_TYPE_RND3:
			analyze_co_func = decomp_tcp_analyze_rnd3;
			break;
		case ROHC_PACKET_TYPE_RND4:
			analyze_co_func = decomp_tcp_analyze_rnd4;
			break;
		case ROHC_PACKET_TYPE_RND5:
			analyze_co_func = decomp_tcp_analyze_rnd5;
			break;
		case ROHC_PACKET_TYPE_RND6:
			analyze_co_func = decomp_tcp_analyze_seq6;
			break;
		case ROHC_PACKET_TYPE_RND7:
			analyze_co_func = decomp_tcp_analyze_rnd7;
			break;
		case ROHC_PACKET_TYPE_RND8:
			retval = decomp_tcp_analyze_rnd8(context,skb,pkt_info,true);
			if(retval){
				rohc_pr(ROHC_DTCP,"profile-tcp: context-%d analyze rand8 packet failed\n",context->cid);
				goto out;
			}
			retval = decomp_tcp_analyze_irr_chain(context,skb,pkt_info);
			return retval;

		case ROHC_PACKET_TYPE_SEQ1:
			analyze_co_func = decomp_tcp_analyze_seq1;
			break;
		case ROHC_PACKET_TYPE_SEQ2:
			analyze_co_func = decomp_tcp_analyze_seq2;
			break;
		case ROHC_PACKET_TYPE_SEQ3:
			analyze_co_func = decomp_tcp_analyze_seq3;
			break;
		case ROHC_PACKET_TYPE_SEQ4:
			analyze_co_func = decomp_tcp_analyze_seq4;
			break;
		case ROHC_PACKET_TYPE_SEQ5:
			analyze_co_func = decomp_tcp_analyze_seq5;
			break;
		case ROHC_PACKET_TYPE_SEQ6:
			analyze_co_func = decomp_tcp_analyze_seq6;
			break;
		case ROHC_PACKET_TYPE_SEQ7:
			analyze_co_func = decomp_tcp_analyze_seq7;
			break;
		case ROHC_PACKET_TYPE_SEQ8:
			analyze_co_func = decomp_tcp_analyze_seq8;
			break;
		default:
			pr_err("not support the co packet type:%d\n",packet_type);
			break;
	}
	cid_type = context->decompresser->cid_type;
	if(cid_type == CID_TYPE_SMALL){
		pkt_info->decomped_hdr_len += pkt_info->cid_len;
		retval = analyze_co_func(context,skb,pkt_info,true);
		if(retval)
			goto out;
	}else{
		retval = analyze_co_func(context,skb,pkt_info,true);
		pkt_info->decomped_hdr_len += pkt_info->cid_len;
		retval = analyze_co_func(context,skb,pkt_info,false);
		if(retval)
			goto out;
	}
	/*next to analyze irr chain*/
	retval = decomp_tcp_analyze_irr_chain(context,skb,pkt_info);
	if(retval)
		rohc_pr(ROHC_DTCP,"profile-tcp: context-%d analyze irr chain failed\n",context->cid);
out:

	return retval;
}
int decomp_tcp_analyze_static_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	int retval;
	/*The static chain consists of one item for each header of the chain
	*of protocol headers to be compressed, starting from the outermost
	*IP header and ending with a TCP header
	*/
	retval = decomp_tcp_analyze_ip_static_chain(context,skb,pkt_info);
	if(retval)
		goto out;
	retval = decomp_tcp_analyze_tcp_static_chain(context,skb,pkt_info);

out:
	return retval;
}

int decomp_tcp_analyze_dynamic_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	int retval;
	/*
	*The dynamic chain consists of one item for each header of the
	*chain of protocol headers to be compressed, starting from the
	*outermost IP header and ending with a UDP header
	*/
	retval = decomp_tcp_analyze_ip_dynamic_chain(context,skb,pkt_info);
	retval = decomp_tcp_analyze_tcp_dynamic_chain(context,skb,pkt_info);
	return retval;
}
int decomp_tcp_rebuild_packet_header(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct sk_buff *decomp_skb;
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcp_iph_context *ip_context;
	struct decomp_tcph_context *tcp_context;
	struct decomp_tcph_options_context *opt_context;
	int retval = 0;

	decomp_skb = context->decomp_skb;
	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	ip_context = &d_tcp_context->ip_context;
	tcp_context = &d_tcp_context->tcp_context;
	opt_context = &d_tcp_context->opt_context;

	decomp_tcp_rebuild_ip_header(ip_context,decomp_skb,pkt_info);

	retval = decomp_tcp_rebuild_tcp_header(tcp_context,opt_context,decomp_skb,pkt_info);
	return retval;
}


int decomp_tcp_analyze_packet_header(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	enum rohc_packet_type packet_type;
	int retval;
	packet_type = pkt_info->packet_type;
	switch(packet_type){
		case ROHC_PACKET_TYPE_IR:
			retval = rohc_decomp_analyze_ir(context,skb,pkt_info);
			if(retval)
				rohc_pr(ROHC_DTCP,"profile tcp analyze ir packet failed\n");
			break;
		case ROHC_PACKET_TYPE_IR_DYN:
			retval = rohc_decomp_analyze_ir_dyn(context,skb,pkt_info);
			if(retval)
				rohc_pr(ROHC_DTCP,"profile tcp analyze ir-dyn packet failed\n");
			break;
		default:
			retval = decomp_tcp_analyze_co_header(context,skb,pkt_info);
			if(retval)
				rohc_pr(ROHC_DTCP,"profile tcp analyze co packet failed\n");
			break;
	}
	rohc_pr(ROHC_DTCP,"TCP context cid-%d packet_type = %d,decomped_hdr_len=%d\n",context->cid,packet_type,pkt_info->decomped_hdr_len);
	return retval;
}

int decomp_tcp_recover_net_packet_header(struct rohc_decomp_context *context,struct sk_buff *skb ,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct sk_buff *decomp_skb;
	struct decomp_tcp_context *d_tcp_context;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;

	u32 off;
	int retval = 0;

	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	iph_update = &d_tcp_context->ip_context.update_by_packet;
	iph_ref = &d_tcp_context->ip_context.iph_ref;

	decomp_skb = context->decomp_skb;
	skb_copy_bits(decomp_skb,0,skb->data,pkt_info->rebuild_hdr_len);

	off = skb_network_header(decomp_skb) - decomp_skb->data;
	iph = (struct iphdr *)(skb->data + off);
	skb_set_network_header(skb,off);

	iph->tot_len = htons(skb->len - off);
	iph->check = ip_fast_csum((unsigned char *)iph,iph->ihl);
	if(has_inner_iph(iph_update,iph_ref)){
		off = skb_inner_network_header(decomp_skb) - decomp_skb->data;
		iph = (struct iphdr *)(skb->data + off);
		skb_set_inner_network_header(skb,off);
		iph->tot_len = htons(skb->len - off);
		iph->check = ip_fast_csum((unsigned char *)iph,iph->ihl);
	}
	off = skb_transport_header(decomp_skb) - decomp_skb->data;
	skb_set_transport_header(skb,off);
	tcp_recover_net_header_dump(skb,context->cid,d_tcp_context->debug_msn);
	return retval;
}

u32 decomp_tcp_last_decompressed_sn(struct rohc_decomp_context *context)
{
	struct decomp_tcp_context *d_tcp_context;
	struct decomp_tcph_context *tcp_context;
	struct rohc_decomp_wlsb *msn_wlsb;
	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	tcp_context = &d_tcp_context->tcp_context;
	msn_wlsb = tcp_context->msn_wlsb;
	return rohc_decomp_lsb_pick_ref(msn_wlsb,false);
}

u8 decomp_tcp_sn_bit_width(struct rohc_decomp_context *context)
{
	return 16;
}

static inline int ip_context_init(struct decomp_tcp_iph_context *ip_context)
{
	struct rohc_decomp_wlsb *wlsb;
	int i;
	int retval = 0;
	ip_context->inner_ttl_hl_wlsb = rohc_decomp_lsb_alloc(TYPE_UCHAR,GFP_ATOMIC);
	if(IS_ERR(ip_context->inner_ttl_hl_wlsb)){
		retval = -ENOMEM;
		goto out;
	}
	for(i = 0 ; i < ROHC_MAX_IP_HDR ; i++){
		wlsb = rohc_decomp_lsb_alloc(TYPE_USHORT,GFP_ATOMIC);
		if(IS_ERR(wlsb)){
			if( i > 0)
				rohc_decomp_lsb_free(ip_context->ipid_wlsb);
			retval = -ENOMEM;
			goto err0;
		}
		ip_context->ip_id_wlsb[i] = wlsb;
	}
	return 0;
err0:
	rohc_decomp_lsb_free(ip_context->inner_ttl_hl_wlsb);
out:
	return retval;
}

static inline void ip_context_destroy(struct decomp_tcp_iph_context *ip_context)
{
	rohc_decomp_lsb_free(ip_context->inner_ttl_hl_wlsb);
	rohc_decomp_lsb_free(ip_context->ipid_wlsb);
	rohc_decomp_lsb_free(ip_context->inner_ipid_wlsb);
}
static inline void ip_context_update(struct  decomp_tcp_iph_context *ip_context,u16 msn)
{
	struct iphdr *new_iph,*to_iph;
	struct ipv6hdr *new_ipv6h,*to_ipv6h;
	struct tcp_iph_update *iph_update;
	struct last_decomped_iph_ref *iph_ref;
	struct tcp_decode_iph *decoded_iphs;

	u16 new_ipid_offset;
	u8  inner_ttl_hl;
	iph_update = &ip_context->update_by_packet;
	iph_ref = &ip_context->iph_ref;
	decoded_iphs = &iph_update->decoded_iphs;

	if(iph_update->has_inner_iph)
		iph_ref->has_inner_iph = true;
	if(analyze_field_is_carryed(&iph_update->new_ipid_bh))
		iph_ref->ipid_bh = (enum ip_id_behavior)iph_update->new_ipid_bh.value;
	new_iph = &decoded_iphs->iph;
	if(rohc_iph_is_v4(new_iph->version)){
		to_iph = &iph_ref->iph;
		memcpy(to_iph,new_iph,sizeof(struct iphdr));
		if(ip_id_is_nbo(iph_ref->ipid_bh))
			new_ipid_offset = ntohs(new_iph->id) - msn;
		else
			new_ipid_offset = __swab16(ntohs(new_iph->id)) - msn;
		rohc_decomp_lsb_setup_ref(ip_context->ipid_wlsb,new_ipid_offset);
		inner_ttl_hl = new_iph->ttl;
	}else{
		//IPV6
	}
	if(iph_ref->has_inner_iph){
		if(analyze_field_is_carryed(&iph_update->new_inner_ipid_bh))
			iph_ref->inner_ipid_bh = (enum ip_id_behavior)iph_update->new_ipid_bh.value;
		new_iph = &decoded_iphs->inner_iph;
		if(rohc_iph_is_v4(new_iph->version)){
			to_iph = &iph_ref->inner_iph;
			memcpy(to_iph,new_iph,sizeof(struct iphdr));
			if(ip_id_is_nbo(iph_ref->inner_ipid_bh))
				new_ipid_offset = ntohs(new_iph->id) - msn;
			else
				new_ipid_offset = __swab16(ntohs(new_iph->id)) - msn;
			rohc_decomp_lsb_setup_ref(ip_context->inner_ipid_wlsb,new_ipid_offset);
			inner_ttl_hl = new_iph->ttl;
		}else{
			//ipv6
		}
	}
	rohc_decomp_lsb_setup_ref(ip_context->inner_ttl_hl_wlsb,inner_ttl_hl);

}
static inline int tcp_context_init(struct decomp_tcph_context *tcp_context)
{
	struct rohc_decomp_wlsb *wlsb;
	int retval = 0;
	tcp_context->seq_wlsb = rohc_decomp_lsb_alloc(TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(tcp_context->seq_wlsb)){
		retval = -ENOMEM;
		goto out;
	}
	tcp_context->seq_scaled_wlsb = rohc_decomp_lsb_alloc(TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(tcp_context->seq_wlsb)){
		retval = -ENOMEM;
		goto err0;
	}
	tcp_context->ack_seq_wlsb = rohc_decomp_lsb_alloc(TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(tcp_context->ack_seq_wlsb)){
		retval = -ENOMEM;
		goto err1;
	}
	tcp_context->ack_seq_scaled_wlsb = rohc_decomp_lsb_alloc(TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(tcp_context->ack_seq_scaled_wlsb)){
		retval = -ENOMEM;
		goto err2;

	}
	tcp_context->window_wlsb = rohc_decomp_lsb_alloc(TYPE_USHORT,GFP_ATOMIC);
	if(IS_ERR(tcp_context->window_wlsb)){
		retval = -ENOMEM;
		goto err3;
	}
	tcp_context->msn_wlsb = rohc_decomp_lsb_alloc(TYPE_USHORT,GFP_ATOMIC);
	if(IS_ERR(tcp_context->msn_wlsb)){
		retval = -ENOMEM;
		goto err4;
	}
	return 0;
err4:
	rohc_decomp_lsb_free(tcp_context->window_wlsb);
err3:
	rohc_decomp_lsb_free(tcp_context->ack_seq_scaled_wlsb);
err2:
	rohc_decomp_lsb_free(tcp_context->ack_seq_wlsb);
err1:
	rohc_decomp_lsb_free(tcp_context->seq_scaled_wlsb);
err0:
	rohc_decomp_lsb_free(tcp_context->seq_wlsb);
out:
	return retval;
}

static inline void tcp_context_destroy(struct decomp_tcph_context *tcp_context)
{
	rohc_decomp_lsb_free(tcp_context->window_wlsb);
	rohc_decomp_lsb_free(tcp_context->msn_wlsb);
	rohc_decomp_lsb_free(tcp_context->seq_wlsb);
	rohc_decomp_lsb_free(tcp_context->seq_scaled_wlsb);
	rohc_decomp_lsb_free(tcp_context->ack_seq_wlsb);
	rohc_decomp_lsb_free(tcp_context->ack_seq_scaled_wlsb);
}


static void  tcp_context_update(struct decomp_tcph_context *tcp_context)
{
	struct tcphdr *new_tcph,*to_tcph;
	struct decomp_tcph_update *tcph_update;
	struct last_decomped_tcph_ref *tcph_ref;
	struct tcph_dynamic_fields *new_tcph_dynamic;

	u32 seq_scaled,ack_seq_scaled;

	tcph_update = &tcp_context->update_by_packet;
	tcph_ref = &tcp_context->tcph_ref;
	new_tcph_dynamic = &tcph_update->analyze_fields.dynamic_fields;

	new_tcph = &tcph_update->decode_tcph.tcph;
	to_tcph = &tcph_ref->tcph;
	memcpy(to_tcph,new_tcph,sizeof(struct tcphdr));

	/*update ack stride if change*/
	if(analyze_field_is_carryed(&new_tcph_dynamic->ack_stride))
		tcph_ref->ack_stride = new_tcph_dynamic->ack_stride.value;

	/*update the ack seq residue if recalculate */
	if(analyze_field_is_carryed(&new_tcph_dynamic->ack_seq_residue))
		tcph_ref->ack_seq_residue = new_tcph_dynamic->ack_seq_residue.value;

	/*update the seq residue if recalculate*/
	if(analyze_field_is_carryed(&new_tcph_dynamic->seq_residue))
		tcph_ref->seq_residue = new_tcph_dynamic->seq_residue.value;

	/*update the ack seq scaled and seq scaled if recalculate*/
	if(decomp_wlsb_analyze_field_is_carryed(&new_tcph_dynamic->seq_scaled))
		rohc_decomp_lsb_setup_ref(tcp_context->seq_scaled_wlsb,new_tcph_dynamic->seq_scaled.encode_v);

	if(decomp_wlsb_analyze_field_is_carryed(&new_tcph_dynamic->ack_seq_scaled))
		rohc_decomp_lsb_setup_ref(tcp_context->ack_seq_scaled_wlsb,new_tcph_dynamic->ack_seq_scaled.encode_v);

	rohc_decomp_lsb_setup_ref(tcp_context->seq_wlsb,ntohl(new_tcph->seq));
	rohc_decomp_lsb_setup_ref(tcp_context->ack_seq_wlsb,ntohl(new_tcph->ack_seq));
	rohc_decomp_lsb_setup_ref(tcp_context->window_wlsb,ntohs(new_tcph->window));

	rohc_decomp_lsb_setup_ref(tcp_context->msn_wlsb,tcph_update->decode_tcph.new_msn);
}
int decomp_tcp_init_context(struct rohc_decomp_context *context)
{
	struct decomp_tcp_context *d_tcp_context;
	int retval = 0;
	d_tcp_context = kzalloc(sizeof(struct decomp_tcp_context),GFP_ATOMIC);
	if(!d_tcp_context){
		pr_err("profile tcp context-%d alloc memeroy for decomp tcp context failed\n",context->cid);
		retval = -ENOMEM;
		goto err0;
	}
	retval = ip_context_init(&d_tcp_context->ip_context);
	if(retval)
		goto err1;
	retval = tcp_context_init(&d_tcp_context->tcp_context);
	if(retval)
		goto err2;
	retval = decomp_tcp_option_init_context(&d_tcp_context->opt_context);
	if(retval)
		goto err3;
	context->inherit_context = d_tcp_context;
	return retval;
err3:
	tcp_context_destroy(&d_tcp_context->tcp_context);
err2:
	ip_context_destroy(&d_tcp_context->ip_context);
err1:
	kfree(d_tcp_context);
err0:
	return retval;
}

int decomp_tcp_update_context(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct decomp_tcp_context *d_tcp_context;
	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	ip_context_update(&d_tcp_context->ip_context,d_tcp_context->tcp_context.update_by_packet.decode_tcph.new_msn);
	tcp_context_update(&d_tcp_context->tcp_context);
	tcp_option_update_context(&d_tcp_context->opt_context);

	if(analyze_field_is_carryed(&d_tcp_context->co_update.ecn_used))
		d_tcp_context->co_ref.ecn_used = !!d_tcp_context->co_update.ecn_used.value;
	return 0;
}

static inline void decomp_tcp_update_by_packet_reset(struct rohc_decomp_context *context)
{
	struct decomp_tcp_context *d_tcp_context;
	d_tcp_context = (struct decomp_tcp_context *)context->inherit_context;
	memset(&d_tcp_context->ip_context.update_by_packet,0,sizeof(struct tcp_iph_update));
	memset(&d_tcp_context->tcp_context.update_by_packet,0,sizeof(struct decomp_tcph_update));
	memset(&d_tcp_context->opt_context.update_by_packet,0,sizeof(struct decomp_tcp_options_update));
}


int decomp_tcp_decompress(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct rohc_decomp_profile_ops *prof_ops;
	int retval;
	prof_ops = context->decomp_profile->pro_ops;
	decomp_tcp_update_by_packet_reset(context);
	pkt_info->skb = skb;
	rohc_pr(ROHC_DTCP,"packet_type=%d\n",pkt_info->packet_type);
	retval = prof_ops->analyze_packet_header(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DTCP,"profile tcp : context-%d analyze packet header failed\n",context->cid);
		goto out;
	}
	retval = prof_ops->decode_packet_header(context,pkt_info);
	if(retval){
		rohc_pr(ROHC_DTCP,"profile tcp:context-%d decode package header failed\n",context->cid);
		goto out;
	}
	retval = prof_ops->rebuild_packet_header(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DTCP,"profile tcp: context-%d rebuild package header failed\n",context->cid);
		goto out;
	}

	prof_ops->update_context(context,pkt_info);
out:
	return retval;
}

struct rohc_decomp_profile_ops decomp_tcp_prof_ops = {
	.adjust_packet_type = decomp_tcp_adjust_packet_type,
	.analyze_packet_header = decomp_tcp_analyze_packet_header,
	.analyze_static_chain = decomp_tcp_analyze_static_chain,
	.analyze_dynamic_chain = decomp_tcp_analyze_dynamic_chain,
	.decode_packet_header = decomp_tcp_decode_packet_header,
	.rebuild_packet_header = decomp_tcp_rebuild_packet_header,
	.recover_net_packet_header = decomp_tcp_recover_net_packet_header,
	.decompress = decomp_tcp_decompress,
	.last_decompressed_sn = decomp_tcp_last_decompressed_sn,
	.sn_bit_width = decomp_tcp_sn_bit_width,
	.init_context = decomp_tcp_init_context,
	.update_context = decomp_tcp_update_context,
};

struct rohc_decomp_profile decomp_profile_tcp = {
	.profile = ROHC_V1_PROFILE_TCP,
	.pro_ops = &decomp_tcp_prof_ops,
};
