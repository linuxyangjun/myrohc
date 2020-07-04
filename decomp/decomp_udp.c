/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	date: 2020/02/18
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
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

#include "../rohc_packet_field_bh.h"
#include "../rohc_common.h"
#include "../rohc_packet.h"
#include "../rohc_profile.h"
#include "../lsb.h"

#include "rohc_decomp.h"
#include "rohc_decomp_profile_v1.h"
#include "rohc_decomp_wlsb.h"
#include "decomp_ip.h"
#include "rohc_decomp_packet.h"
#include "decomp_udp.h"
#include "rohc_decomp_v1_packet.h"
void recover_net_header_dump(struct sk_buff *skb,int cid,u32 msn)
{
	struct iphdr *iph;
	struct udphdr *udph;
	u8 *addr;
	iph = ip_hdr(skb);
	rohc_pr(ROHC_DUMP,"decomp cid : %d msn:%d\n",cid,msn);
	rohc_pr(ROHC_DUMP,"ipid=%d,id_off_msn=%u,tos=%d,ttl=%d,iphl=%d,tot_len=%d,fragof=%x,check=%x\n",ntohs(iph->id),ntohs(iph->id) - msn,iph->tos,iph->ttl,iph->ihl,iph->tot_len,iph->frag_off,iph->check);
	addr = (u8 *)&iph->saddr;
	rohc_pr(ROHC_DUMP,"ipsrc:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	addr = (u8 *)&iph->daddr;
	rohc_pr(ROHC_DUMP,"ipdst:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	udph = udp_hdr(skb);
	rohc_pr(ROHC_DUMP,"dport=%d,sport=%d,len=%d,udpcheck=%x\n",udph->source,udph->dest,udph->len,udph->check);

}
int decomp_udp_decode_msn(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct decomp_profile_v1_context *v1_context;
	struct wlsb_analyze_field *msn;
	struct rohc_decomp_wlsb *msn_wlsb;
	u32 new_msn;
	int retval = 0;
	v1_context = context->inherit_context;
	msn = &v1_context->msn_update;
	msn_wlsb = v1_context->msn_wlsb;
	BUG_ON(!decomp_wlsb_analyze_field_is_carryed(msn));
	if(!msn->is_comp){
		v1_context->msn = msn->encode_v;
	}else{
		if(rohc_decomp_lsb_decode(msn_wlsb,msn->encode_bits,ROHC_LSB_UDP_SN_P,msn->encode_v,&new_msn,false)){
			printk(KERN_DEBUG "profile-%x,cid-%d decode msn faled\n",context->decomp_profile->profile,context->cid);
			retval = -EFAULT;
		}else{
			v1_context->msn = new_msn & 0xffff;
		}
	}
	rohc_pr(ROHC_DEBUG,"msn = %d\n",v1_context->msn);
	return retval;
}


int rohc_decode_udp_header(struct decomp_udp_context *udp_context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct udphdr *decode_udph,*old_udph;
	struct udph_decomp_fields *udp_fields;
	struct udp_static_fields *static_fields;
	struct analyze_field *check;
	int retval = 0;
	udp_fields = &udp_context->update_by_packet.udph_fields;
	decode_udph = &udp_context->update_by_packet.decoded_udph;
	old_udph = &udp_context->last_context_info.udph;
	static_fields = &udp_fields->udp_static_part;
	check = &udp_fields->udph_dynamic_part.check;
	/*decode static fields
	 */
	if(udp_fields->udp_static_fields_update){
		decode_udph->source = static_fields->sport;
		decode_udph->dest = static_fields->dport;
	}else{
		decode_udph->source = old_udph->source;
		decode_udph->dest = old_udph->dest;
	}
	/*decode dynamic part
	 */
	if(analyze_field_is_carryed(check)){
		decode_udph->check = check->value & 0xffff;
	}else
		decode_udph->check = 0;//old_udph->check;

	return retval;
}

int  rohc_rebuild_udp_header(struct decomp_udp_context *udp_context,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info,struct sk_buff *skb)
{
	struct udphdr *decode_udph,*udph;

	int retval = 0;

	decode_udph = &udp_context->update_by_packet.decoded_udph;
	skb_set_transport_header(decomp_skb,decomp_skb->len);
	udph = (struct udphdr *)skb_tail_pointer(decomp_skb);
	memcpy(udph,decode_udph,sizeof(struct udphdr));
	/*udp header len 
	 *
	 */
	udph->len = htons(skb->len - pkt_info->decomped_hdr_len + sizeof(struct udphdr));
	skb_put(decomp_skb,sizeof(struct udphdr));
	pkt_info->rebuild_hdr_len += sizeof(struct udphdr);
	return retval;
}

int decomp_udp_analyze_profile_header(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct analyze_field *new_check_bh;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_udp_context *udp_context;
	struct last_udph_info *last_context_info;
	struct udph_decomp_dynamic_part *udp_dynamic_part;
	u16 check;
	int check_bh;
	int analyze_len = 0;
	int retval = 0;
	v1_context = context->inherit_context;
	udp_context = v1_context->inherit_context;
	last_context_info = &udp_context->last_context_info;
	udp_dynamic_part = &udp_context->update_by_packet.udph_fields.udph_dynamic_part;
	new_check_bh = &udp_context->update_by_packet.udp_check_bh;
	if(analyze_field_is_carryed(new_check_bh))
		check_bh = new_check_bh->value;
	else
		check_bh = last_context_info->check_behavior;
	if(check_bh == UDP_HAS_CHECKSUM){
		analyze_data = skb->data + pkt_info->decomped_hdr_len;
		memcpy(&check,analyze_data,2);
		analyze_data += 2;
		analyze_len += 2;
		decomp_fill_analyze_field(&udp_dynamic_part->check,check);
	}
	rohc_pr(ROHC_DEBUG,"%s :check_bh=%d,analyze_len=%d\n ",__func__,check_bh,analyze_len);
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int rohc_decomp_analyze_udp_static_chain(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_udp_context *udp_context;
	struct udp_static_fields *udp_static_part;
	int analyze_len = 0;
	int retval = 0;
	v1_context = context->inherit_context;
	udp_context = v1_context->inherit_context;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	udp_static_part = &udp_context->update_by_packet.udph_fields.udp_static_part;
	memcpy(udp_static_part,analyze_data,sizeof(struct udp_static_fields));
	analyze_data += sizeof(struct udp_static_fields);
	analyze_len += sizeof(struct udp_static_fields);
	udp_context->update_by_packet.udph_fields.udp_static_fields_update = true;
	pkt_info->decomped_hdr_len += analyze_len;
	rohc_pr(ROHC_DEBUG,"udp static : dport=%d,sport=%d\n",udp_static_part->dport,udp_static_part->sport);
	return retval;
}

int rohc_decomp_analyze_udp_dynamic_chain(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_udp_context *udp_context;
	struct udph_decomp_dynamic_part *udp_dynamic_part;
	struct analyze_field *new_check_bh;
	struct wlsb_analyze_field *msn;
	struct udp_dynamic_fields *dynamic_fields;
	int analyze_len = 0;
	int retval = 0;
	v1_context = context->inherit_context;
	msn = &v1_context->msn_update;
	udp_context = v1_context->inherit_context;
	udp_dynamic_part = &udp_context->update_by_packet.udph_fields.udph_dynamic_part;
	new_check_bh = &udp_context->update_by_packet.udp_check_bh;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	dynamic_fields = (struct udp_dynamic_fields *)analyze_data;
	decomp_wlsb_fill_analyze_field(msn,dynamic_fields->msn,16,false);
	decomp_fill_analyze_field(&udp_dynamic_part->check,dynamic_fields->checksum);
	if(udp_dynamic_part->check.value)
		decomp_fill_analyze_field(new_check_bh,UDP_HAS_CHECKSUM);
	else
		decomp_fill_analyze_field(new_check_bh,UDP_NO_CHECKSUM);
	analyze_len += sizeof(struct udp_dynamic_fields);
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

void decomp_udp_dump(struct sk_buff *skb,int cid,char *func)
{
	struct iphdr *iph;
	struct udphdr *udph;
	u8 *addr;
	iph = ip_hdr(skb);
	rohc_pr(ROHC_DEBUG,"%s cid : %d\n",func,cid);
	rohc_pr(ROHC_DEBUG,"ipid=%d,tos=%d,ttl=%d\n",ntohs(iph->id),iph->tos,iph->ttl);
	addr = (u8 *)&iph->saddr;
	rohc_pr(ROHC_DEBUG,"ipsrc:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	addr = (u8 *)&iph->daddr;
	rohc_pr(ROHC_DEBUG,"ipdst:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	udph = udp_hdr(skb);
	rohc_pr(ROHC_DEBUG,"dport=%d,sport=%d,udplen=%d\n",udph->source,udph->dest,ntohs(udph->len));

}
int decomp_udp_recover_net_header(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *data_start;
	struct sk_buff *decomp_skb;
	struct ethhdr *ethh;
	struct iphdr *outer_iph,*inner_iph;
	struct udphdr *udph;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_ip_context *ip_context;
	int recover_len = 0;
	int retval = 0;
	v1_context = context->inherit_context;
	ip_context = &v1_context->ip_context;
	decomp_skb = context->decomp_skb;
	data_start = skb->data;
	decomp_udp_dump(decomp_skb,context->cid,__func__);
	skb_copy_bits(decomp_skb,0,skb->data,pkt_info->rebuild_hdr_len);
	outer_iph = skb->data + (skb_network_header(decomp_skb) - decomp_skb->data);
	if(outer_iph->version == 4){
		outer_iph->tot_len = htons(skb->len - ((unsigned char *)outer_iph - skb->data));
		outer_iph->check = ip_fast_csum((unsigned char *)outer_iph,outer_iph->ihl);
		skb_set_network_header(skb,(unsigned char *)outer_iph - skb->data);
	}else{
		//ipv6
	}
	if(rohc_decomp_has_inner_iph(&ip_context->last_context_info,&ip_context->update_by_packet)){
		inner_iph = skb->data + (skb_inner_network_header(decomp_skb) - decomp_skb->data);
		if(inner_iph->version == 4){
			inner_iph->tot_len = htons(skb->len - ((skb_inner_network_header(decomp_skb) - decomp_skb->data)));
			inner_iph->check = ip_fast_csum((unsigned char *)inner_iph,inner_iph->ihl);
		}else{
			//ipv6
		}
	}
	/*recover the udp header len.
	 */
	udph = skb->data + (skb_transport_header(decomp_skb) - decomp_skb->data);
	udph->len = htons(skb->len - pkt_info->rebuild_hdr_len + sizeof(struct udphdr));
	skb_set_transport_header(skb,(unsigned char *)udph - skb->data);
//	decomp_udp_dump(skb,context->cid,__func__);	
	if(context->cid == 2){
		rohc_pr(ROHC_DUMP,"packet_type=%d,ext_type=%d,comped_hlen=%d,ture_hlen=%d\n",pkt_info->packet_type,v1_context->ext_type,pkt_info->decomped_hdr_len - 14,pkt_info->rebuild_hdr_len - 14);
		recover_net_header_dump(skb,context->cid,v1_context->msn);
	}
	return 0;
}

int decomp_udp_update_context(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct decomp_profile_v1_context *v1_context;
	struct decomp_udp_context *udp_context;
	struct last_udph_info *last_context_info;
	struct udph_decomp_update *udp_update;
	struct udphdr *decode_udph,*to_save_udph;
	struct analyze_field *new_check_bh;
	int retval = 0;
	v1_context = context->inherit_context;
	udp_context = v1_context->inherit_context;
	udp_update = &udp_context->update_by_packet;
	last_context_info = &udp_context->last_context_info;
	to_save_udph = &last_context_info->udph;
	new_check_bh = &udp_update->udp_check_bh;
	decode_udph = &udp_update->decoded_udph;
	memcpy(to_save_udph,decode_udph,sizeof(struct udphdr));
	if(analyze_field_is_carryed(new_check_bh))
		last_context_info->check_behavior = new_check_bh->value;
	printk(KERN_DEBUG "msn = %d\n",v1_context->msn);
	rohc_decomp_lsb_setup_ref(v1_context->msn_wlsb,v1_context->msn);
	rohc_update_ip_context(&v1_context->ip_context,pkt_info,v1_context->msn);
	return retval;
}

int decomp_udp_analyze_static_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	int retval = 0;
	retval = rohc_decomp_analyze_ip_static_chain(context,skb,pkt_info);
	if(retval){
		pr_err("profile udp cid-%d analyze ip static chain faled\n",context->cid);
		goto out;
	}
	retval = rohc_decomp_analyze_udp_static_chain(context,skb,pkt_info);
	if(retval)
		pr_err("profile udp cid-%d analyze udp static chain faild\n",context->cid);
out:
	return retval;
}


int decomp_udp_analyze_dynamic_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	int retval = 0;
	retval = rohc_decomp_analyze_ip_dynamic_chain(context ,skb,pkt_info);
	if(retval){
		pr_err("profile udp cid-%d analyze ip dynamic chain failed\n",context->cid);
		goto out;
	}
	retval = rohc_decomp_analyze_udp_dynamic_chain(context,skb,pkt_info);
	if(retval)
		pr_err("profile udp cid-%d analyze udp dynamic chain faild\n",context->cid);
out:
	return retval;
}
int decomp_udp_analyze_packet_header(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct decomp_profile_v1_context *v1_context;
	struct decomp_ip_context *ip_context;
	struct decomp_udp_context *udp_context;
	enum rohc_packet_type packet_type; 
	int retval;
	v1_context = context->inherit_context;
	ip_context = &v1_context->ip_context;
	udp_context = v1_context->inherit_context;
	packet_type = pkt_info->packet_type;
	memset(&ip_context->update_by_packet,0,sizeof(ip_context->update_by_packet));
	memset(&udp_context->update_by_packet,0,sizeof(udp_context->update_by_packet));
	memset(&v1_context->msn_update,0,sizeof(struct wlsb_analyze_field));
	switch(packet_type){
		case ROHC_PACKET_TYPE_IR:
			retval = rohc_decomp_analyze_ir(context,skb,pkt_info);
			break;
		case ROHC_PACKET_TYPE_IR_DYN:
			retval = rohc_decomp_analyze_ir_dyn(context,skb,pkt_info);
			break;
		case ROHC_PACKET_TYPE_UO_0:
			retval = rohc_decomp_analyze_uo0(context,skb,pkt_info);
			break;
		case ROHC_PACKET_TYPE_UO_1:
			retval = rohc_decomp_analyze_uo1(context,skb,pkt_info);
			break;
		case ROHC_PACKET_TYPE_URO_2:
			retval = rohc_decomp_analyze_uro2(context,skb,pkt_info);
			break;
		default:
			pr_err("profile udp can't support to analyze the packet type:%d\n",packet_type);
			retval = -EFAULT;
			break;
	}
	return retval;
}
int decomp_udp_decode_packet_header(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct decomp_profile_v1_context *v1_context;

	int retval = 0;
	v1_context = context->inherit_context;
	retval = decomp_udp_decode_msn(context,pkt_info);
	if(retval)
		goto out;
	retval = rohc_decode_ip_packet_header(&v1_context->ip_context,pkt_info,v1_context->msn);
	if(retval){
		pr_err("profile udp cid-%d decode ip header failed\n",context->cid);
		goto out;
	}
	retval = rohc_decode_udp_header((struct decomp_udp_context *)v1_context->inherit_context,pkt_info);
out:
	return retval;
}

int decomp_udp_rebuild_packet_header(struct rohc_decomp_context *context ,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct sk_buff *decomp_skb;
	struct decomp_profile_v1_context *v1_context;
	int retval;
	decomp_skb = context->decomp_skb;
	v1_context = context->inherit_context;
	skb_reset_mac_header(decomp_skb);
	retval = rohc_rebuild_ip_header(&v1_context->ip_context,decomp_skb,pkt_info);
	if(retval){
		pr_err("profile udp cid-%d rebuild ip header failed\n",context->cid);
		goto out;
	}
	retval = rohc_rebuild_udp_header((struct decomp_udp_context *)v1_context->inherit_context,decomp_skb,pkt_info,skb);
	//decomp_udp_dump(decomp_skb,context->cid,__func__);
	//if(context->cid == 2)
	//	recover_net_header_dump(decomp_skb,context->cid,v1_context->msn);
out:
	return retval;
}
u32 decomp_udp_last_decompressed_sn(struct rohc_decomp_context *context)
{
	struct decomp_profile_v1_context *v1_context;
	struct rohc_decomp_wlsb *msn_wlsb;
	v1_context = context->inherit_context;
	msn_wlsb = v1_context->msn_wlsb;
	return rohc_decomp_lsb_pick_ref(msn_wlsb,false);
}

u8 decomp_udp_sn_bit_width(struct rohc_decomp_context *context)
{
	return 16;
}


int decomp_udp_decompress(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct rohc_decomp_profile *decomp_profile;
	struct rohc_decomp_profile_ops *prof_ops;
	int retval;
	decomp_profile = context->decomp_profile;
	prof_ops = decomp_profile->pro_ops;
	printk(KERN_DEBUG "start to decomp the packet for udp\n");
	retval = prof_ops->analyze_packet_header(context,skb,pkt_info);
	if(retval){
		pr_err("profile udp  cid-%d analyze packet header failed\n",context->cid);
		goto out;
	}
	retval = prof_ops->decode_packet_header(context,pkt_info);
	if(retval){
		pr_err("profile udp cid-%d decode packet failed\n",context->cid);
		goto out;
	}
	retval = prof_ops->rebuild_packet_header(context,skb,pkt_info);
	if(retval){
		pr_err("profile udp cid-%d rebuild packet failed\n",context->cid);
		goto out;
	}
	/*
	 *update context
	 */
	printk(KERN_DEBUG "start to updata the context udp\n");
	retval = prof_ops->update_context(context,pkt_info);
	if(retval){
		pr_err("profile udp cid-%d update context failed\n",context->cid);
	}
out:
	return retval;
}


struct decomp_profile_v1_ops decomp_udp_v1_ops = {
	.adjust_extension_type = rohc_decomp_adjust_extension_type,
	.analyze_extension = rohc_decomp_analyze_extension,
};
int decomp_udp_init_context(struct rohc_decomp_context *context)
{
	struct decomp_profile_v1_context *v1_context;
	struct decomp_udp_context *udp_context;
	int retval = 0;
	v1_context = kzalloc(sizeof(struct decomp_profile_v1_context),GFP_ATOMIC);
	if(!v1_context){
		pr_err("profile udp alloc memery for v1 context failed\n");
		retval = -ENOMEM;
		goto out;
	}
	udp_context = kzalloc(sizeof(struct decomp_udp_context),GFP_ATOMIC);
	if(!udp_context){
		pr_err("profile udp alloc memery for udp context failed\n");
		retval = -ENOMEM;
		goto err0;
	}
	retval = rohc_decomp_profile_v1_init_context(v1_context,&decomp_udp_v1_ops);
	if(retval){
		pr_err("profile udp init v1 context failed\n");
		goto err1;
	}
	v1_context->inherit_context = udp_context;
	context->inherit_context = v1_context;
	return retval;
err1:
	kfree(udp_context);
err0:
	kfree(v1_context);
out:
	return retval;
}

struct rohc_decomp_profile_ops decomp_udp_prof_ops = {
	.adjust_packet_type = rohc_decomp_adjust_packet_type,
	.analyze_packet_header = decomp_udp_analyze_packet_header,
	.analyze_profile_header = decomp_udp_analyze_profile_header,
	.analyze_static_chain = decomp_udp_analyze_static_chain,
	.analyze_dynamic_chain = decomp_udp_analyze_dynamic_chain,
	.decode_packet_header = decomp_udp_decode_packet_header,
	.rebuild_packet_header = decomp_udp_rebuild_packet_header,
	.recover_net_packet_header = decomp_udp_recover_net_header,
	.decompress = decomp_udp_decompress,
	.last_decompressed_sn = decomp_udp_last_decompressed_sn,
	.sn_bit_width = decomp_udp_sn_bit_width,
	.init_context = decomp_udp_init_context,
	.update_context = decomp_udp_update_context,
};


struct rohc_decomp_profile profile_decomp_udp = {
	.profile = ROHC_V1_PROFILE_UDP,
	.pro_ops = &decomp_udp_prof_ops,
};
