/*
 *	rohc
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	date: 2020/5/25
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
#include "../rohc_feedback.h"

#include "../rohc_bits_encode.h"
#include "../profile/rohc_v2_packet.h"
#include "../profile/rohc_v2_profile.h"

#include "rohc_decomp.h"
#include "rohc_decomp_wlsb.h"
#include "rohc_decomp_v2_common.h"

static inline int rohc_v2_wlsb_field_static_or_irreg16_analyze(u8 *from,struct wlsb_analyze_field *field ,u8 ind)
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
static inline int rohc_v2_static_or_irreg8_analyze(u8 *from,struct analyze_field *field,u8 ind)
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

bool rohc_v2_has_innermost_iph(struct decomp_iph_field_update *iph_update,struct last_decomped_iph *iph_ref)
{
	return (iph_update->has_inner_iph || iph_ref->has_inner_iph);
}

u8 rohc_v2_iph_obtain_version(struct decomp_iph_field_update *iph_update,struct last_decomped_iph *iph_ref,bool is_inner)
{
	struct iphdr *iph;
	struct iph_analyzed_fields *iph_fields;
	u8 version;
	if(is_inner){
		iph = &iph_ref->inner_iph;
		iph_fields = &iph_update->inner_iph_fields;
	}else{
		iph = &iph_ref->iph;
		iph_fields = &iph_update->iph_fields;
	}
	if(analyze_field_is_carryed(&iph_fields->ip_version))
		version = iph_fields->ip_version.value;
	else
		version = iph->version;
	return version;
}

enum ip_id_behavior rohc_v2_ipv4_obtain_ipid_behavior(struct decomp_iph_field_update *iph_update,struct last_decomped_iph *iph_ref,bool is_inner)
{
	enum ip_id_behavior ipid_bh;

	if(is_inner){
		if(analyze_field_is_carryed(&iph_update->innermost_ipid_bh))
			ipid_bh = iph_update->innermost_ipid_bh.value;
		else
			ipid_bh = iph_ref->inner_ipid_bh;
	}else{
		if(analyze_field_is_carryed(&iph_update->outer_ipid_bh))
			ipid_bh = iph_update->outer_ipid_bh.value;
		else
			ipid_bh = iph_ref->ipid_bh;
	}
	return ipid_bh;
}


bool decomp_innermost_ipid_is_seq(struct rohc_v2_decomp_iph_context *iph_context)
{
	struct decomp_iph_field_update *iph_update;
	struct last_decomped_iph *iph_ref;

	bool retval = false;
	iph_update = &iph_context->update_by_packet;
	iph_ref = &iph_context->iph_ref;

	if(rohc_v2_has_innermost_iph(iph_update,iph_ref)){
		if(rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,true)) && \
		   !ip_id_is_random_or_zero(rohc_v2_ipv4_obtain_ipid_behavior(iph_update,iph_ref,true)))
			retval = true;
	}else{
		if(rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,false)) && \
		   !ip_id_is_random_or_zero(rohc_v2_ipv4_obtain_ipid_behavior(iph_update,iph_ref,false)))
			retval = true;
	}
	return retval;
}

void fill_innermost_iph_dynamic_fields(struct decomp_iph_field_update *iph_update,struct last_decomped_iph *iph_ref,int field,u32 value)
{
	struct iph_dynamic_fields *dynamic_fields;
	if(rohc_v2_has_innermost_iph(iph_update,iph_ref)){
		if(rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,true)))
			dynamic_fields = &iph_update->inner_iph_fields.ipv4_fields.dynamic_fields;
		else
			dynamic_fields = &iph_update->iph_fields.ipv6_fields.dynamic_fields;
	}else{
		if(rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,false)))
			dynamic_fields = &iph_update->iph_fields.ipv4_fields.dynamic_fields;
		else
			dynamic_fields = &iph_update->iph_fields.ipv6_fields.dynamic_fields;
	}
	switch(field){
		case IPH_FIELD_TOS_TC:
			decomp_fill_analyze_field(&dynamic_fields->tos_tc,value);
			break;
		case IPH_FIELD_TTL_HL:
			decomp_fill_analyze_field(&dynamic_fields->ttl_hl,value);
			break;
		case IPH_FIELD_DF:
			decomp_fill_analyze_field(&dynamic_fields->df,value);
			break;
		case IPH_FIELD_IPID_BH:
			decomp_fill_analyze_field(&dynamic_fields->ipid_bh,value);
			break;
	}
}
int rohc_v2_profile_234_flags_analyze(u8 *from,struct decomp_iph_field_update *iph_update,struct last_decomped_iph *iph_ref,u8 ind)
{

	if(!ind)
		return 0;
	if(rohc_v2_has_innermost_iph(iph_update,iph_ref)){
		if(!!BYTE_BIT_7(*from))
			iph_update->iph_fields.outer_ind = true;
	}
	fill_innermost_iph_dynamic_fields(iph_update,iph_ref,IPH_FIELD_DF,!!BYTE_BIT_6(*from));
	fill_innermost_iph_dynamic_fields(iph_update,iph_ref,IPH_FIELD_IPID_BH,BYTE_BITS_2(*from,4));
	return 1;
}
struct wlsb_analyze_field *pick_innermost_ipid_field(struct decomp_iph_field_update *iph_update,struct last_decomped_iph *iph_ref)
{
	struct wlsb_analyze_field *ipid;
	if(rohc_v2_has_innermost_iph(iph_update,iph_ref)){
		if(rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,true)) &&\
		   !ip_id_is_random_or_zero(rohc_v2_ipv4_obtain_ipid_behavior(iph_update,iph_ref,true)))
			ipid = &iph_update->innermost_ipid;
		else
			ipid = NULL;
	}else{
		if(rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,false)) &&\
		   !ip_id_is_random_or_zero(rohc_v2_ipv4_obtain_ipid_behavior(iph_update,iph_ref,false)))
			ipid = &iph_update->outer_ipid;
		else
			ipid = NULL;
	}
	return ipid;
}


int rohc_v2_decomp_analyze_generic_co_common(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct rohc_v2_decomp_iph_context *iph_context;
	struct decomp_iph_field_update *iph_update;
	struct last_decomped_iph *iph_ref;
	struct co_common_generic *co_common;
	struct wlsb_analyze_field *ipid;
	struct rohc_crc_info *crc_info;
	enum rohc_cid_type cid_type;

	bool	analyze_full;

	u16 ipid_off;
	int call_len;
	int analyze_len = 0;
	int retval = 0;

	crc_info = &pkt_info->header_crc;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	iph_context = &co_context->iph_context;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		co_common = (struct co_common_generic *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			co_common = (struct co_common_generic *)analyze_data;
		else
			co_common = (struct co_common_generic *)(analyze_data - 1);
		analyze_full = false;
	}

	if(analyze_first){
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	if(context->decomp_profile->pro_ops->crc_cal){
		crc_info->crc_type = CRC_TYPE_7;
		crc_info->crc_value = co_common->crc;
		crc_info->verify_type = CRC_VERIFY_NET_HEADER;
	}
	iph_update = &iph_context->update_by_packet;
	iph_ref = &iph_context->iph_ref;
	decomp_fill_analyze_field(&co_context->co_update.reorder_ratio,co_common->reorder_ratio);
	/*crc3 cal,not support now*/

	analyze_len += sizeof(struct co_common_generic) - 1;
	analyze_data += analyze_len;

	/*next fields are varibale length fields*/

	call_len = rohc_v2_profile_234_flags_analyze(analyze_data,iph_update,iph_ref,co_common->flag);
	analyze_data += call_len;
	analyze_len += call_len;

	/*tos_tc */
	if(co_common->tos_tc_ind){
		fill_innermost_iph_dynamic_fields(iph_update,iph_ref,IPH_FIELD_TOS_TC,*analyze_data);
		analyze_data++;
		analyze_len++;
	}
	if(co_common->ttl_hl_ind){
		fill_innermost_iph_dynamic_fields(iph_update,iph_ref,IPH_FIELD_TTL_HL,*analyze_data);
		analyze_data++;
		analyze_len++;
	}
	/*msn*/
	decomp_wlsb_fill_analyze_field(&co_context->co_update.msn,*analyze_data,8,true);
	analyze_data++;
	analyze_len++;
	/*innsermost ipid*/
	ipid = pick_innermost_ipid_field(iph_update,iph_ref);
	if(ipid){
		if(co_common->ipid_ind){
			/*keep network byte order*/
			memcpy(&ipid_off,analyze_data,2);
			decomp_wlsb_fill_analyze_field(ipid,ipid_off,16,false);
			analyze_data += 2;
			analyze_len += 2;
		}else{
			ipid_off = *analyze_data;
			decomp_wlsb_fill_analyze_field(ipid,ipid_off,8,true);
			analyze_len++;
			analyze_data++;
		}
	}
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int rohc_v2_decomp_analyze_pt_0_crc3(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct pt_0_crc3 *pt_0_crc;
	struct rohc_crc_info  *header_crc;
	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	header_crc = &pkt_info->header_crc;

	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		pt_0_crc = (struct pt_0_crc3 *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			pt_0_crc = (struct pt_0_crc3 *)analyze_data;
		else
			pt_0_crc = (struct pt_0_crc3 *)(analyze_data - 1);
	}
	if(analyze_first){
		decomp_wlsb_fill_analyze_field(&co_context->co_update.msn,pt_0_crc->msn,4,true);
		if(context->capability & ROHC_DECOMP_CAP_CRC_VERIFY){
			header_crc->crc_type = CRC_TYPE_3;
			header_crc->crc_value = pt_0_crc->crc;
			header_crc->verify_type = CRC_VERIFY_NET_HEADER;
		}
		analyze_len = 1;
	}else
		goto out;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int rohc_v2_decomp_analyze_pt_0_crc7(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct pt_0_crc7 *pt_0_crc;

	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		pt_0_crc = (struct pt_0_crc7 *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			pt_0_crc = (struct pt_0_crc7 *)analyze_data;
		else
			pt_0_crc = (struct pt_0_crc7 *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		decomp_wlsb_fill_analyze_field(&co_context->co_update.msn,pt_0_crc->msn0,5,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_analyze_field_append_bits(&co_context->co_update.msn,pt_0_crc->msn1,1,true);
	/*crc7 not support now*/
	analyze_len += sizeof(struct pt_0_crc7) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int rohc_v2_decomp_analyze_pt_1_seq_id(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_iph_field_update *iph_update;
	struct last_decomped_iph *iph_ref;
	struct wlsb_analyze_field *ipid;
	struct pt_1_seq_id *seq_id;
	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		seq_id = (struct pt_1_seq_id *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			seq_id = (struct pt_1_seq_id *)analyze_data;
		else
			seq_id = (struct pt_1_seq_id *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		decomp_wlsb_fill_analyze_field(&co_context->co_update.msn,seq_id->msn0,2,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_analyze_field_append_bits(&co_context->co_update.msn,seq_id->msn1,4,true);
	iph_update = &co_context->iph_context.update_by_packet;
	iph_ref = &co_context->iph_context.iph_ref;
	ipid = pick_innermost_ipid_field(iph_update,iph_ref);
	if(ipid)
		decomp_wlsb_fill_analyze_field(ipid,seq_id->ipid_off,4,true);
	else
		rohc_pr(ROHC_DV2,"ip id bh is :%d\n",rohc_v2_ipv4_obtain_ipid_behavior(iph_update,iph_ref,false));
	analyze_len += sizeof(struct pt_1_seq_id) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;

}

int rohc_v2_decomp_analyze_pt_2_seq_id(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_iph_field_update *iph_update;
	struct last_decomped_iph *iph_ref;
	struct wlsb_analyze_field *ipid;
	struct pt_2_seq_id *seq_id;

	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	iph_update = &co_context->iph_context.update_by_packet;
	iph_ref = &co_context->iph_context.iph_ref;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		seq_id = (struct pt_2_seq_id *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			seq_id = (struct pt_2_seq_id *)analyze_data;
		else
			seq_id = (struct pt_2_seq_id *)(analyze_data - 1);
		analyze_full = false;
	}
	ipid = pick_innermost_ipid_field(iph_update,iph_ref);
	BUG_ON(!ipid);
	if(analyze_first){
		decomp_wlsb_fill_analyze_field(ipid,seq_id->ipid_off0,5,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_analyze_field_append_bits(ipid,seq_id->ipid_off1,1,true);
	/*crc7 not support now*/
	decomp_wlsb_fill_analyze_field(&co_context->co_update.msn,seq_id->msn,8,true);
	analyze_len += sizeof(struct pt_2_seq_id) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}
static inline int rohc_v2_iph_analyze_static_field(u8 *from,struct iph_analyzed_fields *iph_fields,u8 *next_pro)
{
	struct ipv4h_static_fields *static_fields;
	struct profile_ipv4_static *ipv4_static;
	int analyze_len = 0;
	ipv4_static = (struct profile_ipv4_static *)from;
	if(!ipv4_static->version){
		decomp_fill_analyze_field(&iph_fields->ip_version,4);
		static_fields = &iph_fields->ipv4_fields.static_fields;
		static_fields->version = 4;
		static_fields->protocol = ipv4_static->protocol;
		static_fields->saddr = ipv4_static->saddr;
		static_fields->daddr = ipv4_static->daddr;
		static_fields->update = true;
		*next_pro = ipv4_static->protocol;
		analyze_len = sizeof(struct profile_ipv4_static);
	}else{
		//ipv6
	}
	return analyze_len;
}
int rohc_v2_decomp_analyze_ip_static_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_iph_field_update *iph_update;
	struct last_decomped_iph *iph_ref;
	u8 next_pro;
	int call_len = 0;
	int analyze_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;

	iph_update = &co_context->iph_context.update_by_packet;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	call_len = rohc_v2_iph_analyze_static_field(analyze_data,&iph_update->iph_fields,&next_pro);
	analyze_data += call_len;
	analyze_len += call_len;
	if(next_pro == IPPROTO_IPIP || next_pro == IPPROTO_IPV6){
		iph_update->has_inner_iph = true;
		call_len = rohc_v2_iph_analyze_static_field(analyze_data,&iph_update->inner_iph_fields,&next_pro);
		analyze_len += call_len;
		if(next_pro == IPPROTO_IPIP || next_pro == IPPROTO_IPV6){
			pr_err("profile-%x has too many ip header when analyze ip static chain\n",context->decomp_profile->profile);
			retval = -EPERM;
			goto out;
		}
	}
	pkt_info->decomped_hdr_len += analyze_len;
out:
	return retval;
}

static inline int rohc_v2_iph_analyze_dynamic_field(u8 *from,struct iph_analyzed_fields *iph_fields,bool is_ipv4)
{
	struct iph_dynamic_fields *dynamic_fields;
	u16 ipid;
	int analyze_len = 0;
	struct profile_ipv4_dynamic *ipv4_dynamic;
	if(is_ipv4){
		ipv4_dynamic = (struct profile_ipv4_dynamic *)from;
		dynamic_fields = &iph_fields->ipv4_fields.dynamic_fields;
		decomp_fill_analyze_field(&dynamic_fields->tos_tc,ipv4_dynamic->tos);
		decomp_fill_analyze_field(&dynamic_fields->ttl_hl,ipv4_dynamic->ttl);
		decomp_fill_analyze_field(&dynamic_fields->df,ipv4_dynamic->df);
		decomp_fill_analyze_field(&dynamic_fields->ipid_bh,ipv4_dynamic->ipid_bh);
		analyze_len = sizeof(struct profile_ipv4_dynamic);
		if(!ip_id_is_zero(ipv4_dynamic->ipid_bh)){
			from += analyze_len;
			/*keep network byte order*/
			memcpy(&ipid,from,2);
			decomp_wlsb_fill_analyze_field(&dynamic_fields->ipid,ipid,16,false);
			analyze_len += 2;
		}
	}else{
		//ipv6
	}
	return analyze_len;
}
int rohc_v2_decomp_analyze_ip_dynamic_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct rohc_v2_decomp_iph_context *iph_context;
	struct decomp_iph_field_update *iph_update;
	struct last_decomped_iph *iph_ref;
	struct iph_analyzed_fields *iph_fields;

	int call_len;
	int analyze_len = 0;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	iph_context = &co_context->iph_context;
	iph_update = &iph_context->update_by_packet;
	iph_ref = &iph_context->iph_ref;
	iph_fields = &iph_update->iph_fields;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	call_len = rohc_v2_iph_analyze_dynamic_field(analyze_data,iph_fields,rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,false)));
	analyze_data += call_len;
	analyze_len += call_len;
	if(rohc_v2_has_innermost_iph(iph_update,iph_ref)){
		iph_fields = &iph_update->inner_iph_fields;
		call_len = rohc_v2_iph_analyze_dynamic_field(analyze_data,iph_fields,rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,true)));
		analyze_len += call_len;
	}
	pkt_info->decomped_hdr_len += analyze_len;
	return 0;
}

int rohc_v2_decomp_analyze_ip_irr_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct rohc_v2_decomp_iph_context *iph_context;

	struct iph_dynamic_fields *dynamic_fields;
	struct decomp_iph_field_update *iph_update;
	struct last_decomped_iph *iph_ref;

	u16 ipid;
	int analyze_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	iph_context = &co_context->iph_context;

	iph_update = &co_context->iph_context.update_by_packet;
	iph_ref = &co_context->iph_context.iph_ref;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,false)))
		dynamic_fields = &iph_update->iph_fields.ipv4_fields.dynamic_fields;
	else
		dynamic_fields = &iph_update->iph_fields.ipv6_fields.dynamic_fields;
	if(rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,false)) && \
           ip_id_is_random(rohc_v2_ipv4_obtain_ipid_behavior(iph_update,iph_ref,false))){
		/*keep network byte order*/
		memcpy(&ipid,analyze_data,2);
		decomp_wlsb_fill_analyze_field(&iph_update->outer_ipid,ipid,16,false);
		analyze_len += 2;
		analyze_data += 2;
	}
	/*outer header tos_tc and ttl_hl*/
	if(rohc_v2_has_innermost_iph(iph_update,iph_ref) && iph_update->iph_fields.outer_ind){
		decomp_fill_analyze_field(&dynamic_fields->tos_tc,*analyze_data);
		analyze_data++;
		analyze_len++;
		decomp_fill_analyze_field(&dynamic_fields->ttl_hl,*analyze_data);
		analyze_data++;
		analyze_len++;
	}
	/*innermost ipv4 header ipid*/
	if(rohc_v2_has_innermost_iph(iph_update,iph_ref)){
		if(ip_id_is_random(rohc_v2_ipv4_obtain_ipid_behavior(iph_update,iph_ref,true)) &&\
		   rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,true))){
			/*keep network byte order*/
			memcpy(&ipid,analyze_data,2);
			decomp_wlsb_fill_analyze_field(&iph_update->innermost_ipid,ipid,16,false);
			analyze_len += 2;
		}
	}
	pkt_info->decomped_hdr_len += analyze_len;
	return 0;

}

static inline int rohc_v2_decode_ipv4_header(struct ipv4h_analyzed_fields *ipv4_fields,struct iphdr *decode_iph,struct iphdr *iph_ref,enum ip_id_behavior ipid_bh,struct rohc_decomp_wlsb *ipid_wlsb,u32 msn)
{
	struct ipv4h_static_fields *static_fields;
	struct iph_dynamic_fields *dynamic_fields;
	struct wlsb_analyze_field *ipid;
	u32 ipid_off_decode;
	u16 new_ipid;
	u16 frag_off;
	int retval = 0;

	static_fields = &ipv4_fields->static_fields;
	dynamic_fields = &ipv4_fields->dynamic_fields;


	/*decode static fields*/
	if(static_fields->update){
		decode_iph->version = static_fields->version;
		decode_iph->protocol = static_fields->protocol;
		decode_iph->saddr = static_fields->saddr;
		decode_iph->daddr = static_fields->daddr;
	}else{
		decode_iph->version = iph_ref->version;
		decode_iph->protocol = iph_ref->protocol;
		decode_iph->saddr = iph_ref->saddr;
		decode_iph->daddr = iph_ref->daddr;
	}

	/*decode dynamic fields
	 */

	if(analyze_field_is_carryed(&dynamic_fields->df)){
		if(dynamic_fields->df.value)
			frag_off = IP_DF;
		else
			frag_off = 0;
		decode_iph->frag_off = htons(frag_off);
	}else
		decode_iph->frag_off = iph_ref->frag_off;

	if(analyze_field_is_carryed(&dynamic_fields->tos_tc))
		decode_iph->tos = dynamic_fields->tos_tc.value & 0xff;
	else
		decode_iph->tos = iph_ref->tos;

	if(analyze_field_is_carryed(&dynamic_fields->ttl_hl))
		decode_iph->ttl = dynamic_fields->ttl_hl.value & 0xff;
	else
		decode_iph->ttl = iph_ref->ttl;

	/*decode ip id*/
	ipid = &dynamic_fields->ipid;
	if(ip_id_is_zero(ipid_bh))
		decode_iph->id = 0;
	else if(ip_id_is_random(ipid_bh)){
		if(!decomp_wlsb_analyze_field_is_carryed(ipid) || ipid->is_comp){
			rohc_pr(ROHC_DV2,"decode ip id failed when ipid is random,carryed=%d,is_comp=%d\n",ipid->flags,ipid->is_comp);
			retval = -EFAULT;
			goto out;
		}else
			decode_iph->id = ipid->encode_v & 0xffff;
	}else{
		if(decomp_wlsb_analyze_field_is_carryed(ipid) && !ipid->is_comp)
			decode_iph->id = ipid->encode_v & 0xffff;
		else{
			if(!decomp_wlsb_analyze_field_is_carryed(ipid)){
				ipid_off_decode = rohc_decomp_lsb_pick_ref(ipid_wlsb,false);
			}else{
				if(rohc_decomp_lsb_decode(ipid_wlsb,ipid->encode_bits,ROHC_LSB_V2_IPID_P(ipid->encode_bits),ipid->encode_v,&ipid_off_decode,false)){
					rohc_pr(ROHC_DV2,"%s :decode ip id offset failed,msn:%d\n",__func__,msn);
				}
			}
			new_ipid = (ipid_off_decode + msn) & 0xffff;
			if(!ip_id_is_nbo(ipid_bh))
				new_ipid = __swab16(new_ipid);
			decode_iph->id = htons(new_ipid);
		}
	}

out:
	return retval;
}
int rohc_v2_decode_common_msn(struct rohc_v2_decomp_common_context *co_context)
{
	struct wlsb_analyze_field *msn;
	struct rohc_decomp_wlsb *msn_wlsb;
	u32 decode_msn;
	msn = &co_context->co_update.msn;
	msn_wlsb = co_context->msn_wlsb;
	if(!decomp_wlsb_analyze_field_is_carryed(msn)){
		rohc_pr(ROHC_DV2,"msn should be carryed every packet\n");
		return -EFAULT;
	}
	if(!msn->is_comp)
		decode_msn = msn->encode_v;
	else if(rohc_decomp_lsb_decode(msn_wlsb,msn->encode_bits,rohc_v2_msn_k_to_p_under_rr(REORDER_R_NONE,msn->encode_bits),msn->encode_v,&decode_msn,false)){
		rohc_pr(ROHC_DV2,"rohc v2 decode msn failed\n");
		return -EFAULT;
	}
	co_context->co_decode.new_msn = decode_msn;
	return 0;
}
int rohc_v2_decode_ip_header(struct rohc_v2_decomp_iph_context *iph_context,struct rohc_decomp_pkt_hdr_info *pkt_info,u32 msn)
{
	struct iphdr *new_iph,*old_iph;
	struct decomp_iph_field_update *iph_update;
	struct last_decomped_iph *iph_ref;
	struct iph_analyzed_fields *iph_fields;

	int retval;
	iph_update = &iph_context->update_by_packet;
	iph_ref = &iph_context->iph_ref;
	iph_fields = &iph_update->iph_fields;

	if(rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,false))){
		new_iph = &iph_update->decoded_iphs.iph;
		old_iph = &iph_ref->iph;
		retval = rohc_v2_decode_ipv4_header(&iph_fields->ipv4_fields,new_iph,old_iph,rohc_v2_ipv4_obtain_ipid_behavior(iph_update,iph_ref,false),iph_context->outer_ipidoff_wlsb,msn);
		if(retval)
			goto out;
	}else{
		//ipv6
	}
	if(rohc_v2_has_innermost_iph(iph_update,iph_ref)){
		iph_fields = &iph_update->inner_iph_fields;
		if(rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,true))){
			new_iph = &iph_update->decoded_iphs.inner_iph;
			old_iph = &iph_ref->inner_iph;
			retval = rohc_v2_decode_ipv4_header(&iph_fields->ipv4_fields,new_iph,old_iph,rohc_v2_ipv4_obtain_ipid_behavior(iph_update,iph_ref,true),iph_context->innermost_ipidoff_wlsb,msn);
		}else{
			//ipv6
		}
	}
out:
	return retval;
}

static inline void rohc_v2_rebuild_ipv4_header(struct iphdr *decode_iph,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool is_inner)
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
static inline void rohc_v2_rebuild_ipv6_header(struct ipv6hdr *decode_ipv6h,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{

}
int rohc_v2_rebuild_ip_header(struct rohc_v2_decomp_iph_context *iph_context,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct iphdr *decode_iph;
	struct ipv6hdr *decode_ipv6h;
	struct decomp_iph_field_update *iph_update;
	struct last_decomped_iph *iph_ref;

	iph_update = &iph_context->update_by_packet;
	iph_ref = &iph_context->iph_ref;
	if(rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,false))){
		decode_iph = &iph_update->decoded_iphs.iph;
		rohc_v2_rebuild_ipv4_header(decode_iph,decomp_skb,pkt_info,false);
	}else{
		//TODO .ipv6
	}

	if(rohc_v2_has_innermost_iph(iph_update,iph_ref)){
		if(rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,true))){
			decode_iph = &iph_update->decoded_iphs.inner_iph;
			rohc_v2_rebuild_ipv4_header(decode_iph,decomp_skb,pkt_info,true);
		}else{
			//TODO.ipv6
		}
	}
	return 0;
}

void rohc_v2_ip_context_update(struct rohc_v2_decomp_iph_context *iph_context,u32 msn)
{
	struct iphdr *new_iph,*to_iph;
	struct last_decomped_iph *iph_ref;
	struct decomp_iph_field_update *iph_update;
	struct iph_decoded *decoded_iphs;

	u16 ipid_off;

	iph_update = &iph_context->update_by_packet;
	iph_ref = &iph_context->iph_ref;
	decoded_iphs = &iph_update->decoded_iphs;
	if(iph_update->has_inner_iph)
		iph_ref->has_inner_iph = true;

	if(analyze_field_is_carryed(&iph_update->outer_ipid_bh))
		iph_ref->ipid_bh = (enum ip_id_behavior)iph_update->outer_ipid_bh.value;

	new_iph =  &decoded_iphs->iph;
	if(rohc_iph_is_v4(new_iph->version)){
		to_iph = &iph_ref->iph;
		memcpy(to_iph,new_iph,sizeof(struct iphdr));
		if(!ip_id_is_nbo(iph_ref->ipid_bh))
			ipid_off = __swab16(ntohs(new_iph->id)) - msn;
		else
			ipid_off = ntohs(new_iph->id) - msn;
		rohc_decomp_lsb_setup_ref(iph_context->outer_ipidoff_wlsb,ipid_off);
	}else{
		//ipv6
	}

	if(iph_ref->has_inner_iph){
		if(analyze_field_is_carryed(&iph_update->innermost_ipid_bh))
			iph_ref->inner_ipid_bh = (enum ip_id_behavior)iph_update->innermost_ipid_bh.value;
		new_iph = &decoded_iphs->inner_iph;
		if(rohc_iph_is_v4(new_iph->version)){
			to_iph = &iph_ref->inner_iph;
			memcpy(to_iph,new_iph,sizeof(struct iphdr));
			if(!ip_id_is_nbo(iph_ref->inner_ipid_bh))
				ipid_off = __swab16(ntohs(new_iph->id)) - msn;
			else
				ipid_off = ntohs(new_iph->id) - msn;
			rohc_decomp_lsb_setup_ref(iph_context->innermost_ipidoff_wlsb,ipid_off);
		}else{
			//ipv6
		}
	}
}

int rohc_v2_ip_init_context(struct rohc_v2_decomp_iph_context *iph_context)
{
	int i;
	int retval = 0;
	struct rohc_decomp_wlsb *wlsb;
	for(i = 0; i < ROHC_V2_MAX_IP_HDR;i++){
		wlsb = rohc_decomp_lsb_alloc(TYPE_USHORT,GFP_ATOMIC);
		if(IS_ERR(wlsb)){
			if( i > 0){
				rohc_decomp_lsb_free(iph_context->ip_id_wlsb[i - 1]);
				retval = -ENOMEM;
				goto err;
			}
		}
		iph_context->ip_id_wlsb[i] = wlsb;
	}
	return 0;
err:
	return retval;
}

void rohc_v2_ip_destroy_context(struct rohc_v2_decomp_iph_context *iph_context)
{
	int i;
	for(i = 0;i < ROHC_V2_MAX_IP_HDR;i++){
		rohc_decomp_lsb_free(iph_context->ip_id_wlsb[i]);
	}
}
