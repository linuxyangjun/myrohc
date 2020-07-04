/*
 *	rohc
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	date: 2020/6/16
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

#include "rohc_decomp_packet.h"


int decomp_ip_v2_analyze_static_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	int retval;
	retval = rohc_v2_decomp_analyze_ip_static_chain(context,skb,pkt_info);
	return retval;
}

static inline int ipendpoint_analyze_iph_dynamic_field(u8 *from,struct iph_analyzed_fields *iph_fields,struct wlsb_analyze_field  *msn,struct analyze_field *rr,bool is_ipv4,bool is_inner)
{
	struct iph_dynamic_fields *dynamic_fields;
	u16 ipid,msn_v;
	int analyze_len = 0;
	struct profile_ipv4_dynamic *ipv4_dynamic;
	struct profile_ipv4_endpoint_innermost_dynamic *ipv4_endpoint_dynamic;
	if(is_ipv4){
		dynamic_fields = &iph_fields->ipv4_fields.dynamic_fields;
		if(is_inner){
			ipv4_endpoint_dynamic = (struct profile_ipv4_endpoint_innermost_dynamic *)from;
			decomp_fill_analyze_field(&dynamic_fields->tos_tc,ipv4_endpoint_dynamic->tos);
			decomp_fill_analyze_field(&dynamic_fields->ttl_hl,ipv4_endpoint_dynamic->ttl);
			decomp_fill_analyze_field(&dynamic_fields->df,ipv4_endpoint_dynamic->df);
			decomp_fill_analyze_field(&dynamic_fields->ipid_bh,ipv4_endpoint_dynamic->ipid_bh);
			analyze_len += sizeof(struct profile_ipv4_endpoint_innermost_dynamic);
			from += analyze_len;
			if(!ip_id_is_zero(ipv4_endpoint_dynamic->ipid_bh)){
				/*keep network byte order*/
				memcpy(&ipid,from,2);
				decomp_wlsb_fill_analyze_field(&dynamic_fields->ipid,ipid,16,false);
				analyze_len += 2;
				from += 2;
			}
			memcpy(&msn_v,from,2);
			msn_v = ntohs(msn_v);
			analyze_len += 2;
			decomp_wlsb_fill_analyze_field(msn,msn_v,16,false);
		}else{
			ipv4_dynamic = (struct profile_ipv4_dynamic *)from;
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
		}
	}else{
		//ipv6
	}
	return analyze_len;
}
int decomp_ip_v2_analyze_dynamic_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct rohc_v2_decomp_iph_context *iph_context;
	struct decomp_iph_field_update *iph_update;
	struct last_decomped_iph *iph_ref;
	struct iph_analyzed_fields *iph_fields;
	struct wlsb_analyze_field *msn;
	struct analyze_field *rr;
	int call_len;
	int analyze_len = 0;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	iph_context = &co_context->iph_context;
	iph_update = &iph_context->update_by_packet;
	iph_ref = &iph_context->iph_ref;
	iph_fields = &iph_update->iph_fields;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	msn = &co_context->co_update.msn;
	rr = &co_context->co_update.reorder_ratio;
	if(!rohc_v2_has_innermost_iph(iph_update,iph_ref))
		call_len = ipendpoint_analyze_iph_dynamic_field(analyze_data,iph_fields,msn,rr,rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,false)),true);
	else
		call_len = ipendpoint_analyze_iph_dynamic_field(analyze_data,iph_fields,msn,rr,rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,false)),false);

	analyze_data += call_len;
	analyze_len += call_len;
	if(rohc_v2_has_innermost_iph(iph_update,iph_ref)){
		iph_fields = &iph_update->inner_iph_fields;
		call_len = ipendpoint_analyze_iph_dynamic_field(analyze_data,iph_fields,msn,rr,rohc_iph_is_v4(rohc_v2_iph_obtain_version(iph_update,iph_ref,true)),true);
		analyze_len += call_len;
	}
	pkt_info->decomped_hdr_len += analyze_len;
	return 0; 
}


int decomp_ip_v2_analyze_irr_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	int retval;
	retval = rohc_v2_decomp_analyze_ip_irr_chain(context,skb,pkt_info);
	return retval;
}

int decomp_ip_v2_analyze_co_header(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct sk_buff *decomp_skb;

	int (*analyze_co_func)(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first);
	enum rohc_packet_type packet_type;

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
			analyze_co_func = rohc_v2_decomp_analyze_generic_co_common;
			break;
		case ROHC_PACKET_TYPE_PT_0_CRC3:
			analyze_co_func = rohc_v2_decomp_analyze_pt_0_crc3;
			break;
		case ROHC_PACKET_TYPE_PT_0_CRC7:
			analyze_co_func = rohc_v2_decomp_analyze_pt_0_crc7;
			break;
		case ROHC_PACKET_TYPE_PT_1_SEQ_ID:
			analyze_co_func = rohc_v2_decomp_analyze_pt_1_seq_id;
			break;
		case ROHC_PACKET_TYPE_PT_2_SEQ_ID:
			analyze_co_func = rohc_v2_decomp_analyze_pt_2_seq_id;
			break;
		default:
			rohc_pr(ROHC_DIP2,"profile-v2 IP not support the packet_type : %d\n",packet_type);
			retval = -EFAULT;
			goto out;
	}
	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		pkt_info->decomped_hdr_len += pkt_info->cid_len;
		retval = analyze_co_func(context,skb,pkt_info,true);
	}else{
		retval = analyze_co_func(context,skb,pkt_info,true);
		pkt_info->decomped_hdr_len += pkt_info->cid_len;
		retval = analyze_co_func(context,skb,pkt_info,false);
	}
	retval = decomp_ip_v2_analyze_irr_chain(context,skb,pkt_info);
out:
	return retval;
}

int decomp_ip_v2_decode_packet_header(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct rohc_v2_decomp_common_context *co_context;
	struct rohc_v2_decomp_iph_context *iph_context;

	int retval;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	iph_context = &co_context->iph_context;

	retval = rohc_v2_decode_common_msn(co_context);
	if(retval)
		goto out;
	retval = rohc_v2_decode_ip_header(iph_context,pkt_info,co_context->co_decode.new_msn);

out:
	return retval;
}


enum rohc_packet_type decomp_ip_v2_adjust_packet_type(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	enum rohc_packet_type packet_type;

	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL)
		analyze_data = skb->data + pkt_info->decomped_hdr_len + pkt_info->cid_len;
	else
		analyze_data = skb->data + pkt_info->decomped_hdr_len;
	if(rohc_packet_is_co_repair(analyze_data))
		packet_type = ROHC_PACKET_TYPE_CO_REPAIR;
	else if(rohc_packet_is_generic_co_common(analyze_data))
		packet_type = ROHC_PACKET_TYPE_CO_COMMON;
	else if(rohc_packet_is_pt_0_crc3(analyze_data))
		packet_type = ROHC_PACKET_TYPE_PT_0_CRC3;
	else if(rohc_packet_is_pt_0_crc7(analyze_data))
		packet_type = ROHC_PACKET_TYPE_PT_0_CRC7;
	else if(rohc_packet_is_pt_1_seq_id(analyze_data))
		packet_type = ROHC_PACKET_TYPE_PT_1_SEQ_ID;
	else if(rohc_packet_is_pt_2_seq_id(analyze_data))
		packet_type = ROHC_PACKET_TYPE_PT_2_SEQ_ID;
	else{
		rohc_pr(ROHC_DIP2,"profile IP can't support the packet type,%x\n",*analyze_data);
		packet_type = ROHC_PACKET_TYPE_UNDECIDE;
	}
	rohc_pr(ROHC_DIP2,"IP analyze packet type:%d\n",packet_type);
	return packet_type;
}


int decomp_ip_v2_init_context(struct rohc_decomp_context *context)
{
	struct rohc_v2_decomp_common_context *co_context;

	int retval;
	co_context = kzalloc(sizeof(struct rohc_v2_decomp_common_context),GFP_ATOMIC);
	if(!co_context){
		pr_err("alloc memery for decomp IP v2 common context failed\n");
		retval = -ENOMEM;
		goto out;
	}

	co_context->msn_wlsb = rohc_decomp_lsb_alloc(TYPE_USHORT,GFP_ATOMIC);
	if(IS_ERR(co_context->msn_wlsb)){
		pr_err("alloc msn wlsb for IP profile-v2 failed\n");
		retval = -ENOMEM;
		goto err0;
	}
	retval = rohc_v2_ip_init_context(&co_context->iph_context);
	if(retval)
		goto err1;
	context->inherit_context = co_context;

	return 0;
err1:
	rohc_decomp_lsb_free(co_context->msn_wlsb);

err0:
	kfree(co_context);
out:
	return retval;
}


int decomp_ip_v2_update_context(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct rohc_v2_decomp_common_context *co_context;
	struct rohc_v2_decomp_iph_context *iph_context;

	u32 msn;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	iph_context = &co_context->iph_context;

	msn = co_context->co_decode.new_msn;

	rohc_v2_ip_context_update(iph_context,msn);

	rohc_decomp_lsb_setup_ref(co_context->msn_wlsb,msn);
	return 0;
}

u8 decomp_ip_v2_sn_bit_width(struct rohc_decomp_context *context)
{
	return 16;
}

u32 decomp_ip_v2_last_decompressed_sn(struct rohc_decomp_context *context)
{
	struct rohc_v2_decomp_common_context *co_context;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	return rohc_decomp_lsb_pick_ref(co_context->msn_wlsb,false);
}

int decomp_ip_v2_rebuild_packet_header(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct sk_buff *decomp_skb;
	struct rohc_v2_decomp_common_context *co_context;

	struct rohc_v2_decomp_iph_context *iph_context;

	decomp_skb = context->decomp_skb;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;

	iph_context = &co_context->iph_context;
	/*fist rebuild ip header*/
	rohc_v2_rebuild_ip_header(iph_context,decomp_skb,pkt_info);

	return 0;
}


int decomp_ip_v2_analyze_packet_header(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	enum rohc_packet_type packet_type;
	int retval;
	packet_type = pkt_info->packet_type;
	switch(packet_type){
		case ROHC_PACKET_TYPE_IR:
			retval = rohc_decomp_analyze_ir(context,skb,pkt_info);
			break;
		case ROHC_PACKET_TYPE_IR_DYN:
			retval = rohc_decomp_analyze_ir_dyn(context,skb,pkt_info);
			break;
		case ROHC_PACKET_TYPE_CO_REPAIR:
			retval = rohc_decomp_analyze_co_repair(context,skb,pkt_info);
			break;
		default:
			retval = decomp_ip_v2_analyze_co_header(context,skb,pkt_info);
			break;
	}
	return retval;
}


int decomp_ip_v2_recover_net_packet_header(struct rohc_decomp_context *context,struct sk_buff *skb ,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct iphdr *iph;
	struct rohc_v2_decomp_common_context *co_context;

	struct rohc_v2_decomp_iph_context *iph_context;
	struct last_decomped_iph *iph_ref;
	struct sk_buff *decomp_skb;
	struct udphdr *udph;
	struct rohc_crc_info *header_crc;
	u8 crc;
	int off;
	int retval = 0;

	header_crc = &pkt_info->header_crc;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	iph_context = &co_context->iph_context;
	iph_ref = &iph_context->iph_ref;

	decomp_skb = context->decomp_skb;

	skb_copy_bits(decomp_skb,0,skb->data,pkt_info->rebuild_hdr_len);

	off = skb_network_header(decomp_skb) - decomp_skb->data;
	iph = (struct iphdr *)(skb->data + off);
	skb_set_network_header(skb,off);
	iph->tot_len = htons(skb->len - off);
	iph->check = ip_fast_csum((unsigned char *)iph,iph->ihl);
	if(iph_ref->has_inner_iph){
		off = skb_inner_network_header(decomp_skb) - decomp_skb->data;
		iph = (struct iphdr *)(skb->data + off);
		skb_set_inner_network_header(skb,off);
		iph->tot_len = htons(skb->len - off);
		iph->check = ip_fast_csum((unsigned char *)iph,iph->ihl);
	}
	rohc_v2_ip_header_dump(skb,context->cid,co_context->co_decode.new_msn,false);

	return 0;
}


static inline void decomp_ip_v2_reset_update_by_packet(struct rohc_decomp_context *context)
{
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_udp_v2_context *udp_context;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	memset(&co_context->iph_context.update_by_packet,0,sizeof(struct decomp_iph_field_update));
	memset(&co_context->co_update,0,sizeof(struct rohc_v2_common_update));
	memset(&co_context->co_decode,0,sizeof(struct rohc_v2_common_decode));
}


int decomp_ip_v2_decompress(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct rohc_crc_info *header_crc;
	struct rohc_decomp_profile_ops *decomp_prof_ops;
	u8 crc;
	int retval;

	decomp_prof_ops = context->decomp_profile->pro_ops;
	header_crc = &pkt_info->header_crc;
	pkt_info->skb = skb;
	decomp_ip_v2_reset_update_by_packet(context);
	retval = decomp_prof_ops->analyze_packet_header(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DIP2,"profie-v2 IP analyze header failed,cid :%d\n",context->cid);
		goto out;
	}

	if(header_crc->verify_type == CRC_VERIFY_ROHC_HEADER){
		crc = decomp_prof_ops->crc_cal(skb,header_crc);
		if(crc == header_crc->crc_value){
			rohc_pr(ROHC_DIP2,"success\n");
		}else
			rohc_pr(ROHC_DIP2,"failed,crc=%x,crarry_crc=%x\n",crc,header_crc->crc_value);
	}
	retval = decomp_prof_ops->decode_packet_header(context,pkt_info);
	if(retval){
		rohc_pr(ROHC_DIP2,"profie-v2 IP decode header failed,cid :%d\n",context->cid);
		goto out;
	}
	retval = decomp_prof_ops->rebuild_packet_header(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DIP2,"profie-v2 IP rebuild header failed,cid :%d\n",context->cid);
		goto out;
	}
out:
	return retval;
}

struct rohc_decomp_profile_ops decomp_ip_v2_prof_ops = {
	.adjust_packet_type = decomp_ip_v2_adjust_packet_type,
	.analyze_packet_header = decomp_ip_v2_analyze_packet_header,
	.analyze_static_chain = decomp_ip_v2_analyze_static_chain,
	.analyze_dynamic_chain = decomp_ip_v2_analyze_dynamic_chain,
	.decode_packet_header = decomp_ip_v2_decode_packet_header,
	.rebuild_packet_header = decomp_ip_v2_rebuild_packet_header,
	.recover_net_packet_header = decomp_ip_v2_recover_net_packet_header,
	.decompress = decomp_ip_v2_decompress,
	.last_decompressed_sn = decomp_ip_v2_last_decompressed_sn,
	.sn_bit_width = decomp_ip_v2_sn_bit_width,
	.init_context = decomp_ip_v2_init_context,
	.update_context = decomp_ip_v2_update_context,
	.crc_cal = rohc_crc_cal,
};

struct rohc_decomp_profile decomp_profile_ip_v2 = {
	.profile = ROHC_V2_PROFILE_IP,
	.pro_ops = &decomp_ip_v2_prof_ops,
};

