
/*
 *	rohc
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	Date   :	2020-6-16
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
#include "../rohc_profile.h"
#include "../rohc_cid.h"
#include "../rohc_bits_encode.h"
#include "../rohc_packet.h"
#include "../rohc_feedback.h"
#include "../lsb.h"
#include "../rohc_ipid.h"
#include "../profile/rohc_v2_profile.h"
#include "../profile/rohc_v2_packet.h"

#include "rohc_comp.h"
#include "rohc_comp_wlsb.h"
#include "rohc_comp_packet.h"
#include "rohc_comp_v2_common.h"



void comp_ip_v2_update(struct rohc_v2_common_context *co_context,struct rohc_comp_packet_hdr_info *pkt_info,u32 msn,int oa_max)
{
	rohc_v2_iph_update_probe(&co_context->iph_context,pkt_info,oa_max,msn);
	memset(&co_context->co_update,0,sizeof(struct rohc_v2_common_update));
	rohc_v2_cal_msn_encode_bits_set(&co_context->co_update.msn_encode_bits,co_context->msn_wlsb,REORDER_R_NONE,msn,TYPE_USHORT);
}

enum rohc_packet_type comp_ip_v2_adjust_packet_type_so(struct rohc_v2_common_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rohc_v2_iph_context *iph_context;
	struct rohc_bits_encode_set *msn_encode_bits;
	enum rohc_packet_type packet_type;

	iph_context = &context->iph_context;
	msn_encode_bits = &context->co_update.msn_encode_bits;
	if(!ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(4)) &&\
	    !ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(6)) &&\
	    !ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(8)))
		packet_type = ROHC_PACKET_TYPE_IR_DYN;
	else if(outer_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_DF) || \
		outer_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_IPID_BH))
		packet_type = ROHC_PACKET_TYPE_IR_DYN;
	else if(innermost_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_DF) ||\
		innermost_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_IPID_BH) ||\
		innermost_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_TOS_TC) ||\
		innermost_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_TTL_HL) ||\
		outer_iph_dynamic_field_update(iph_context,pkt_info,IPH_FIELD_TOS_TC) ||\
		outer_iph_dynamic_field_update(iph_context,pkt_info,IPH_FIELD_TTL_HL))
		packet_type = ROHC_PACKET_TYPE_CO_COMMON;
	else{
		if(!innermost_ipid_bh_is_seq(iph_context,pkt_info) || \
		   !innermost_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_IPID_OFF)){
			if(ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(4)))
				packet_type = ROHC_PACKET_TYPE_PT_0_CRC3;
			else if(ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(6)))
				packet_type = ROHC_PACKET_TYPE_PT_0_CRC7;
			else
				packet_type = ROHC_PACKET_TYPE_CO_COMMON;
		}else{
			if(ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(6)) &&\
			   innermost_ipid_encode_set_test(iph_context,pkt_info->has_inner_iph,ROHC_ENCODE_BY_BITS(4)))
				packet_type = ROHC_PACKET_TYPE_PT_1_SEQ_ID;
			else if(ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(8)) &&\
				innermost_ipid_encode_set_test(iph_context,pkt_info->has_inner_iph,ROHC_ENCODE_BY_BITS(6)))
				packet_type = ROHC_PACKET_TYPE_PT_2_SEQ_ID;
			else
				packet_type = ROHC_PACKET_TYPE_CO_COMMON;
		}
	}
	rohc_pr(ROHC_DIP2,"IP detect packet type:%d\n",packet_type);
	return packet_type;
}



static inline int comp_v2_iph_build_dynamic_field(u8 *to,struct iphdr *iph,enum ip_id_behavior ipid_bh,bool is_inner,u16 msn)
{
	struct profile_ipv4_dynamic *ipv4_dynamic;
	struct profile_ipv4_endpoint_innermost_dynamic *endpoint_ipv4_dynamic;
	int encode_len = 0;
	if(rohc_iph_is_v4(iph->version)){
		if(is_inner){
			endpoint_ipv4_dynamic = (struct profile_ipv4_endpoint_innermost_dynamic *)to;
			endpoint_ipv4_dynamic->reorder_ratio = REORDER_R_NONE;
			endpoint_ipv4_dynamic->ipid_bh = ipid_bh;
			endpoint_ipv4_dynamic->df = !!(ntohs(iph->frag_off) & IP_DF);
			endpoint_ipv4_dynamic->tos = iph->tos;
			endpoint_ipv4_dynamic->ttl = iph->ttl;
			encode_len = sizeof(struct profile_ipv4_endpoint_innermost_dynamic);
			to += encode_len;
			if(!ip_id_is_zero(ipid_bh)){
				/*keep network byte order*/
				memcpy(to,&iph->id,2);
				encode_len += 2;
				to += 2;
			}
			/*change to network byte order */
			msn = htons(msn);
			memcpy(to,&msn,2);
			encode_len += 2;
			
		}else{
			ipv4_dynamic = (struct profile_ipv4_dynamic *)to;
			ipv4_dynamic->ipid_bh = ipid_bh;
			ipv4_dynamic->df = !!(ntohs(iph->frag_off) & IP_DF);
			ipv4_dynamic->tos = iph->tos;
			ipv4_dynamic->ttl = iph->ttl;
			encode_len = sizeof(struct profile_ipv4_dynamic);
			if(!ip_id_is_zero(ipid_bh)){
				to += encode_len;
				/*keep network byte order*/
				memcpy(to,&iph->id,2);
				encode_len += 2;
			}
		}

	}else{
		//IPV6;
	}
	return encode_len;
}

int comp_ip_v2_build_dynamic_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct iphdr *iph;
	struct sk_buff *comp_skb;
	struct rohc_v2_common_context *co_context;
	struct rohc_v2_iph_context *iph_context;
	struct iph_field_update *iph_update;
	u16 msn;
	int call_len;
	int encode_len = 0;
	int retval = 0;
	iph = &pkt_info->iph;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	iph_context = &co_context->iph_context;
	iph_update = &iph_context->update_by_packet;
	msn = context->co_fields.msn;
	if(!pkt_info->has_inner_iph)
		call_len = comp_v2_iph_build_dynamic_field(comp_hdr,iph,iph_update->new_ipid_bh,true,msn);
	else
		call_len = comp_v2_iph_build_dynamic_field(comp_hdr,iph,iph_update->new_ipid_bh,false,msn);
	comp_hdr += call_len;
	encode_len += call_len;
	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		iph_update = &iph_context->inner_update_by_packet;
		call_len = comp_v2_iph_build_dynamic_field(comp_hdr,iph,iph_update->new_ipid_bh,true,msn);
		encode_len += call_len;
	}

	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;

}

int comp_ip_v2_build_static_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	int retval = 0;
	retval = rohc_comp_v2_build_ip_static_chain(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DIP2,"profile ip build  static chain failed\n");
	}
	return retval;
}

int comp_ip_v2_build_irr_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rohc_v2_common_context *co_context;
	struct sk_buff *comp_skb;
	int retval;
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	comp_skb = context->comp_skb;
	retval = rohc_comp_v2_build_ip_irr_chain(&co_context->iph_context,comp_skb,pkt_info);
	return retval;
}

int comp_ip_v2_build_co_header(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct ethhdr *eth;
	struct sk_buff *comp_skb;
	int (*build_co_func)(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first);
	enum rohc_packet_type packet_type;
	enum rohc_cid_type cid_type;
	u16 cid,pad_locat;
	int cid_encode_len;
	int retval = 0;
	comp_skb = context->comp_skb;
	comp_hdr = comp_skb->data;

	cid_type  = context->compresser->cid_type;
	packet_type = pkt_info->packet_type;
	BUG_ON(comp_skb->len);
	/*Ethernet header add before rohc header.
	 */

	if(context->comp_eth_hdr && !comp_skb->len){
		eth = eth_hdr(skb);
		memcpy(comp_hdr,eth,sizeof(struct ethhdr));
		pkt_info->comp_hdr_len += sizeof(struct ethhdr);
		comp_hdr += sizeof(struct ethhdr);
	}
	pad_locat = pkt_info->comp_hdr_len;
	cid = context->cid;
	switch(packet_type){
		case ROHC_PACKET_TYPE_CO_COMMON:
			build_co_func = rohc_comp_v2_build_generic_co_common;
			break;
		case ROHC_PACKET_TYPE_PT_0_CRC3:
			build_co_func = rohc_comp_v2_build_pt_0_crc3;
			break;
		case ROHC_PACKET_TYPE_PT_0_CRC7:
			build_co_func = rohc_comp_v2_build_pt_0_crc7;
			break;
		case ROHC_PACKET_TYPE_PT_1_SEQ_ID:
			build_co_func = rohc_comp_v2_build_pt_1_seq_id;
			break;
		case ROHC_PACKET_TYPE_PT_2_SEQ_ID:
			build_co_func = rohc_comp_v2_build_pt_2_seq_id;
			break;
		default:
			rohc_pr(ROHC_DIP2,"profile IP cid-%d not support the packet_type:%d\n",context->cid,packet_type);
			retval = -EFAULT;
			goto out;
	}
	if(cid_type == CID_TYPE_SMALL){
		retval = rohc_cid_encode(cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		pkt_info->comp_hdr_len += cid_encode_len;
		skb_put(comp_skb,pkt_info->comp_hdr_len);
		build_co_func(context,skb,pkt_info,true);
	}else{
		skb_put(comp_skb,pkt_info->comp_hdr_len);
		retval = build_co_func(context,skb,pkt_info,true);
		if(retval)
			goto out;
		comp_hdr = skb_tail_pointer(comp_skb);
		retval = rohc_cid_encode(cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		skb_put(comp_skb,cid_encode_len);
		pkt_info->comp_hdr_len += cid_encode_len;
		build_co_func(context,skb,pkt_info,false);
	}

	retval = comp_ip_v2_build_irr_chain(context,skb,pkt_info);

	if(!retval){
		if((pkt_info->to_comp_pkt_hdr_len & 0x1) != (pkt_info->comp_hdr_len & 0x1)){
			memmove(comp_skb->data + pad_locat + 1,comp_skb->data + pad_locat,pkt_info->comp_hdr_len - pad_locat);
			skb_put(comp_skb,1);
			comp_hdr = comp_skb->data + pad_locat;
			*comp_hdr = ROHC_PACKET_PADDING;
			pkt_info->comp_hdr_len++;
		}
	}
out:
	return retval;
}

int comp_ip_v2_build_comp_header(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,enum rohc_packet_type packet_type)
{
	int retval;

	switch(packet_type){
		case ROHC_PACKET_TYPE_IR:
			retval = rohc_comp_build_ir(context,skb,pkt_info);
			break;
		case ROHC_PACKET_TYPE_IR_DYN:
			retval = rohc_comp_build_ir_dyn(context,skb,pkt_info);
			break;
		case ROHC_PACKET_TYPE_CO_REPAIR:
			retval = rohc_comp_build_co_repair(context,skb,pkt_info);
			break;
		default:
			retval = comp_ip_v2_build_co_header(context,skb,pkt_info);
			break;

	}
	return retval;
}

int comp_ip_v2_init_context(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct iphdr *iph;
	struct rohc_v2_common_context *co_context;

	int retval = 0;
	co_context = kzalloc(sizeof(struct rohc_v2_common_context),GFP_ATOMIC);
	if(!co_context){
		pr_err("alloc memery for rohc v2 common context failed\n");
		retval = -ENOMEM;
		goto out;
	}
	co_context->oa_upward_pkts = 3;
	co_context->msn_wlsb = comp_wlsb_alloc(co_context->oa_upward_pkts,TYPE_USHORT,TYPE_USHORT,GFP_ATOMIC);
	if(IS_ERR(co_context->msn_wlsb)){
		pr_err("alloc wlsb for msn failed\n");
		goto err0;
	}

	rohc_v2_comp_init_ip_context(&co_context->iph_context,co_context->oa_upward_pkts);
	context->prof_context = co_context;
	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		if(rohc_iph_is_v4(iph->version))
			context->co_fields.msn = ntohl(iph->id);
		else{
			iph = &pkt_info->iph;
			if(rohc_iph_is_v4(iph->version))
				context->co_fields.msn = ntohl(iph->id);
			else
				get_random_bytes(&context->co_fields.msn,2);
		}
	}else{
		iph = &pkt_info->iph;
		if(rohc_iph_is_v4(iph->version))
			context->co_fields.msn = ntohl(iph->id);
		else
			get_random_bytes(&context->co_fields.msn,2);
	}
	return 0;
err0:
	kfree(co_context);
out:
	return retval;
}

void comp_ip_v2_update_context(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rohc_v2_common_context *co_context;
	struct rohc_v2_iph_context *iph_context;

	u16 msn;
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	iph_context = &co_context->iph_context;

	msn = context->co_fields.msn;
	/*add msn to wlsb*/
	comp_wlsb_add(co_context->msn_wlsb,NULL,msn,msn);
	rohc_v2_update_ip_context(iph_context,pkt_info,msn);
}


enum rohc_packet_type comp_ip_v2_adjust_packet_type(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rohc_v2_common_context *co_context;
	enum rohc_packet_type packet_type;
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	comp_ip_v2_update(co_context,pkt_info,context->co_fields.msn,co_context->oa_upward_pkts);
	switch(context->context_state){
		case COMP_STATE_IR:
			packet_type = ROHC_PACKET_TYPE_IR;
			break;
		case COMP_STATE_FO:
			packet_type = ROHC_PACKET_TYPE_IR_DYN;
			break;
		case COMP_STATE_SO:
			packet_type = comp_ip_v2_adjust_packet_type_so(co_context,pkt_info);
	}
	pkt_info->packet_type = packet_type;
	return packet_type;
}
u32 comp_ip_v2_new_msn(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u16 new_msn;
	new_msn = (u16)(context->co_fields.msn + 1);
	return new_msn;
}
int comp_ip_v2_compress(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct comp_profile_ops *pro_ops;
	enum rohc_packet_type packet_type;
	int retval = 0;
	pro_ops = context->comp_profile->pro_ops;
	context->co_fields.msn = pro_ops->new_msn(context,pkt_info);
	packet_type = pro_ops->adjust_packet_type(context,skb,pkt_info);
	retval = pro_ops->build_comp_header(context,skb,pkt_info,packet_type);
	if(!retval)
		pro_ops->update_context(context,pkt_info);

	rohc_v2_ip_header_dump(skb,context->cid,context->co_fields.msn,true);
	return retval;

}

struct comp_profile_ops comp_ip_v2_profile_ops = {
	.adjust_packet_type = comp_ip_v2_adjust_packet_type,
	.new_msn = comp_ip_v2_new_msn,
	.build_static_chain = comp_ip_v2_build_static_chain,
	.build_dynamic_chain = comp_ip_v2_build_dynamic_chain,
	.compress = comp_ip_v2_compress,
	.build_comp_header = comp_ip_v2_build_comp_header,
	.init_context = comp_ip_v2_init_context,
	.update_context = comp_ip_v2_update_context,
	.feedback_input = rohc_comp_v2_feedback_input,
};
struct rohc_comp_profile comp_profile_v2_ip = {
	.profile = ROHC_V2_PROFILE_IP,
	.pro_ops = &comp_ip_v2_profile_ops,
};
