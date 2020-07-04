/*
 *	rohc
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	Date   :	2020-05-26
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
#include "comp_udp_v2.h"


void rohc_v2_udph_update_probe(struct comp_udp_v2_context *udp_context,struct rohc_comp_packet_hdr_info *pkt_info,int oa_max)
{
	struct udphdr *udph;
	struct udph_field_update *udph_update;
	struct last_comped_udph *udph_ref;
	struct udph_field_trans_times *update_trans_times;
	udph = &pkt_info->udph;
	udph_update = &udp_context->update_by_packet;
	udph_ref = &udp_context->udph_ref;

	memset(udph_update,0,sizeof(struct udph_field_update));

	update_trans_times = &udp_context->update_trans_times;
	if(udph->check)
		udph_update->check_bh = UDP_CHECK_SUM;
	else
		udph_update->check_bh = UDP_CHECK_NONE;
	net_header_field_update_probe(udph_update->check_bh,udph_ref->check_bh,&udph_update->check_bh_update,&update_trans_times->check_bh_trans_time,oa_max);

}

void comp_udp_v2_update_probe(struct rohc_v2_common_context *co_context,struct rohc_comp_packet_hdr_info *pkt_info,u32 msn,int oa_max)
{
	struct comp_udp_v2_context *udp_context;
	udp_context = (struct comp_udp_v2_context *)co_context->inherit_context;
        rohc_v2_iph_update_probe(&co_context->iph_context,pkt_info,oa_max,msn);
	rohc_v2_udph_update_probe(udp_context,pkt_info,oa_max);
	memset(&co_context->co_update,0,sizeof(struct rohc_v2_common_update));
	rohc_v2_cal_msn_encode_bits_set(&co_context->co_update.msn_encode_bits,co_context->msn_wlsb,REORDER_R_NONE,msn,TYPE_USHORT);
}


int rohc_v2_build_udp_static_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct udphdr *udph;
	struct sk_buff *comp_skb;

	struct profile_udp_static *udp_static;
	int encode_len = 0;

	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	udph = &pkt_info->udph;
	udp_static = (struct profile_udp_static *)comp_hdr;
	udp_static->sport = udph->source;
	udp_static->dport = udph->dest;
	encode_len = sizeof(struct profile_udp_static);
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return 0;
}

int rohc_v2_build_udp_dynamic_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct udphdr *udph;
	struct rohc_v2_common_context *co_context;
	struct comp_udp_v2_context *udp_context;

	u16 msn;
	int encode_len = 0;
	int retval = 0;
	struct profile_udp_endpoint_dynamic *udp_dynamic;

	co_context = (struct rohc_comp_v2_common *)context->prof_context;
	udp_context = (struct comp_udp_v2_context *)co_context->inherit_context;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	udp_dynamic = (struct profile_udp_endpoint_dynamic *)comp_hdr;
	udph = &pkt_info->udph;
	msn = context->co_fields.msn;
	udp_dynamic->checksum = udph->check;
	udp_dynamic->msn = htons(msn);
	udp_dynamic->reorder_ratio = REORDER_R_NONE;
	encode_len = sizeof(struct profile_udp_endpoint_dynamic);
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	udp_context->update_trans_times.check_bh_trans_time++;
	return 0;
}

int rohc_v2_build_udp_irr_chain(struct comp_udp_v2_context *udp_context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct udphdr *udph;
	int encode_len = 0;
	udph = &pkt_info->udph;
	comp_hdr = skb_tail_pointer(comp_skb);
	if(udph->check){
		/*keep network byte order*/
		memcpy(comp_hdr,&udph->check,2);
		encode_len = 2;
		comp_hdr += 2;
	}
	if(encode_len){
		skb_put(comp_skb,encode_len);
		pkt_info->comp_hdr_len += encode_len;
	}
	return 0;
}



enum rohc_packet_type comp_udp_v2_adjust_packet_type_so(struct rohc_v2_common_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rohc_v2_iph_context *iph_context;
	struct comp_udp_v2_context *udp_context;
	struct iph_packet_update *iph_update,*inner_iph_update;
	struct rohc_bits_encode_set *msn_encode_bits;
	enum rohc_packet_type packet_type;

	iph_context = &context->iph_context;
	udp_context = (struct comp_udp_v2_context *)context->inherit_context;
	msn_encode_bits = &context->co_update.msn_encode_bits;
	if(udp_context->update_by_packet.check_bh_update || \
	   (!ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(4)) &&\
	    !ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(6)) &&\
	    !ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(8))))
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

	return packet_type;
}

enum rohc_packet_type comp_udp_v2_adjust_packet_type(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rohc_v2_common_context *co_context;
	u32 msn;
	enum rohc_packet_type packet_type;
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	msn = context->co_fields.msn;

	comp_udp_v2_update_probe(co_context,pkt_info,msn,co_context->oa_upward_pkts);
	switch(context->context_state){
		case COMP_STATE_IR:
			packet_type = ROHC_PACKET_TYPE_IR;
			break;
		case COMP_STATE_FO:
			packet_type = ROHC_PACKET_TYPE_IR_DYN;
			break;
		case COMP_STATE_SO:
			packet_type = comp_udp_v2_adjust_packet_type_so(co_context,pkt_info);
			break;
	}
	rohc_pr(ROHC_DUDP2,"decide packet type:%d\n",packet_type);
	pkt_info->packet_type = packet_type;
	return packet_type;
}

u32 comp_udp_v2_new_msn(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u16 new_msn;
	new_msn = (u16)(context->co_fields.msn + 1);
	return new_msn;
}

int comp_udp_v2_build_irr_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct sk_buff *comp_skb;
	struct rohc_v2_common_context *co_context;
	struct rohc_v2_iph_context *iph_context;
	struct comp_udp_v2_context *udp_context;
	int retval;
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	iph_context = &co_context->iph_context;
	udp_context = (struct comp_udp_v2_context *)co_context->inherit_context;

	comp_skb = context->comp_skb;
	rohc_comp_v2_build_ip_irr_chain(iph_context,comp_skb,pkt_info);
	rohc_v2_build_udp_irr_chain(udp_context,comp_skb,pkt_info);
	return 0;
}
int comp_udp_v2_build_co_header(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
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
			rohc_pr(ROHC_DUDP2,"profile udp cid-%d not support the packet_type:%d\n",context->cid,packet_type);
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
	retval = comp_udp_v2_build_irr_chain(context,skb,pkt_info);
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
int comp_udp_v2_build_comp_header(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,enum rohc_packet_type packet_type)
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
			retval = comp_udp_v2_build_co_header(context,skb,pkt_info);
			break;

	}
	return retval;
}

int comp_udp_v2_build_static_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	int retval;
	retval = rohc_comp_v2_build_ip_static_chain(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DUDP2,"udp cid-%d build ip static chain failed\n",context->cid);
		goto out;
	}
	retval = rohc_v2_build_udp_static_chain(context,skb,pkt_info);
out:
	return retval;
}

int comp_udp_v2_build_dynamic_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	int retval;

	retval = rohc_comp_v2_build_ip_dynamic_chain(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DUDP2,"udp cid-%d build ip dyanmic chain fialed\n",context->cid);
		goto out;
	}
	retval = rohc_v2_build_udp_dynamic_chain(context,skb,pkt_info);

out:
	return retval;
}

int comp_udp_v2_feedback_input(struct rohc_v2_common_context *co_context,int ack_type,u32 msn,int msn_width,bool sn_valid)
{
	struct rohc_v2_iph_context *iph_context;
	struct comp_udp_v2_context *udp_context;
	iph_context = &co_context->iph_context;
	udp_context = (struct comp_udp_v2_context *)co_context->inherit_context;

	switch(ack_type){
		case ROHC_FEEDBACK_ACK:
			udp_context->update_trans_times.check_bh_trans_time = co_context->oa_upward_pkts;
			break;
		case ROHC_FEEDBACK_NACK:
		case ROHC_FEEDBACK_STATIC_NACK:
			udp_context->update_trans_times.check_bh_trans_time = 0;
			break;

	}
	return 0;
}

struct rohc_v2_prof_ops udp_v2_prof_ops = {
	.feedback_input = comp_udp_v2_feedback_input,
};
int comp_udp_v2_init_context(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct iphdr *iph;
	struct rohc_v2_common_context *co_context;
	struct comp_udp_v2_context *udp_context;
	int retval = 0;
	co_context = kzalloc(sizeof(struct rohc_v2_common_context),GFP_ATOMIC);
	if(!co_context){
		pr_err("alloc memery for rohc v2 common context failed\n");
		retval = -ENOMEM;
		goto out;
	}
	co_context->oa_upward_pkts = 3;
	udp_context = kzalloc(sizeof(struct comp_udp_v2_context),GFP_ATOMIC);
	if(!udp_context){
		pr_err("alloc memery for rohc v2 udp context failed\n");
		goto err0;
	}
	co_context->msn_wlsb = comp_wlsb_alloc(co_context->oa_upward_pkts,TYPE_USHORT,TYPE_USHORT,GFP_ATOMIC);
	if(IS_ERR(co_context->msn_wlsb)){
		pr_err("alloc wlsb for msn failed\n");
		goto err1;
	}
	co_context->prof_ops = &udp_v2_prof_ops;
	rohc_v2_comp_init_ip_context(&co_context->iph_context,co_context->oa_upward_pkts);
	context->capability |= ROHC_COMP_CAP_CRC_VERIFY;
	context->prof_context = co_context;
	co_context->inherit_context = udp_context;
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
err1:
	kfree(udp_context);
err0:
	kfree(co_context);
out:
	return retval;
}

void rohc_v2_update_udph_context(struct comp_udp_v2_context *udp_context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct last_comped_udph *udph_ref;
	struct udph_field_update *udph_update;
	struct udphdr *new_udph,*to_udph;

	udph_update = &udp_context->update_by_packet;
	udph_ref = &udp_context->udph_ref;
	new_udph = &pkt_info->udph;
	to_udph = &pkt_info->udph;

	memcpy(to_udph,new_udph,sizeof(struct udphdr));
	udph_ref->check_bh = udph_update->check_bh;

}
void comp_udp_v2_update_context(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rohc_v2_common_context *co_context;
	struct rohc_v2_iph_context *iph_context;
	struct comp_udp_v2_context *udp_context;
	u16 msn;
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	iph_context = &co_context->iph_context;
	udp_context = (struct comp_udp_v2_context *)co_context->inherit_context;
	msn = context->co_fields.msn;
	/*add msn to wlsb*/
	comp_wlsb_add(co_context->msn_wlsb,NULL,msn,msn);
	rohc_v2_update_ip_context(iph_context,pkt_info,msn);
	rohc_v2_update_udph_context(udp_context,pkt_info);
}

int comp_udp_v2_compress(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct comp_profile_ops *pro_ops;
	enum rohc_packet_type packet_type;
	int retval = 0;
	pro_ops = context->comp_profile->pro_ops;

	rohc_v2_net_header_dump(skb,context->cid,context->co_fields.msn);
	context->co_fields.msn = pro_ops->new_msn(context,pkt_info);
	packet_type = pro_ops->adjust_packet_type(context,skb,pkt_info);
	retval = pro_ops->build_comp_header(context,skb,pkt_info,packet_type);
	if(!retval)
		pro_ops->update_context(context,pkt_info);

	return retval;

}

struct comp_profile_ops comp_udp_v2_pro_ops = {
	.adjust_packet_type = comp_udp_v2_adjust_packet_type,
	.new_msn = comp_udp_v2_new_msn,
	.build_static_chain = comp_udp_v2_build_static_chain,
	.build_dynamic_chain = comp_udp_v2_build_dynamic_chain,
	.compress = comp_udp_v2_compress,
	.build_comp_header = comp_udp_v2_build_comp_header,
	.init_context = comp_udp_v2_init_context,
	.update_context = comp_udp_v2_update_context,
	.feedback_input = rohc_comp_v2_feedback_input,
	.crc_cal = rohc_crc_cal,
};
struct rohc_comp_profile comp_profile_v2_udp = {
	.profile = ROHC_V2_PROFILE_UDP,
	.pro_ops = &comp_udp_v2_pro_ops,
};
