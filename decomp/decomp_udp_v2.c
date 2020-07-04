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
#include "../rohc_feedback.h"

#include "../rohc_bits_encode.h"
#include "../profile/rohc_v2_packet.h"
#include "../profile/rohc_v2_profile.h"

#include "rohc_decomp.h"
#include "rohc_decomp_wlsb.h"
#include "rohc_decomp_v2_common.h"
#include "decomp_udp_v2.h"
#include "rohc_decomp_packet.h"


int udp_checksum_is_carryed(struct decomp_udph_field_update *udp_update,struct last_decomped_udph *udp_ref)
{
	int new_check_bh;
	if(analyze_field_is_carryed(&udp_update->udph_fields.dynamic_fields.check_bh))
		new_check_bh = udp_update->udph_fields.dynamic_fields.check_bh.value;
	else
		new_check_bh = udp_ref->check_bh;
	return new_check_bh;
}



int rohc_v2_analyze_udp_irr_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_udp_v2_context *udp_context;
	struct decomp_udph_field_update *udp_update;
	struct last_decomped_udph *udp_ref;
	u16 checksum;
	int analyze_len = 0;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	udp_context = (struct decomp_udp_v2_context *)co_context->inherit_context;
	udp_update = &udp_context->update_by_packet;
	udp_ref = &udp_context->udph_ref;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(udp_checksum_is_carryed(udp_update,udp_ref)){
		memcpy(&checksum,analyze_data,2);
		decomp_fill_analyze_field(&udp_update->udph_fields.dynamic_fields.check,checksum);
		analyze_len = 2;
	}
	if(analyze_len)
		pkt_info->decomped_hdr_len += analyze_len;
	return 0;
}


int rohc_v2_analyze_udp_static_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_udp_v2_context *udp_context;
	struct decomp_udph_field_update *udp_update;

	struct profile_udp_static *udp_static;
	struct udph_static_fields *static_fields;
	int analyze_len = 0;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	udp_context = (struct decomp_udp_v2_context *)co_context->inherit_context;
	udp_update = &udp_context->update_by_packet;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	udp_static = (struct profile_udp_static *)analyze_data;
	static_fields = &udp_update->udph_fields.static_fields;
	static_fields->sport = udp_static->sport;
	static_fields->dport = udp_static->dport;
	static_fields->update = true;
	analyze_len = sizeof(struct profile_udp_static);
	pkt_info->decomped_hdr_len += analyze_len;
	return 0;
}

int rohc_v2_analyze_udp_dynamic_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_udp_v2_context *udp_context;
	struct decomp_udph_field_update *udp_update;
	struct udph_dynamic_fields *dynamic_fields;
	struct profile_udp_endpoint_dynamic *udp_dynamic;
	struct wlsb_analyze_field *msn;
	int analyze_len = 0;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	udp_context = (struct decomp_udp_v2_context *)co_context->inherit_context;
	udp_update = &udp_context->update_by_packet;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	udp_dynamic = (struct profile_udp_endpoint_dynamic *)analyze_data;
	dynamic_fields = &udp_update->udph_fields.dynamic_fields;

	msn = &co_context->co_update.msn;
	decomp_fill_analyze_field(&dynamic_fields->check,udp_dynamic->checksum);
	if(!udp_dynamic->checksum)
		decomp_fill_analyze_field(&dynamic_fields->check_bh,UDP_CHECK_SUM);
	else
		decomp_fill_analyze_field(&dynamic_fields->check_bh,UDP_CHECK_NONE);
	decomp_wlsb_fill_analyze_field(msn,ntohs(udp_dynamic->msn),16,false);
	decomp_fill_analyze_field(&co_context->co_update.reorder_ratio,udp_dynamic->reorder_ratio);
	analyze_len = sizeof(struct profile_udp_endpoint_dynamic);

	pkt_info->decomped_hdr_len += analyze_len;
	return 0;
}

int rohc_v2_decode_udp_header(struct decomp_udp_v2_context *udp_context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct udphdr *new_udph,*old_udph;
	struct decomp_udph_field_update *udp_update;
	struct last_decomped_udph *udph_ref;
	struct udph_static_fields *static_fields;
	struct udph_dynamic_fields *dynamic_fields;

	udp_update = &udp_context->update_by_packet;
	udph_ref = &udp_context->udph_ref;
	static_fields = &udp_update->udph_fields.static_fields;
	dynamic_fields = &udp_update->udph_fields.dynamic_fields;
	new_udph = &udp_update->decoded_updh.udph;
	old_udph = &udph_ref->udph;
	/*decode static field*/
	if(static_fields->update){
		new_udph->source = static_fields->sport;
		new_udph->dest = static_fields->dport;
	}else{
		new_udph->source = old_udph->source;
		new_udph->dest = old_udph->dest;
	}
	/*decode checksum*/
	if(analyze_field_is_carryed(&dynamic_fields->check))
		new_udph->check = dynamic_fields->check.value & 0xffff;
	else
		new_udph->check = 0;
	return 0;
}

void rohc_v2_udp_update_context(struct decomp_udp_v2_context *udp_context)
{
	struct udphdr *new_udph,*to_udph;
	struct last_decomped_udph *udph_ref;
	struct decomp_udph_field_update *udp_update;

	udp_update = &udp_context->update_by_packet;
	udph_ref = &udp_context->udph_ref;
	new_udph = &udp_update->decoded_updh.udph;
	to_udph = &udph_ref->udph;
	memcpy(to_udph,new_udph,sizeof(struct udphdr));
	if(analyze_field_is_carryed(&udp_update->udph_fields.dynamic_fields.check_bh))
		udph_ref->check_bh = udp_update->udph_fields.dynamic_fields.check_bh.value;
}


int decomp_udp_v2_analyze_static_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	int retval;
	retval = rohc_v2_decomp_analyze_ip_static_chain(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DUDP2,"profile udp v2 analyze ip static chain failed\n");
		retval = -EFAULT;
		goto out;
	}
	retval = rohc_v2_analyze_udp_static_chain(context,skb,pkt_info);
out:
	return retval;
}


int decomp_udp_v2_analyze_dynamic_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	int retval;
	retval = rohc_v2_decomp_analyze_ip_dynamic_chain(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DUDP2,"profile udp v2 analyze ip dynamic chain failed\n");
		retval = -EFAULT;
		goto out;
	}
	retval = rohc_v2_analyze_udp_dynamic_chain(context,skb,pkt_info);
out:
	return retval;
}

int decomp_udp_v2_analyze_irr_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	int retval;

	retval = rohc_v2_decomp_analyze_ip_irr_chain(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DUDP2,"profile udp v2 analyze irr chain failed\n");
		goto out;
	}
	retval = rohc_v2_analyze_udp_irr_chain(context,skb,pkt_info);
out:
	return retval;
}

int decomp_udp_v2_analyze_co_header(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
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
			rohc_pr(ROHC_DUDP2,"profile-v2 udp not support the packet_type : %d\n",packet_type);
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
	retval = decomp_udp_v2_analyze_irr_chain(context,skb,pkt_info);
out:
	return retval;
}
int decomp_udp_v2_decode_packet_header(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct rohc_v2_decomp_common_context *co_context;
	struct rohc_v2_decomp_iph_context *iph_context;
	struct decomp_udp_v2_context *udp_context;
	int retval;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	iph_context = &co_context->iph_context;
	udp_context = (struct decomp_udp_v2_context *)co_context->inherit_context;
	retval = rohc_v2_decode_common_msn(co_context);
	if(retval)
		goto out;
	retval = rohc_v2_decode_ip_header(iph_context,pkt_info,co_context->co_decode.new_msn);
	if(retval)
		goto out;
	retval = rohc_v2_decode_udp_header(udp_context,pkt_info);
out:
	return retval;
}
enum rohc_packet_type decomp_udp_v2_adjust_packet_type(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
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
		rohc_pr(ROHC_DUDP2,"profile can't support the packet type,%x\n",*analyze_data);
		packet_type = ROHC_PACKET_TYPE_UNDECIDE;
	}
	return packet_type;
}

int decomp_udp_v2_init_context(struct rohc_decomp_context *context)
{
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_udp_v2_context *udp_context;
	int retval;
	co_context = kzalloc(sizeof(struct rohc_v2_decomp_common_context),GFP_ATOMIC);
	if(!co_context){
		pr_err("alloc memery for decomp udp v2 common context failed\n");
		retval = -ENOMEM;
		goto out;
	}
	udp_context = kzalloc(sizeof(struct decomp_udp_v2_context),GFP_ATOMIC);
	if(!udp_context){
		pr_err("alloc memery for decomp udp v2 context failed\n");
		retval = -ENOMEM;
		goto err0;
	}
	co_context->msn_wlsb = rohc_decomp_lsb_alloc(TYPE_USHORT,GFP_ATOMIC);
	if(IS_ERR(co_context->msn_wlsb)){
		pr_err("alloc msn wlsb for udp profile-v2 failed\n");
		retval = -ENOMEM;
		goto err1;
	}
	retval = rohc_v2_ip_init_context(&co_context->iph_context);
	if(retval)
		goto err2;
	context->inherit_context = co_context;
	co_context->inherit_context = udp_context;

	context->capability |= ROHC_DECOMP_CAP_CRC_VERIFY;
	return 0;
err2:
	rohc_decomp_lsb_free(co_context->msn_wlsb);
err1:
	kfree(udp_context);
err0:
	kfree(co_context);
out:
	return retval;
}
int decomp_udp_v2_update_context(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct rohc_v2_decomp_common_context *co_context;
	struct rohc_v2_decomp_iph_context *iph_context;
	struct decomp_udp_v2_context *udp_context;
	u32 msn;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	iph_context = &co_context->iph_context;
	udp_context = (struct decomp_udp_v2_context *)co_context->inherit_context;
	msn = co_context->co_decode.new_msn;

	rohc_v2_ip_context_update(iph_context,msn);
	rohc_v2_udp_update_context(udp_context);
	rohc_decomp_lsb_setup_ref(co_context->msn_wlsb,msn);
	return 0;
}

u8 decomp_udp_v2_sn_bit_width(struct rohc_decomp_context *context)
{
	return 16;
}

u32 decomp_udp_v2_last_decompressed_sn(struct rohc_decomp_context *context)
{
	struct rohc_v2_decomp_common_context *co_context;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	return rohc_decomp_lsb_pick_ref(co_context->msn_wlsb,false);
}

int rohc_v2_rebuild_udp_header(struct decomp_udp_v2_context *udp_context,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct udphdr *new_udph,*to_udph;
	skb_set_transport_header(decomp_skb,decomp_skb->len);
	to_udph = (struct udphdr *)skb_tail_pointer(decomp_skb);
	new_udph = &udp_context->update_by_packet.decoded_updh.udph;
	memcpy(to_udph,new_udph,sizeof(struct udphdr));
	skb_put(decomp_skb,sizeof(struct udphdr));
	pkt_info->rebuild_hdr_len += sizeof(struct udphdr);
	return 0;
}
int decomp_udp_v2_rebuild_packet_header(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct sk_buff *decomp_skb;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_udp_v2_context *udp_context;
	struct rohc_v2_decomp_iph_context *iph_context;

	decomp_skb = context->decomp_skb;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	udp_context = (struct decomp_udp_v2_context *)co_context->inherit_context;
	iph_context = &co_context->iph_context;
	/*fist rebuild ip header*/
	rohc_v2_rebuild_ip_header(iph_context,decomp_skb,pkt_info);
	/*next step to rebuild the udp header*/
	rohc_v2_rebuild_udp_header(udp_context,decomp_skb,pkt_info);
	return 0;
}


int decomp_udp_v2_recover_net_packet_header(struct rohc_decomp_context *context,struct sk_buff *skb ,struct rohc_decomp_pkt_hdr_info *pkt_info)
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
	off = skb_transport_header(decomp_skb) - decomp_skb->data;
	udph = (struct udphdr *)(skb->data + off);
	skb_set_transport_header(skb,off);
	udph->len = htons(skb->len - off);
	rohc_v2_net_header_dump(skb,context->cid,co_context->co_decode.new_msn);
	if(context->capability & ROHC_DECOMP_CAP_CRC_VERIFY){
		if(header_crc->verify_type == CRC_VERIFY_NET_HEADER){
			header_crc->start_off = ETH_HLEN;
			header_crc->len = pkt_info->rebuild_hdr_len - ETH_HLEN;
			if(context->decomp_profile->pro_ops->crc_verify(skb,header_crc))
				rohc_pr(ROHC_DUDP2,"udp header CRC-VERIFY FAILED,type:%s,crarry_crc:%x\n",rohc_crc_type_to_name(header_crc->crc_type),header_crc->crc_value);
			else
				rohc_pr(ROHC_DUDP2,"udp heade CRC-VERIFY SUCESS,type:%s,carry_crc:%x\n",rohc_crc_type_to_name(header_crc->crc_type),header_crc->crc_value);

		}
	}
	return 0;
}


int decomp_udp_v2_analyze_packet_header(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
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
			retval = decomp_udp_v2_analyze_co_header(context,skb,pkt_info);
			break;
	}
	return retval;
}

static inline void decomp_udp_v2_reset_update_by_packet(struct rohc_decomp_context *context)
{
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_udp_v2_context *udp_context;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	udp_context = (struct decomp_udp_v2_context *)co_context->inherit_context;

	memset(&co_context->iph_context.update_by_packet,0,sizeof(struct decomp_iph_field_update));
	memset(&udp_context->update_by_packet,0,sizeof(struct decomp_udph_field_update));
	memset(&co_context->co_update,0,sizeof(struct rohc_v2_common_update));
	memset(&co_context->co_decode,0,sizeof(struct rohc_v2_common_decode));
}
int decomp_udp_v2_decompress(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct rohc_crc_info *header_crc;
	struct rohc_decomp_profile_ops *decomp_prof_ops;
	u8 crc;
	int retval;

	decomp_prof_ops = context->decomp_profile->pro_ops;
	header_crc = &pkt_info->header_crc;
	pkt_info->skb = skb;
	decomp_udp_v2_reset_update_by_packet(context);
	retval = decomp_prof_ops->analyze_packet_header(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DUDP2,"profie-v2 udp analyze header failed,cid :%d\n",context->cid);
		goto out;
	}
	if(header_crc->verify_type == CRC_VERIFY_ROHC_HEADER){
		crc = decomp_prof_ops->crc_cal(skb,header_crc);
		if(crc == header_crc->crc_value){
			rohc_pr(ROHC_DUDP2,"success\n");
		}else
			rohc_pr(ROHC_DUDP2,"failed,crc=%x,crarry_crc=%x\n",crc,header_crc->crc_value);
	}
	retval = decomp_prof_ops->decode_packet_header(context,pkt_info);
	if(retval){
		rohc_pr(ROHC_DUDP2,"profie-v2 udp decode header failed,cid :%d\n",context->cid);
		goto out;
	}
	retval = decomp_prof_ops->rebuild_packet_header(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DUDP2,"profie-v2 udp rebuild header failed,cid :%d\n",context->cid);
		goto out;
	}

	//decomp_prof_ops->update_context(context,pkt_info);
out:
	return retval;
}

struct rohc_decomp_profile_ops profiev2_udp_decomp_ops = {
	.adjust_packet_type = decomp_udp_v2_adjust_packet_type,
	.analyze_packet_header = decomp_udp_v2_analyze_packet_header,
	.analyze_static_chain = decomp_udp_v2_analyze_static_chain,
	.analyze_dynamic_chain = decomp_udp_v2_analyze_dynamic_chain,
	.decode_packet_header = decomp_udp_v2_decode_packet_header,
	.rebuild_packet_header = decomp_udp_v2_rebuild_packet_header,
	.recover_net_packet_header = decomp_udp_v2_recover_net_packet_header,
	.decompress = decomp_udp_v2_decompress,
	.last_decompressed_sn = decomp_udp_v2_last_decompressed_sn,
	.sn_bit_width = decomp_udp_v2_sn_bit_width,
	.init_context = decomp_udp_v2_init_context,
	.update_context = decomp_udp_v2_update_context,
	.crc_cal = rohc_crc_cal,
	.crc_verify = rohc_crc_verify,
};

struct rohc_decomp_profile decomp_profile_udp_v2 = {
	.profile = ROHC_V2_PROFILE_UDP,
	.pro_ops = &profiev2_udp_decomp_ops,
};

