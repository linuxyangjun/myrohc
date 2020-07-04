/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>

#include "../rohc_packet.h"
#include "../rohc_profile.h"
#include "../rohc_common.h"
#include "../rohc_cid.h"
#include "rohc_comp.h"


int rohc_comp_build_ir(struct rohc_comp_context *context , struct sk_buff *skb , struct rohc_comp_packet_hdr_info *pkt_info)
{

	unsigned char *comp_hdr,*crc;
	unsigned char *payload;
	struct ethhdr *eth;
	struct sk_buff *comp_skb;
	struct rohc_compresser *rohc_comp;
	struct comp_profile_ops *prof_ops;
	struct rohc_crc_info *crc_info;
	enum rohc_profile prof;
	int cid_encode_len;
	u16 cid;
	int pad_locat;
	int encode_len = 0;
	int retval = 0;
	comp_skb = context->comp_skb;
	rohc_comp = context->compresser;
	cid = context->cid;
	comp_hdr = comp_skb->data;
	prof = context->comp_profile->profile;
	prof_ops = context->comp_profile->pro_ops;
	crc_info = &pkt_info->crc_info;
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
	crc_info->start_off = pkt_info->comp_hdr_len;
	if(rohc_comp->cid_type == CID_TYPE_SMALL){
		retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		comp_hdr += cid_encode_len;
		*comp_hdr = ROHC_PACKET_IR;
		comp_hdr ++;

	}else{
		*comp_hdr = ROHC_PACKET_IR;
		comp_hdr ++;
		retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		comp_hdr += cid_encode_len;
		
	}
	pkt_info->comp_hdr_len += 1 + cid_encode_len;
	/**
	 *add profile
	 */
	*comp_hdr = prof;
	comp_hdr++;
	pkt_info->comp_hdr_len++;
	/**
	 *add crc ,
	 */
	*comp_hdr = 0;
	crc = comp_hdr;
	/**
	 *TODO calculate crc .
	 */
	pkt_info->comp_hdr_len++;
	skb_put(comp_skb,pkt_info->comp_hdr_len);
	if(prof_ops->build_static_chain){
		retval = prof_ops->build_static_chain(context,skb,pkt_info);
		if(retval){
			pr_err("%s : context-%d,prof-%x build static chain failed\n",rohc_comp->name,cid,prof);
			goto out;
		}
	}
	if(prof_ops->build_dynamic_chain){
		retval = prof_ops->build_dynamic_chain(context,skb,pkt_info);
		if(retval){
			pr_err("%s : context-%d,prof-%x build dynamic chain failed\n",rohc_comp->name,cid,prof);
			goto out;
		}
	}
	if(prof_ops->crc_cal){
		crc_info->crc_type = CRC_TYPE_8;
		crc_info->len = pkt_info->comp_hdr_len - crc_info->start_off;
		*crc = prof_ops->crc_cal(comp_skb,crc_info);
	}
	if(prof == ROHC_V1_PROFILE_TCP){
		u8 *cid_byte,*type_byte;
		rohc_pr(ROHC_DTCP,"to_comp_pkt_hdr_len=%d,comp_hdr_len=%d\n",pkt_info->to_comp_pkt_hdr_len,pkt_info->comp_hdr_len);
		cid_byte = comp_skb->data + sizeof(struct ethhdr);
		type_byte = comp_skb->data + sizeof(struct ethhdr) + cid_encode_len;
		rohc_pr(ROHC_DTCP,"cid=%d,type_byte=%x\n",*cid_byte,*type_byte);
	}
	if((pkt_info->to_comp_pkt_hdr_len & 0x1) != (pkt_info->comp_hdr_len & 0x1)){
		memmove(comp_skb->data + pad_locat + 1,comp_skb->data + pad_locat,pkt_info->comp_hdr_len - pad_locat);
		skb_put(comp_skb,1);
		comp_hdr = comp_skb->data + pad_locat;
		*comp_hdr = ROHC_PACKET_PADDING;
		pkt_info->comp_hdr_len++;
	}
out:
	return retval;
}


rohc_comp_build_ir_dyn(struct rohc_comp_context *context , struct sk_buff *skb ,struct rohc_comp_packet_hdr_info *pkt_info)
{
	
	unsigned char *comp_hdr,*crc;
	struct ethhdr *eth;
	struct sk_buff *comp_skb;
	struct rohc_compresser *rohc_comp;
	struct comp_profile_ops *prof_ops;
	struct rohc_crc_info *crc_info;
	enum rohc_profile prof;
	int cid_encode_len;

	u16 cid;
	int pad_locat;
	int encode_len = 0;
	int retval = 0;
	comp_skb = context->comp_skb;
	rohc_comp = context->compresser;
	cid = context->cid;
	comp_hdr = comp_skb->data;
	prof = context->comp_profile->profile;
	prof_ops = context->comp_profile->pro_ops;
	crc_info = &pkt_info->crc_info;
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
	crc_info->start_off = pkt_info->comp_hdr_len;
	if(rohc_comp->cid_type == CID_TYPE_SMALL){
		retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		comp_hdr += cid_encode_len;
		*comp_hdr = ROHC_PACKET_IR_DYN;
		comp_hdr ++;

	}else{
		*comp_hdr = ROHC_PACKET_IR_DYN;
		comp_hdr ++;
		retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		comp_hdr += cid_encode_len;
		
	}
	pkt_info->comp_hdr_len += 1 + cid_encode_len;
	/**
	 *add profile
	 */
	*comp_hdr = prof;
	comp_hdr++;
	pkt_info->comp_hdr_len++;
	/**
	 *add crc ,
	 */
	*comp_hdr = 0;
	crc = comp_hdr;
	/**
	 *TODO calculate crc .
	 */
	pkt_info->comp_hdr_len++;
	skb_put(comp_skb,pkt_info->comp_hdr_len);

	if(prof_ops->build_dynamic_chain){
		retval = prof_ops->build_dynamic_chain(context,skb,pkt_info);
		if(retval){
			pr_err("%s : context-%d,prof-%x build dynamic chain failed\n",rohc_comp->name,cid,prof);
			goto out;
		}
	}
	if(prof_ops->crc_cal){
		crc_info->crc_type = CRC_TYPE_8;
		crc_info->len = pkt_info->comp_hdr_len - sizeof(struct ethhdr);
		*crc = prof_ops->crc_cal(comp_skb,crc_info);
	}

	if((pkt_info->to_comp_pkt_hdr_len & 0x1) != (pkt_info->comp_hdr_len & 0x1)){
		memmove(comp_skb->data + pad_locat + 1,comp_skb->data + pad_locat,pkt_info->comp_hdr_len - pad_locat);
		skb_put(comp_skb,1);
		comp_hdr = comp_skb->data + pad_locat;
		*comp_hdr = ROHC_PACKET_PADDING;
		pkt_info->comp_hdr_len++;
	}
out:
	return retval;
}

int rohc_comp_build_co_repair(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct ethhdr *eth;
	struct sk_buff *comp_skb;
	struct rohc_compresser *rohc_comp;
	struct comp_profile_ops *prof_ops;
	enum rohc_profile prof;
	int cid_encode_len;
	u16 cid;
	int pad_locat;
	int encode_len = 0;
	int retval = 0;
	comp_skb = context->comp_skb;
	rohc_comp = context->compresser;
	cid = context->cid;
	comp_hdr = comp_skb->data;
	prof = context->comp_profile->profile;
	prof_ops = context->comp_profile->pro_ops;
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
	if(rohc_comp->cid_type == CID_TYPE_SMALL){
		retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		comp_hdr += cid_encode_len;
		*comp_hdr = ROHC_PACKET_CO_REPAIR;
		comp_hdr++;

	}else{
		*comp_hdr = ROHC_PACKET_CO_REPAIR;
		comp_hdr++;
		retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		comp_hdr += cid_encode_len;

	}
	pkt_info->comp_hdr_len += 1 + cid_encode_len;
	/*r1 and crc-7,not support now*/
	*comp_hdr = 0;
	comp_hdr++;
	pkt_info->comp_hdr_len++;
	/*r2 and crc-3,not support now*/
	*comp_hdr = 0;
	pkt_info->comp_hdr_len++;
	skb_put(comp_skb,pkt_info->comp_hdr_len);
	if(prof_ops->build_dynamic_chain){
		retval = prof_ops->build_dynamic_chain(context,skb,pkt_info);
		if(retval){
			pr_err("%s : context-%d,prof-%x build dynamic chain failed\n",rohc_comp->name,cid,prof);
			goto out;
		}
	}
	if((pkt_info->to_comp_pkt_hdr_len & 0x1) != (pkt_info->comp_hdr_len & 0x1)){
		memmove(comp_skb->data + pad_locat + 1,comp_skb->data + pad_locat,pkt_info->comp_hdr_len - pad_locat);
		skb_put(comp_skb,1);
		comp_hdr = comp_skb->data + pad_locat;
		*comp_hdr = ROHC_PACKET_PADDING;
		pkt_info->comp_hdr_len++;
	}
out:
	return retval;
}
