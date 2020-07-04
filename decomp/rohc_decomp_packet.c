/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	date: 2020/02/17
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

#include "../rohc_common.h"
#include "../rohc_cid.h"
#include "../rohc_packet.h"
#include "../rohc_profile.h"
#include "../rohc_ipid.h"

#include "rohc_decomp.h"

int rohc_decomp_analyze_ir(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct sk_buff *decomp_skb;
	struct rohc_decomp_profile_ops *prof_ops;
	struct rohc_crc_info		*crc_info;
	enum rohc_cid_type cid_type;
	u8 crc;
	int retval = 0;
	decomp_skb = context->decomp_skb;
	cid_type = context->decompresser->cid_type;
	prof_ops = context->decomp_profile->pro_ops;
	crc_info = &pkt_info->header_crc;
	BUG_ON(decomp_skb->len);
	/*copy the ether header.
	 */
	if(context->decomp_eth_hdr){
		memcpy(decomp_skb->data,skb->data,sizeof(struct ethhdr));
		pkt_info->rebuild_hdr_len = sizeof(struct ethhdr);
		skb_put(decomp_skb,sizeof(struct ethhdr));
	}
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	crc_info->start_off = pkt_info->decomped_hdr_len - (pkt_info->cid_len + 1) - 1;
	crc = *analyze_data;
	*analyze_data = 0;
	/*TODO crc caculte and check ,now not support
	 *
	 */
	pkt_info->decomped_hdr_len++;
	analyze_data++;

	/*next field is static chain
	 */
	BUG_ON(!prof_ops->analyze_static_chain);
	retval = prof_ops->analyze_static_chain(context,skb,pkt_info);
	if(retval){
		pr_err("profile-%x cid-%d analyze static chain of ir packet failed\n",context->decomp_profile->profile,context->cid);
		goto out;
	}
	/*next field is dynamic chain
	 */
	BUG_ON(!prof_ops->analyze_dynamic_chain);
	retval = prof_ops->analyze_dynamic_chain(context,skb,pkt_info);
	if(retval)
		pr_err("profile-%x cid-%d analyze dynamic chain of ir packet failed\n",context->decomp_profile->profile,context->cid);
	if(prof_ops->crc_cal){
		crc_info->crc_type = CRC_TYPE_8;
		crc_info->verify_type =CRC_VERIFY_ROHC_HEADER;
		crc_info->crc_value = crc;
		crc_info->len = pkt_info->decomped_hdr_len - crc_info->start_off;
	}
out:
	return retval;
}

int rohc_decomp_analyze_ir_dyn(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct sk_buff *decomp_skb;
	struct rohc_decomp_profile_ops *prof_ops;
	struct rohc_crc_info *header_crc;
	enum rohc_cid_type cid_type;
	u8 crc;
	int retval = 0;
	decomp_skb = context->decomp_skb;
	cid_type = context->decompresser->cid_type;
	prof_ops = context->decomp_profile->pro_ops;
	header_crc = &pkt_info->header_crc;
	BUG_ON(decomp_skb->len);
	/*copy the ether header.
	 */
	if(context->decomp_eth_hdr){
		memcpy(decomp_skb->data,skb->data,sizeof(struct ethhdr));
		pkt_info->rebuild_hdr_len = sizeof(struct ethhdr);
		skb_put(decomp_skb,sizeof(struct ethhdr));
	}
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	crc = *analyze_data;
	*analyze_data = 0;
	header_crc->start_off = pkt_info->decomped_hdr_len - (pkt_info->cid_len + 1) - 1;
	/*TODO crc caculte and check ,now not support
	 *
	 */
	pkt_info->decomped_hdr_len++;
	analyze_data++;

	/*next field is dynamic chain
	 */
	BUG_ON(!prof_ops->analyze_dynamic_chain);
	retval = prof_ops->analyze_dynamic_chain(context,skb,pkt_info);
	if(retval)
		pr_err("profile-%x cid-%d analyze dynamic chain of ir packet failed\n",context->decomp_profile->profile,context->cid);
	if(prof_ops->crc_cal){
		header_crc->crc_type = CRC_TYPE_8;
		header_crc->verify_type =CRC_VERIFY_ROHC_HEADER;
		header_crc->crc_value = crc;
		header_crc->len = pkt_info->decomped_hdr_len - header_crc->start_off;
	}
	return retval;
}

int rohc_decomp_analyze_co_repair(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct sk_buff *decomp_skb;
	struct rohc_decomp_profile_ops *prof_ops;
	enum rohc_cid_type cid_type;
	u8 crc3,crc7;
	int retval = 0;
	decomp_skb = context->decomp_skb;
	cid_type = context->decompresser->cid_type;
	prof_ops = context->decomp_profile->pro_ops;
	BUG_ON(decomp_skb->len);
	/*copy the ether header.
	 */
	if(context->decomp_eth_hdr){
		memcpy(decomp_skb->data,skb->data,sizeof(struct ethhdr));
		pkt_info->rebuild_hdr_len = sizeof(struct ethhdr);
		skb_put(decomp_skb,sizeof(struct ethhdr));
	}
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	/*skip the discriminator and cid bytes*/
	if(cid_type == CID_TYPE_SMALL){
		pkt_info->decomped_hdr_len += pkt_info->cid_len + 1;
		analyze_data += pkt_info->cid_len + 1;
	}else{
		pkt_info->decomped_hdr_len  += pkt_info->cid_len + 1;
		analyze_data += 1 + pkt_info->cid_len;
	}
	/*field.1 r1 and crc7,skip it*/
	analyze_data++;
	pkt_info->decomped_hdr_len++;
	/*field.2 r2 and crc3 skip it*/
	analyze_data++;
	pkt_info->decomped_hdr_len++;
	/*next field is dynamic chain
	 */
	BUG_ON(!prof_ops->analyze_dynamic_chain);
	retval = prof_ops->analyze_dynamic_chain(context,skb,pkt_info);
	if(retval)
		pr_err("profile-%x cid-%d analyze dynamic chain of co-repair packet failed\n",context->decomp_profile->profile,context->cid);

	return retval;
}	
