/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	Date: 2020/5/20
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
#include "../profile/rtp_profile.h"
#include "rohc_decomp.h"
#include "decomp_rtp_clist.h"
int rtp_v2_csrc_analyze_clist(struct decomp_rtp_csrc_context *csrc_context,const struct sk_buff *skb,struct	rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data,*item_start;
	struct decomp_rtp_csrc_update *csrc_update;
	struct csrc_carryed_items *carryed_items;
	struct csrc_analyze_item *new_item;

	bool ps,is_carryed;
	u32 item_v;
	int cc,i;
	int xi_len;
	int analyze_len = 0;
	int retval = 0;

	csrc_update = &csrc_context->update_by_packet;
	carryed_items = &csrc_update->carryed_items;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	/*field.1 :PS,CC*/
	ps = !!BYTE_BIT_4(*analyze_data);
	cc = BYTE_BITS_4(*analyze_data,0);
	analyze_data++;
	analyze_len++;
	/*field.2 xi table*/
	xi_len = rtp_csrc_cal_xi_table_len(cc,ps);
	item_start = analyze_data + xi_len;
	analyze_len += xi_len;

	carryed_items->cc = cc;
	carryed_items->comp_list_present = true;

	for(i = 0 ; i < cc;i++){
		new_item = &carryed_items->analyze_item[i];
		if(ps){
			is_carryed = !!BYTE_BIT_7(*analyze_data);
			new_item->item_type = BYTE_BITS_7(*analyze_data,0);
			analyze_data++;
		}else{
			if(!(i % 2)){
				is_carryed = !!BYTE_BIT_7(*analyze_data);
				new_item->item_type = BYTE_BITS_3(*analyze_data,4);
			}else{
				is_carryed = !!BYTE_BIT_4(*analyze_data);
				new_item->item_type = BYTE_BITS_3(*analyze_data,0);
				analyze_data++;
			}
		}
		if(is_carryed){
			/*keep netwrok byte order*/
			memcpy(&item_v,item_start,4);
			decomp_fill_analyze_field(&new_item->item_field,item_v);
			item_start += 4;
			analyze_len += 4;
		}
	}
	rohc_pr(ROHC_DV2,"analyze clist: cc = %d,analyze_len=%d\n",cc,analyze_len);
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}
int rtp_csrc_analyze_generic_scheme(struct decomp_rtp_csrc_context *csrc_context,const struct sk_buff *skb,struct	rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data,*item_start;
	struct decomp_rtp_csrc_update *csrc_update;
	struct csrc_carryed_items *carryed_items;
	struct csrc_analyze_item *new_item;

	bool ps,is_carryed;
	u32 item_v;
	int cc,i;
	int xi_len;
	int analyze_len = 0;
	int retval = 0;

	csrc_update = &csrc_context->update_by_packet;
	carryed_items = &csrc_update->carryed_items;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	/*field.1 :ET,GP,PS,CC*/
	ps = !!BYTE_BIT_4(*analyze_data);
	cc = BYTE_BITS_4(*analyze_data,0);
	analyze_data++;
	analyze_len++;
	/*field.2 xi table*/
	xi_len = rtp_csrc_cal_xi_table_len(cc,ps);
	item_start = analyze_data + xi_len;
	analyze_len += xi_len;

	carryed_items->cc = cc;
	carryed_items->comp_list_present = true;

	for(i = 0 ; i < cc;i++){
		new_item = &carryed_items->analyze_item[i];
		if(ps){
			is_carryed = !!BYTE_BIT_7(*analyze_data);
			new_item->item_type = BYTE_BITS_7(*analyze_data,0);
			analyze_data++;
		}else{
			if(!(i % 2)){
				is_carryed = !!BYTE_BIT_7(*analyze_data);
				new_item->item_type = BYTE_BITS_3(*analyze_data,4);
			}else{
				is_carryed = !!BYTE_BIT_4(*analyze_data);
				new_item->item_type = BYTE_BITS_3(*analyze_data,0);
				analyze_data++;
			}
		}
		if(is_carryed){
			/*keep netwrok byte order*/
			memcpy(&item_v,item_start,4);
			decomp_fill_analyze_field(&new_item->item_field,item_v);
			item_start += 4;
			analyze_len += 4;
		}
	}
	rohc_pr(ROHC_DRTP,"analyze clist: cc = %d,analyze_len=%d\n",cc,analyze_len);
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

static inline int rtp_csrc_insert_item(struct last_decomped_rtp_csrc *csrc_ref,struct csrc_carryed_items *carryed_items,struct csrc_analyze_item *insert_items,const u16 insert_bit_mask,int insert_num)
{
	struct csrc_analyze_item *new_item,*insert_item;
	struct rtp_csrc *rtp_csrc;
	int new_cc,i;
	int insert_index = 0;
	int ref_index = 0;
	new_cc = csrc_ref->cc + insert_num;
	for(i = 0; i < new_cc;i++){
		new_item = &carryed_items->analyze_item[i];
		if(insert_bit_mask & (1 << i)){
			insert_item = &insert_items[insert_index];
			//new_item->item_type = insert_item->item_type;
			//decomp_fill_analyze_field(&new_item->item_field,insert_item->value);
			memcpy(new_item,insert_item,sizeof(struct csrc_analyze_item));
			insert_index++;
		}else{
			rtp_csrc = &csrc_ref->ssrcs[ref_index];
			new_item->item_type = rtp_csrc->item_type;
			//decomp_fill_analyze_field(&new_item->item_field,rtp_csrc->ssrc);
			ref_index++;
		}
	}
	carryed_items->cc = new_cc;
	return 0;
}
int rtp_csrc_analyze_insert_scheme(struct decomp_rtp_csrc_context *csrc_context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data,*item_start;
	struct decomp_rtp_csrc_update *csrc_update;
	struct csrc_carryed_items *carryed_items;
	struct csrc_analyze_item *new_item;

	u16 insert_bit_mask;
	u32 item_v;
	bool ps,is_carryed;
	int cc,i;
	int xi_len;
	int insert_num = 0;
	int analyze_len = 0;
	int retval = 0;

	struct csrc_analyze_item insert_item[CSRC_CARRYED_MAX] = {[0 ... CSRC_CARRYED_MAX - 1] = {0}};
	csrc_update = &csrc_context->update_by_packet;
	carryed_items = &csrc_update->carryed_items;

	carryed_items->comp_list_present = true;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	/*filed.1:ET,GP,PS,and XI 1(if ps == 0)*/
	ps = !!BYTE_BIT_4(*analyze_data);
	if(!ps){
		new_item = &insert_item[0];
		new_item->item_type = BYTE_BITS_3(*analyze_data,0);
	}
	analyze_data++;
	analyze_len++;
	/*field.2,gen id not need*/
	/*field.3,ref id,i set zero,skip it*/
	analyze_data++;
	analyze_len++;
	/*filed.4 insertion bit mask*/
	if(BYTE_BIT_7(*analyze_data)){
		insert_bit_mask = BYTE_BITS_7(*analyze_data,0);
		analyze_data++;
		insert_bit_mask = (insert_bit_mask << 8) | (*analyze_data);
		analyze_data++;
		analyze_len += 2;
	}else{
		insert_bit_mask = BYTE_BITS_7(*analyze_data,0);
		analyze_data++;
		analyze_len++;
	}
	/*caculate the number of 1 in the insert_bit_mask,
	 * which is the insert item num
	 * */

	cc = hweight16(insert_bit_mask);
	/*field.5 xi table*/
	xi_len = rtp_csrc_cal_xi_len_insert_scheme(cc,ps);
	item_start = analyze_data + xi_len;
	analyze_len += xi_len;

	for(i=0 ;i < cc;i++){
		new_item = &insert_item[i];
		if(!ps){
			if(i){
				if(i % 2){
					new_item->item_type = BYTE_BITS_3(*analyze_data,4);
				}else{
					new_item->item_type = BYTE_BITS_3(*analyze_data,0);
					analyze_data++;
				}
			}
		}else{
			new_item->item_type = BYTE_BITS_7(*analyze_data,0);
			analyze_data++;
		}
		memcpy(&item_v,item_start,4);
		decomp_fill_analyze_field(&new_item->item_field,item_v);
		item_start += 4;
		analyze_len += 4;
	}
	if(cc){
		rtp_csrc_insert_item(&csrc_context->csrc_ref,carryed_items,insert_item,insert_bit_mask,cc);
	}
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int rtp_csrc_analyze_remove_scheme(struct decomp_rtp_csrc_context *csrc_context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data,*item_start;
	struct decomp_rtp_csrc_update *csrc_update;
	struct last_decomped_rtp_csrc *csrc_ref;
	struct rtp_csrc *ssrc_ref;
	struct csrc_carryed_items *carryed_items;
	struct csrc_analyze_item *new_item;


	int cc,i;
	u16 remove_bit_mask;

	int item_idx = 0;
	int analyze_len = 0;
	int retval = 0;

	csrc_update = &csrc_context->update_by_packet;
	csrc_ref = &csrc_context->csrc_ref;

	carryed_items = &csrc_update->carryed_items;

	carryed_items->comp_list_present = true;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	/*filed.1 :ET,GP,RES,COUNT*/
	cc = BYTE_BITS_4(*analyze_data,0);
	analyze_data++;
	analyze_len++;
	/*filed.2 gen id,not need*/
	/*field.3, ref id ,i set zero,skip it*/
	analyze_data++;
	analyze_len++;
	/*filed.4 removal bit mask*/
	if(BYTE_BIT_7(*analyze_data)){
		remove_bit_mask = BYTE_BITS_7(*analyze_data,0);
		analyze_data++;
		remove_bit_mask = (remove_bit_mask << 8) | (*analyze_data);
		analyze_data++;
		analyze_len += 2;
	}else{
		remove_bit_mask = BYTE_BITS_7(*analyze_data,0);
		analyze_data++;
		analyze_len++;
	}
	if(cc != csrc_ref->cc){
		rohc_pr(ROHC_DRTP,"%s : error carryed count : %d,ref_cc=%d,remove_bit_mask=%x\n",__func__,cc,csrc_ref->cc,remove_bit_mask);
		retval = -EFAULT;
		goto out;
	}
	for(i = 0 ;i < cc; i++){
		if(remove_bit_mask & (1 << i))
			continue;
		ssrc_ref = &csrc_ref->ssrcs[i];
		new_item = &carryed_items->analyze_item[item_idx];
		new_item->item_type = ssrc_ref->item_type;
		decomp_fill_analyze_field(&new_item->item_field,ssrc_ref->ssrc);
		item_idx++;
	}
	carryed_items->cc = item_idx;

	pkt_info->decomped_hdr_len += analyze_len;
out:
	return retval;
}

int rtp_csrc_analyze_remove_insert_scheme(struct decomp_rtp_csrc_context *csrc_context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data,*item_start;
	struct decomp_rtp_csrc_update *csrc_update;
	struct last_decomped_rtp_csrc *csrc_ref;
	struct rtp_csrc *ssrc_ref,*new_ssrc;
	struct csrc_carryed_items *carryed_items;
	struct csrc_analyze_item *new_item,*insert_item;

	u16 insert_bit_mask;
	u16 remove_bit_mask;
	u32 item_v;
	bool ps;
	int new_cc;
	int cc,i;
	int xi_len;
	int item_idx = 0;
	int insert_idx = 0;
	int analyze_len = 0;
	int retval = 0;

	struct csrc_analyze_item insert_items[CSRC_CARRYED_MAX] = {[0 ... CSRC_CARRYED_MAX - 1] = {0}};
	struct rtp_csrc remove_ssrcs[CSRC_CARRYED_MAX] = {[0 ... CSRC_CARRYED_MAX - 1] = {0}};

	csrc_update = &csrc_context->update_by_packet;
	carryed_items = &csrc_update->carryed_items;
	csrc_ref = &csrc_context->csrc_ref;

	carryed_items->comp_list_present = true;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	/*field.1 : ET,GP,PS and XI 1(if ps == 0)*/
	ps = !!BYTE_BIT_4(*analyze_data);
	if(!ps){
		insert_item = &insert_items[0];
		insert_item->item_type = BYTE_BITS_3(*analyze_data,0);
	}
	analyze_data++;
	analyze_len++;
	/*filed.2 gen id,not need*/
	/*field.3, ref id ,i set zero,skip it*/
	analyze_data++;
	analyze_len++;

	/*filed.4 removal bit mask*/
	if(BYTE_BIT_7(*analyze_data)){
		remove_bit_mask = BYTE_BITS_7(*analyze_data,0);
		analyze_data++;
		remove_bit_mask = (remove_bit_mask << 8) | (*analyze_data);
		analyze_data++;
		analyze_len += 2;
	}else{
		remove_bit_mask = BYTE_BITS_7(*analyze_data,0);
		analyze_data++;
		analyze_len++;
	}

	/*filed.5 insertion bit mask*/
	if(BYTE_BIT_7(*analyze_data)){
		insert_bit_mask = BYTE_BITS_7(*analyze_data,0);
		analyze_data++;
		insert_bit_mask = (insert_bit_mask << 8) | (*analyze_data);
		analyze_data++;
		analyze_len += 2;
	}else{
		insert_bit_mask = BYTE_BITS_7(*analyze_data,0);
		analyze_data++;
		analyze_len++;
	}


	/*caculate the number of 1 in the insert_bit_mask,
	 * which is the insert item num
	 * */

	cc = hweight16(insert_bit_mask);
	/*field.6 xi table*/
	xi_len = rtp_csrc_cal_xi_len_insert_scheme(cc,ps);

	item_start = analyze_data + xi_len;
	analyze_len += xi_len;

	for(i = 0 ; i < cc;i++){
		insert_item = &insert_items[i];
		if(!ps){
			if(i){
				if(i % 2){
					insert_item->item_type = BYTE_BITS_3(*analyze_data,4);
				}else{
					insert_item->item_type = BYTE_BITS_3(*analyze_data,0);
					analyze_data++;
				}
			}
		}else{
			insert_item->item_type = BYTE_BITS_7(*analyze_data,0);
			analyze_data++;
		}
		/*keep netwrok byte order*/
		memcpy(&item_v,item_start,4);
		decomp_fill_analyze_field(&insert_item->item_field,item_v);
		item_start += 4;
		analyze_len += 4;
	}
	/*first step,remove items */
	for(i = 0 ;i < csrc_ref->cc; i++){
		if(remove_bit_mask & (1 << i))
			continue;
		ssrc_ref = &csrc_ref->ssrcs[i];
		new_ssrc = &remove_ssrcs[item_idx];
		memcpy(new_ssrc,ssrc_ref,sizeof(struct rtp_csrc));
		item_idx++;
	}

	/*next step,insert items*/

	new_cc = cc + item_idx;
	item_idx = 0;
	for(i = 0; i < new_cc;i++){
		new_item = &carryed_items->analyze_item[item_idx];
		if(insert_bit_mask & (1 << i)){
			insert_item = &insert_items[insert_idx];
			memcpy(new_item,insert_item,sizeof(struct csrc_analyze_item));
			insert_idx++;
		}else{
			ssrc_ref = &remove_ssrcs[item_idx];
			new_item->item_type = ssrc_ref->item_type;
			//decomp_fill_analyze_field(&new_item->item_field,ssrc_ref->ssrc);
		}
	}
	carryed_items->cc = new_cc;
	pkt_info->decomped_hdr_len += analyze_len;

	return retval;
}

void rtp_csrc_copy_static_clist(struct decomp_rtp_csrc_context *csrc_context)
{
	struct last_decomped_rtp_csrc *csrc_ref;
	struct decomp_rtp_csrc_update *csrc_update;
	struct csrc_carryed_items *carryed_items;
	struct rtp_csrc *ssrc_ref;
	struct csrc_analyze_item *new_item;

	int i;

	csrc_ref = &csrc_context->csrc_ref;
	csrc_update = &csrc_context->update_by_packet;

	carryed_items = &csrc_update->carryed_items;

	if(carryed_items->comp_list_present)
		return;

	carryed_items->cc = csrc_ref->cc;

	for(i = 0;i < carryed_items->cc;i++){
		new_item = &carryed_items->analyze_item[i];
		ssrc_ref = &csrc_ref->ssrcs[i];

		new_item->item_type = ssrc_ref->item_type;
	}

}


int rtp_csrc_analyze_clist(struct decomp_rtp_csrc_context *csrc_context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	int scheme_type;

	int analyze_len = 0;
	int retval;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	scheme_type = BYTE_BITS_2(*analyze_data,6);
	switch(scheme_type){
		case ET_TYPE_0:
			retval = rtp_csrc_analyze_generic_scheme(csrc_context,skb,pkt_info);
			break;
		case ET_TYPE_1:
			retval = rtp_csrc_analyze_insert_scheme(csrc_context,skb,pkt_info);
			break;
		case ET_TYPE_2:
			retval = rtp_csrc_analyze_remove_scheme(csrc_context,skb,pkt_info);
			break;
		case ET_TYPE_3:
			retval = rtp_csrc_analyze_remove_insert_scheme(csrc_context,skb,pkt_info);
			break;
		default:
			rohc_pr(ROHC_DRTP,"rtp can't support the csrc list scheme_type : %d\n",scheme_type);
			retval = -EFAULT;
			break;
	}
	return retval;
}

int rtp_csrc_decode_ssr(struct decomp_rtp_csrc_context *csrc_context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct last_decomped_rtp_csrc *csrc_ref;
	struct decomp_rtp_csrc_update *csrc_update;
	struct rtp_decode_csrc *decode_csrc;
	struct csrc_carryed_items *carryed_items;
	struct rtp_csrc *ssrc_ref,*new_ssrc;
	struct ssrc_item_to_index *ref_map,*new_map;
	struct csrc_analyze_item *new_item;
	struct analyze_field *item_field;

	int i;
	int retval = 0;

	csrc_ref = &csrc_context->csrc_ref;
	csrc_update = &csrc_context->update_by_packet;
	decode_csrc = &csrc_update->decode_csrc;
	carryed_items = &csrc_update->carryed_items;

	if(!carryed_items->cc)
		goto out;
	for(i = 0 ; i < carryed_items->cc;i++){
		new_item = &carryed_items->analyze_item[i];
		new_ssrc = &decode_csrc->decode_ssrcs[decode_csrc->cc];
		new_map = &decode_csrc->new_map[new_item->item_type];
		new_map->maped = true;
		new_map->index = decode_csrc->cc;
		new_ssrc->item_type = new_item->item_type;
		item_field = &new_item->item_field;
		if(analyze_field_is_carryed(item_field)){
			new_ssrc->ssrc = item_field->value;
		}else{
			ref_map = &csrc_ref->ref_map[new_item->item_type];
			if((ref_map->index >= CSRC_CARRYED_MAX) || !ref_map->maped){
				rohc_pr(ROHC_DRTP2,"%s: error index:%d,maped:%d\n",ref_map->index,ref_map->maped);
				retval = -EFAULT;
				goto out;
			}
			if(decode_csrc->cc >= CSRC_CARRYED_MAX){
				rohc_pr(ROHC_DRTP2,"%s: error cc index:%d\n",decode_csrc->cc);
				retval = -EFAULT;
				goto out;
			}
			ssrc_ref = &csrc_ref->ssrcs[ref_map->index];
			new_ssrc->ssrc = ssrc_ref->ssrc;
		}
		decode_csrc->cc++;
	}

out:
	return retval;
}

int rtp_csrc_rebuild_csrc_list(struct decomp_rtp_csrc_context *csrc_context,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info,int *cc)
{
	u32 *ssrc;
	struct rtp_decode_csrc *decode_csrc;
	struct rtp_csrc *ssrc_item;
	int i;
	decode_csrc = &csrc_context->update_by_packet.decode_csrc;
	if(!decode_csrc->cc){
		*cc = 0;
		return 0;
	}
	ssrc = (u32 *)skb_tail_pointer(decomp_skb);
	*cc = decode_csrc->cc;
	for(i = 0; i < decode_csrc->cc;i++){
		ssrc_item = &decode_csrc->decode_ssrcs[i];
		memcpy(ssrc,&ssrc_item->ssrc,4);
		ssrc++;
	}
	skb_put(decomp_skb,*cc * 4);
	pkt_info->rebuild_hdr_len += decode_csrc->cc * 4;
	return 0;
}
int decomp_rtp_csrc_update_context(struct decomp_rtp_csrc_context *csrc_context)
{
	struct last_decomped_rtp_csrc *csrc_ref;
	struct decomp_rtp_csrc_update *csrc_update;
	struct rtp_decode_csrc *decode_csrc;
	csrc_ref = &csrc_context->csrc_ref;
	csrc_update = &csrc_context->update_by_packet;
	decode_csrc = &csrc_update->decode_csrc;
	struct ssrc_item_to_index *to_map,*new_map;
	struct rtp_csrc *to_ssrc,*new_ssrc;
	int i;
	csrc_ref->cc = decode_csrc->cc;
	for(i = 0 ; i < csrc_ref->cc;i++){
		to_ssrc = &csrc_ref->ssrcs[i];
		new_ssrc = &decode_csrc->decode_ssrcs[i];
		memcpy(to_ssrc,new_ssrc,sizeof(struct rtp_csrc));
		to_map = &csrc_ref->ref_map[new_ssrc->item_type];
		new_map = &decode_csrc->new_map[new_ssrc->item_type];
		memcpy(to_map,new_map,sizeof(struct ssrc_item_to_index));
	}
	return 0;
}

int decomp_rtp_csrc_init_context(struct decomp_rtp_csrc_context *csrc_context)
{
	return 0;
}
