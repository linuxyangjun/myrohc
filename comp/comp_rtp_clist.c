/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	Date   :	2020-05-19
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
#include "../profile/rtp_profile.h"

#include "rohc_comp.h"
#include "comp_rtp_clist.h"
static void rtp_csrc_free_item(struct rtp_csrc_context *context,int item_type)
{
	BUG_ON(item_type > SSRC_ITEM_GENERIC_MAX);
	clear_bit(item_type,context->item_bitmap);
}
static void rtp_ssrc_to_item(struct rtp_csrc *new_ssrc,struct rtp_csrc_context *context)
{
	struct last_comped_rtph_csrcs *csrc_ref;
	struct ssrc_item_generic *new_item;
	struct rtp_csrc *old_ssrc;
	int i,free;
	bool found = false;
	csrc_ref = &context->csrc_ref;
	for(i = 0 ; i < csrc_ref->cc;i++){
		old_ssrc = &csrc_ref->rtp_csrcs[i];
		if(new_ssrc->ssrc == old_ssrc->ssrc){
			new_ssrc->item_type = old_ssrc->item_type;
			found = true;
			new_item = &context->ssrc_items[new_ssrc->item_type];
			list_move(&new_item->list,&context->item_active_list);
		}
	}
	if(!found){
		free = find_first_zero_bit(context->item_bitmap,SSRC_ITEM_GENERIC_MAX + 1);
		if(free > SSRC_ITEM_GENERIC_MAX){
			rohc_pr(ROHC_DRTP,"rtp ssrc generic exhaust\n");
			new_item = list_last_entry(&context->item_active_list,struct ssrc_item_generic,list);
			list_del_init(&new_item->list);
		}else{
			new_item = &context->ssrc_items[free];
		}
		list_add(&new_item->list,&context->item_active_list);
		new_ssrc->item_type = new_item->item_type;
	}
}


void rtp_csrc_update_probe(struct rtp_csrc_context *context,struct rohc_comp_packet_hdr_info *pkt_info,int oa_max)
{
	struct rtp_csrc *new_ssrc,*old_ssrc,*insert_ssrc;
	struct rtp_new_csrcs *rtph_csrc;
	struct last_comped_rtph_csrcs *csrc_ref;
	struct rtp_csrc_update *csrc_update;
	struct rtp_ssrc_item_update *item_update;
	struct ssrc_update_trans_times *update_trans_times;
	int i,max_cc;
	enum ssrc_item_type item_type,insert_item_type_max,item_type_max;
	bool list_strcture_update = false;
	struct ssrc_item_map item_map[SSRC_ITEM_GENERIC_MAX] = {[0 ... SSRC_ITEM_GENERIC_MAX - 1] = {0}};
	/*if the length of the bit list is less than
	 * the required bit mask length,append additional
	 * zeros
	 */
	u32 insert_bit_mask = 0;
	/*If the length of the bit list is less than
	 * the required bit mask length,append additional
	 * ones
	 */
	u32 remove_bit_mask = 0;
	item_type_max = 0;
	rtph_csrc = &pkt_info->rtph_csrc;
	csrc_ref = &context->csrc_ref;
	csrc_update = &context->update_by_packet;
	item_update = csrc_update->ssrc_item_update;
	update_trans_times = context->update_trans_times;
	memset(csrc_update,0,sizeof(struct rtp_csrc_update));

	if(context->is_first_packet){
		csrc_update->csrc_list_update = true;
		//return;
	}

	if(rtph_csrc->cc != csrc_ref->cc){
		csrc_update->csrc_list_update = true;
		if(!csrc_ref->cc && rtph_csrc->cc)
			csrc_update->csrc_list_zero_to_non_zero = true;
	}
	if(!rtph_csrc->cc)
		return;
	for(i = 0 ; i < rtph_csrc->cc;i++){
		new_ssrc = &rtph_csrc->rtp_csrcs[i];
		if(i < csrc_ref->cc){
			old_ssrc = &csrc_ref->rtp_csrcs[i];
			item_map[old_ssrc->item_type].appear_in_ref = true;
			item_map[old_ssrc->item_type].maped = true;
			item_map[old_ssrc->item_type].ref_index = i;
			if(new_ssrc->ssrc == old_ssrc->ssrc){
				new_ssrc->item_type = old_ssrc->item_type;
				item_map[new_ssrc->item_type].appear_in_cur = true;
			}else{
				list_strcture_update = true;
				rtp_ssrc_to_item(new_ssrc,context);
				item_map[new_ssrc->item_type].appear_in_cur = true;
			}
			item_map[new_ssrc->item_type].maped = true;
			item_map[new_ssrc->item_type].cur_index = i;
		}else{
			rtp_ssrc_to_item(new_ssrc,context);
			item_map[new_ssrc->item_type].appear_in_cur = true;
			item_map[new_ssrc->item_type].maped = true;
			item_map[new_ssrc->item_type].cur_index = i;
		}

	}
	for(;i < csrc_ref->cc;i++){
		old_ssrc = &csrc_ref->rtp_csrcs[i];
		item_map[old_ssrc->item_type].appear_in_ref = true;
		item_map[old_ssrc->item_type].maped = true;
		item_map[old_ssrc->item_type].ref_index = i;
	}
	insert_item_type_max = 0;
	for(i = 0 ; i < SSRC_ITEM_GENERIC_MAX;i++){
		if(item_map[i].maped){
			if(item_map[i].appear_in_cur){
				if(item_type_max < i)
					item_type_max = i;
			}
			if(!item_map[i].appear_in_cur){
				remove_bit_mask |= (1 << item_map[i].ref_index);
				/*free the generic item type*/
				rtp_csrc_free_item(context,i);
			}
			if(!item_map[i].appear_in_ref){
				if(insert_item_type_max < i)
					insert_item_type_max = i;
				item_update[i].static_update = true;
				insert_bit_mask |= 1 << item_map[i].cur_index;
				//insert_ssrc = &csrc_update->item_insert[csrc_update->insert_num];
				//memcpy(insert_ssrc,&rtph_csrc->rtp_csrcs[item_map[i].cur_index],sizeof(struct rtp_csrc));
				csrc_update->insert_num++;
			}
		}
	}
	if(insert_bit_mask){
		csrc_update->insert_bit_len = rtph_csrc->cc;
		csrc_update->insert_bit_mask = insert_bit_mask;
		csrc_update->csrc_insert = true;
		csrc_update->insert_item_type_max = insert_item_type_max;
		csrc_update->csrc_list_update = true;
	}
	if(remove_bit_mask){
		csrc_update->remove_bit_len = csrc_ref->cc;
		csrc_update->remove_bit_mask = remove_bit_mask;
		csrc_update->csrc_remove = true;
		csrc_update->csrc_list_update = true;
	}
	csrc_update->item_type_max = item_type_max;

}

static inline bool rtp_ssrc_item_need_carry(struct rtp_ssrc_item_update *item_update,enum rohc_packet_type packet_type)
{
	bool is_need  = false;
	if(rohc_packet_is_covered_by_crc8(packet_type) || item_update->static_update)
		is_need = true;
	return is_need;
}

int rtp_csrc_build_generic_scheme(struct rtp_csrc_context *context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	u8 *item_start;
	struct rtphdr *rtph;
	struct rtp_new_csrcs *rtph_csrc;
	struct rtp_csrc *new_ssrc;
	struct rtp_csrc_update *new_csrc_update;
	struct rtp_ssrc_item_update *ssrc_item_update;
	enum	rohc_packet_type packet_type;
	bool ps;
	bool is_need_carryed;
	int xi_len,i,m;
	int encode_len = 0;
	int retval = 0;

	packet_type = pkt_info->packet_type;

	rtph_csrc = &pkt_info->rtph_csrc;

	new_csrc_update = &context->update_by_packet;
	ssrc_item_update = new_csrc_update->ssrc_item_update;
	comp_hdr = skb_tail_pointer(comp_skb);
	m = rtph_csrc->cc;
	if(m){
		if(new_csrc_update->item_type_max > 7)
			ps = 1;
		else
			ps = 0;
		xi_len = rtp_csrc_cal_xi_table_len(m,ps);
	}
	/*field.1 : ET ,GP,PS and cc*/
	*comp_hdr = (ET_TYPE_0 << 6) | (ps << 4) | (m & 0xf);
	encode_len++;
	comp_hdr++;
	if(!m)
		goto out;
	item_start = comp_hdr + xi_len;
	encode_len += xi_len;
	for(i = 0 ; i < m;i++){
		new_ssrc = &rtph_csrc->rtp_csrcs[i];
		is_need_carryed = rtp_ssrc_item_need_carry(&ssrc_item_update[new_ssrc->item_type],packet_type);
		if(ps){
			*comp_hdr = (is_need_carryed << 7) | (new_ssrc->item_type & 0x7f);
			comp_hdr++;
		}else{
			if(!(i % 2)){
				*comp_hdr = (is_need_carryed << 7) | ((new_ssrc->item_type & 0x7) << 4);
			}else{
				(*comp_hdr) |= (is_need_carryed << 3) | (new_ssrc->item_type & 0x7);
				comp_hdr++;
			}
		}
		if(is_need_carryed){
			memcpy(item_start,&new_ssrc->ssrc,4);
			encode_len += 4;
			item_start += 4;
		}
	}
	if(m & 1){
		//add padding
	}
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rtp_csrc_build_insert_scheme(struct rtp_csrc_context *context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	u8 *item_start;
	struct rtphdr *rtph;
	struct rtp_new_csrcs *rtph_csrc;
	struct rtp_csrc *new_ssrc;
	struct rtp_csrc_update *new_csrc_update;
	bool ps;
	int xi_len,i,m;
	int insert_idx = 0;
	int encode_len = 0;
	int retval = 0;

	rtph_csrc = &pkt_info->rtph_csrc;
	new_csrc_update = &context->update_by_packet;
	comp_hdr = skb_tail_pointer(comp_skb);
	if(new_csrc_update->insert_item_type_max > 7)
		ps = 1;
	else
		ps = 0;
	xi_len = rtp_csrc_cal_xi_len_insert_scheme(new_csrc_update->insert_num,ps);
	/*find first item that need be inserted*/
	insert_idx = find_first_bit(&new_csrc_update->insert_bit_mask,(CSRC_CARRYED_MAX + 1));
	/*filed.1 : ET,GP,PS,and XI 1*/
	*comp_hdr = (ET_TYPE_1 << 6) | (ps << 4);
	if(!ps){
		new_ssrc = &rtph_csrc->rtp_csrcs[insert_idx];
		(*comp_hdr) |=  (1 << 3) | (new_ssrc->item_type & 0x7);
	}
	comp_hdr++;
	encode_len++;
	/*filed.2 gen_id,not need*/
	/*filed.3 ref_id ,i set zero*/
	*comp_hdr = 0;
	comp_hdr++;
	encode_len++;
	/*filed.4 insertion bit mask*/
	if(new_csrc_update->insert_bit_len <= 7){
		*comp_hdr = (0 << 7) | (new_csrc_update->insert_bit_mask & 0x3f);
		comp_hdr++;
		encode_len++;
	}else{
		*comp_hdr = (1 << 7) | ((new_csrc_update->insert_bit_mask >> 8) & 0x3f);
		comp_hdr++;
		*comp_hdr = new_csrc_update->insert_bit_mask & 0xff;
		comp_hdr++;
		encode_len += 2;
	}
	/*filed.5 xi list*/
	item_start = comp_hdr + xi_len;
	encode_len += xi_len;

	for(i = 0 ; i < new_csrc_update->insert_num;i++){

		new_ssrc = &rtph_csrc->rtp_csrcs[insert_idx];//&new_csrc_update->item_insert[i];
		if(!ps){
			if(i){
				if(i % 2){
					*comp_hdr = (1 << 7) | ((new_ssrc->item_type & 0x7) << 4);
				}else{
					(*comp_hdr) = (1 << 3) | (new_ssrc->item_type & 0x7);
					comp_hdr++;
				}
			}
		}else{
			*comp_hdr = (1 << 7) | (new_ssrc->item_type & 0x7f);
			comp_hdr++;
		}
		memcpy(item_start,&new_ssrc->ssrc,4);
		item_start += 4;
		encode_len += 4;
		/*find next set bit*/
		/*find next item that need be inserted*/
		insert_idx = find_next_bit(&new_csrc_update->insert_bit_mask,(CSRC_CARRYED_MAX + 1),insert_idx + 1);
		if(insert_idx > CSRC_CARRYED_MAX)
			rohc_pr(ROHC_DRTP,"error insert index:%d\n",insert_idx);
	}
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rtp_csrc_build_remove_scheme(struct rtp_csrc_context *context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct rtp_csrc_update *new_csrc_update;
	int m;
	int encode_len = 0;
	int retval = 0;
	comp_hdr = skb_tail_pointer(comp_skb);

	new_csrc_update = &context->update_by_packet;
	/*filed.1 :ET,GP,reserve and count*/
	*comp_hdr = (ET_TYPE_2 << 6) | (new_csrc_update->remove_bit_len & 0xf);
	comp_hdr++;
	encode_len++;
	/*filed.2 gen_id,not need*/
	/*filed.3 .i set zero*/
	*comp_hdr = 0;
	comp_hdr++;
	encode_len++;
	/*field.4 removal bit mask*/
	if(new_csrc_update->remove_bit_len <= 7){
		*comp_hdr = new_csrc_update->remove_bit_mask & 0x7f;
		comp_hdr++;
		encode_len++;
	}else{
		*comp_hdr = (1 << 7) | ((new_csrc_update->remove_bit_mask >> 8) & 0x7f);
		comp_hdr++;
		*comp_hdr = new_csrc_update->remove_bit_mask & 0xff;
		comp_hdr++;
		encode_len += 2;
	}
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rtp_csrc_build_remove_insert_scheme(struct rtp_csrc_context *context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	u8 *item_start;
	struct rtp_csrc_update *new_csrc_update;
	struct rtp_csrc *new_ssrc;
	struct rtp_new_csrcs *rtph_csrc;
	bool ps;
	int i;
	int xi_len;
	int insert_idx;
	int encode_len = 0;
	int retval = 0;

	rtph_csrc = &pkt_info->rtph_csrc;
	new_csrc_update = &context->update_by_packet;
	comp_hdr = skb_tail_pointer(comp_skb);


	insert_idx = find_first_bit(&new_csrc_update->insert_bit_mask,(CSRC_CARRYED_MAX + 1));
	if(new_csrc_update->insert_item_type_max > 7)
		ps = 1;
	else
		ps = 0;
	xi_len = rtp_csrc_cal_xi_len_insert_scheme(new_csrc_update->insert_num,ps);

	/*filed.1 ET,GP,PS,XI1*/
	*comp_hdr = (ET_TYPE_3 << 6) | (ps << 4);
	if(!ps){
		new_ssrc = &rtph_csrc->rtp_csrcs[insert_idx];
		(*comp_hdr) |= (1 << 3) | (new_ssrc->item_type & 0x7);
	}
	comp_hdr++;
	encode_len++;
	/*filed.2 gen_id,not need*/
	/*filed.3 .i set zero*/
	*comp_hdr = 0;
	comp_hdr++;
	encode_len++;
	/*filed.4 removal bit mask*/
	if(new_csrc_update->remove_bit_len <= 7){
		*comp_hdr = new_csrc_update->remove_bit_mask & 0x7f;
		comp_hdr++;
		encode_len++;
	}else{
		*comp_hdr = (1 << 7) | ((new_csrc_update->remove_bit_mask >> 8) & 0x7f);
		comp_hdr++;
		*comp_hdr = new_csrc_update->remove_bit_mask & 0xff;
		comp_hdr++;
		encode_len += 2;
	}
	/*field.5 insertion bit mask*/
	if(new_csrc_update->insert_bit_len <= 7){
		*comp_hdr = new_csrc_update->insert_bit_mask & 0x7f;
		comp_hdr++;
		encode_len++;
	}else{
		*comp_hdr = (1 << 7) | ((new_csrc_update->insert_bit_mask >> 8) & 0x7f);
		comp_hdr++;
		*comp_hdr = new_csrc_update->insert_bit_mask & 0xff;
		comp_hdr++;
		encode_len += 2;
	}
	item_start = comp_hdr + xi_len;
	encode_len += xi_len;

	for(i = 0 ; i < new_csrc_update->insert_num;i++){
		//new_ssrc = &new_csrc_update->item_insert[i];
		new_ssrc = &rtph_csrc->rtp_csrcs[insert_idx];
		if(!ps){
			if(i){
				if(i % 2){
					*comp_hdr = (1 << 7) | ((new_ssrc->item_type & 0x7) << 4);
				}else{
					(*comp_hdr) = (1 << 3) | (new_ssrc->item_type & 0x7);
					comp_hdr++;
				}
			}
		}else{
			*comp_hdr = (1 << 7) | (new_ssrc->item_type & 0x7f);
			comp_hdr++;
		}
		memcpy(item_start,&new_ssrc->ssrc,4);
		item_start += 4;
		encode_len += 4;

		/*find next set bit*/
		/*find next item that need be inserted*/
		insert_idx = find_next_bit(&new_csrc_update->insert_bit_mask,(CSRC_CARRYED_MAX + 1),insert_idx + 1);
		if(insert_idx > CSRC_CARRYED_MAX)
			rohc_pr(ROHC_DRTP,"error insert index:%d\n",insert_idx);
	}
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rtp_csrc_build_clist(struct rtp_csrc_context *context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rtphdr *rtph;
	struct rtp_csrc_update *new_csrc_update;
	enum rohc_packet_type packet_type;
	int scheme_type;
	int retval = 0;
	rtph= &pkt_info->rtph;
	new_csrc_update = &context->update_by_packet;
	packet_type = pkt_info->packet_type;
	if(rohc_packet_is_covered_by_crc8(packet_type)){
		if(!rtph->cc)
			goto out;
		scheme_type = ET_TYPE_0;
	}else{
		if(!rtph->cc)
			scheme_type = ET_TYPE_0;
		else if(new_csrc_update->csrc_list_zero_to_non_zero)
			scheme_type = ET_TYPE_0;
		else if(new_csrc_update->csrc_remove && new_csrc_update->csrc_insert)
			scheme_type = ET_TYPE_3;
		else if(new_csrc_update->csrc_insert)
			scheme_type = ET_TYPE_1;
		else if(new_csrc_update->csrc_remove)
			scheme_type = ET_TYPE_2;
		else{
			rohc_pr(ROHC_DRTP,"%s : ccrc comp list update ? %d\n",__func__,new_csrc_update->csrc_list_update);
			goto out;
		}
	}
	switch(scheme_type){
		case ET_TYPE_0:
			retval = rtp_csrc_build_generic_scheme(context,comp_skb,pkt_info);
			break;
		case ET_TYPE_1:
			retval =  rtp_csrc_build_insert_scheme(context,comp_skb,pkt_info);
			break;
		case ET_TYPE_2:
			retval = rtp_csrc_build_remove_scheme(context,comp_skb,pkt_info);
			break;
		case ET_TYPE_3:
			retval = rtp_csrc_build_remove_insert_scheme(context,comp_skb,pkt_info);
			break;
	}
out:
	return retval;
}

int rtp_v2_csrc_build_clist(struct rtp_csrc_context *context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	u8 *item_start;
	struct rtphdr *rtph;
	struct rtp_new_csrcs *rtph_csrc;
	struct rtp_csrc *new_ssrc;
	struct rtp_csrc_update *new_csrc_update;
	struct rtp_ssrc_item_update *ssrc_item_update;
	enum	rohc_packet_type packet_type;
	bool ps;
	bool is_need_carryed;
	int xi_len,i,m;
	int encode_len = 0;
	int retval = 0;

	packet_type = pkt_info->packet_type;

	rtph_csrc = &pkt_info->rtph_csrc;

	new_csrc_update = &context->update_by_packet;
	ssrc_item_update = new_csrc_update->ssrc_item_update;
	comp_hdr = skb_tail_pointer(comp_skb);
	m = rtph_csrc->cc;
	if(m){
		if(new_csrc_update->item_type_max > 7)
			ps = 1;
		else
			ps = 0;
		xi_len = rtp_csrc_cal_xi_table_len(m,ps);
	}
	/*field.1 : PS and cc*/
	*comp_hdr = (ps << 4) | (m & 0xf);
	encode_len++;
	comp_hdr++;
	if(!m)
		goto out;
	item_start = comp_hdr + xi_len;
	encode_len += xi_len;
	for(i = 0 ; i < m;i++){
		new_ssrc = &rtph_csrc->rtp_csrcs[i];
		is_need_carryed = rtp_ssrc_item_need_carry(&ssrc_item_update[new_ssrc->item_type],packet_type);
		if(ps){
			*comp_hdr = (is_need_carryed << 7) | (new_ssrc->item_type & 0x7f);
			comp_hdr++;
		}else{
			if(!(i % 2)){
				*comp_hdr = (is_need_carryed << 7) | ((new_ssrc->item_type & 0x7) << 4);
			}else{
				(*comp_hdr) |= (is_need_carryed << 3) | (new_ssrc->item_type & 0x7);
				comp_hdr++;
			}
		}
		if(is_need_carryed){
			memcpy(item_start,&new_ssrc->ssrc,4);
			encode_len += 4;
			item_start += 4;
		}
	}
	if(m & 1){
		//add padding
	}
	rohc_pr(ROHC_DRTP,"%s: xi_len=%d,m=%d,encode_len=%d\n",__func__,xi_len,m,encode_len);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return 0;

}

int rtp_csrc_update_context(struct rtp_csrc_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rtp_new_csrcs *rtph_csrc;
	struct rtp_csrc *new_ssrc,*to_ssrc;
	struct last_comped_rtph_csrcs *csrc_ref;
	int ssrc_num,i;
	int retval = 0;

	rtph_csrc = &pkt_info->rtph_csrc;
	csrc_ref = &context->csrc_ref;
	ssrc_num = rtph_csrc->cc;
	csrc_ref->cc = ssrc_num;
	for(i = 0 ; i < ssrc_num;i++){
		new_ssrc = &rtph_csrc->rtp_csrcs[i];
		to_ssrc = &csrc_ref->rtp_csrcs[i];
		memcpy(to_ssrc,new_ssrc,sizeof(struct rtp_csrc));
	}
	context->is_first_packet = false;
	return retval;
}
int rtp_csrc_init_context(struct rtp_csrc_context *csrc_context)
{
	struct ssrc_item_generic *item_generic;
	int i;
	csrc_context->item_bitmap = kcalloc(BITS_TO_LONGS(SSRC_ITEM_GENERIC_MAX + 1),sizeof(unsigned long),GFP_ATOMIC);
	if(!csrc_context->item_bitmap){
		pr_err("%s : alloc item map field\n",__func__);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&csrc_context->item_active_list);
	for(i = 0 ; i < SSRC_ITEM_GENERIC_MAX;i++){
		item_generic = &csrc_context->ssrc_items[i];
		item_generic->item_type = i;
		INIT_LIST_HEAD(&item_generic->list);
	}
	csrc_context->is_first_packet = true;
	return 0;
}
