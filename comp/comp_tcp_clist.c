/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	Date   :	2020-04-02
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
#include <net/tcp.h>

#include "../rohc_common.h"
#include "../rohc_profile.h"
#include "../rohc_cid.h"
#include "../rohc_bits_encode.h"
#include "../rohc_packet.h"
#include "../rohc_feedback.h"
#include "../lsb.h"
#include "../profile/tcp_packet.h"
#include "../profile/tcp_profile.h"

#include "rohc_comp.h"
#include "rohc_comp_wlsb.h"
#include "comp_tcp_clist.h"

void tcp_option_destroy_context(struct tcph_option_context *opt_context)
{
	kfree(opt_context->item_generic_bitmap);
	comp_wlsb_destroy(opt_context->ts_wlsb);
	comp_wlsb_destroy(opt_context->tsecho_wlsb);
}
void tcph_option_update_context(struct tcph_option_context *opt_context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,u32 msn)
{
	u8 *opt_start;
	struct tcphdr *tcph;
	struct	tcph_option *from,*to;
	struct tcph_carryed_options *new_tcph_options;
	struct last_tcph_carryed_options *tcph_opts_ref;
	struct tcph_options_update *new_opts_update;
	int i,opt_len;
	tcph_opts_ref = &opt_context->tcph_opts_ref;
	new_opts_update = &opt_context->opts_update_by_packet;
	new_tcph_options = &pkt_info->tcph_options;
	tcph = tcp_hdr(skb);
	opt_len = (tcph->doff * 4) - sizeof(struct tcphdr);
	opt_start = (u8 *)(tcph + 1);
	if(opt_len)
		memcpy(tcph_opts_ref->opt_buff,opt_start,opt_len);
	for( i = 0 ; i < new_tcph_options->opt_num;i++){
		from = &new_tcph_options->tcp_options[i];
		to = &tcph_opts_ref->tcp_options[i];
		memcpy(to,from,sizeof(struct tcph_option));
	}
	tcph_opts_ref->opt_num = new_tcph_options->opt_num;
	if(new_opts_update->ts_carryed){
		comp_wlsb_add(opt_context->ts_wlsb,NULL,msn,new_opts_update->tsval);
		comp_wlsb_add(opt_context->tsecho_wlsb,NULL,msn,new_opts_update->tsecho);
	}
	opt_context->is_first_packet = false;
}
int tcp_option_init_context(struct tcph_option_context *opt_context,int oa_max)
{
	struct	item_generic *item_g;
	int i,retval;
	opt_context->item_generic_bitmap = kcalloc(BITS_TO_LONGS(ROHC_TCP_OPT_GENERIC_MAX + 1),sizeof(unsigned long),GFP_ATOMIC);
	if(!opt_context->item_generic_bitmap){
		pr_err("alloc memeroy for option item generic bitmap failed\n");
		retval = -ENOMEM;
		goto out;
	}
	opt_context->ts_wlsb = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(opt_context->ts_wlsb)){
		pr_err("alloc wlsb for timestample failed\n");
		retval = -ENOMEM;
		goto err1;
	}
	opt_context->tsecho_wlsb = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(opt_context->tsecho_wlsb)){
		pr_err("alloc wlsb for ts echo failed\n");
		retval = -ENOMEM;
		goto err2;
	}
	INIT_LIST_HEAD(&opt_context->item_generic_active_list);
	for(i = 0 ; i < ROHC_TCP_OPT_GENERIC_MAX ; i++ ){
		item_g = &opt_context->item_generics[i];
		item_g->type = ROHC_TCP_ITEM_GENERIC7 + i;
		INIT_LIST_HEAD(&item_g->list);
	}
	opt_context->is_first_packet = true;
	return 0;
err2:
	comp_wlsb_destroy(opt_context->ts_wlsb);
err1:
	kfree(opt_context->item_generic_bitmap);
out:
	return retval;
}
static inline void tcp_option_to_generic(struct tcph_option_context *opt_context,struct tcph_option *new_opt)
{
	struct last_tcph_carryed_options *opts_ref;
	struct tcph_option *old_opt;
	struct item_generic *new_item_genric;
	int i,free;
	bool	found = false;
	opts_ref = &opt_context->tcph_opts_ref;
	for(i = 0 ; i < opts_ref->opt_num ;i++){
		old_opt = &opts_ref->tcp_options[i];
		if(old_opt->kind == new_opt->kind){
			new_opt->item_type = old_opt->item_type;
			new_item_genric = &opt_context->item_generics[old_opt->item_type - ROHC_TCP_ITEM_GENERIC7];
			list_move(&new_item_genric->list,&opt_context->item_generic_active_list);
			found = true;
		}
	}
	if(!found){
		free = find_first_zero_bit(opt_context->item_generic_bitmap,ROHC_TCP_OPT_GENERIC_MAX + 1);
		if(free > ROHC_TCP_OPT_GENERIC_MAX){
			rohc_pr(ROHC_DTCP,"can't find a free generic item for tcp option : %d\n",new_opt->kind);
			/*use the item that is not update long time.
			*/
			new_item_genric = list_last_entry(&opt_context->item_generic_active_list,struct item_generic,list);
			list_del_init(&new_item_genric->list);	
		}else
			new_item_genric = &opt_context->item_generics[free];	
	
		list_add(&new_item_genric->list,&opt_context->item_generic_active_list);
		new_opt->item_type = new_item_genric->type;
	}

}
static inline void tcp_option_kind_to_item(struct tcph_option_context *opt_context,struct tcph_option *new_opt)
{
	
	struct item_generic *new_item_genric;
	enum	rohc_tcp_item_type item_type;
	int i;

	switch(new_opt->kind){
		case	TCPOPT_NOP:
			new_opt->item_type = ROHC_TCP_ITEM_NOP;
			break;
		case	TCPOPT_EOL:
			new_opt->item_type = ROHC_TCP_ITEM_EOL;
			break;
		case	TCPOPT_MSS:
			new_opt->item_type = ROHC_TCP_ITEM_MSS;
			break;
		case	TCPOPT_WINDOW:
			new_opt->item_type = ROHC_TCP_ITEM_WS;
			break;
		case	TCPOPT_SACK_PERM:
			new_opt->item_type = ROHC_TCP_ITEM_SACK_PERM;
			break;
		case	TCPOPT_SACK:
			new_opt->item_type = ROHC_TCP_ITEM_SACK;
			break;
		case	TCPOPT_TIMESTAMP:
			new_opt->item_type = ROHC_TCP_ITEM_TS;
			break;
		default:
			tcp_option_to_generic(opt_context,new_opt);
			break;
	}

}
#if 0
static inline void tcp_option_kind_to_item(struct tcph_option_context *opt_context,struct tcph_option *new_opt,struct tcph_option *old_opt)
{

	if(new_opt->kind == old_opt->kind){
		new_opt->item_type = old_opt->item_type;
		if()
	}else{
		
	}
}
#endif
static bool tcp_options_list_structrue_update_probe(struct tcph_option_context *opt_context,struct tcph_carryed_options *new_opts,int *structrue_trans_time,struct item_to_index maped[],int oa_max)
{
	struct last_tcph_carryed_options *opts_ref;
	struct	tcph_option *new_opt,*old_opt;
	int i,opts_ref_num;
	bool is_update = false;
	opts_ref = &opt_context->tcph_opts_ref;
	opts_ref_num = opts_ref->opt_num;
	if(opts_ref->opt_num != new_opts->opt_num)
		is_update = true;
	for(i = 0; i < new_opts->opt_num;i++){
		new_opt = &new_opts->tcp_options[i];
		if(i < opts_ref_num){
			old_opt = &opts_ref->tcp_options[i];
			maped[old_opt->item_type].is_maped = true;
			maped[old_opt->item_type].index = i;
			if(new_opt->kind != old_opt->kind)
				is_update = true;
			if(new_opt->kind == old_opt->kind)
				new_opt->item_type = old_opt->item_type;
			else
				tcp_option_kind_to_item(opt_context,new_opt);
		}else
			tcp_option_kind_to_item(opt_context,new_opt);

	}
	/*if last tcp packet has more options
	  */
	for(;i < opts_ref_num ;i++){
		old_opt = &opts_ref->tcp_options[i];
		maped[old_opt->item_type].is_maped = true;
		maped[old_opt->item_type].index = i;
	}
out:
	if(is_update){
		*structrue_trans_time = 0;
	}else if((*structrue_trans_time) < oa_max)
		is_update = true;
	else
		is_update = false;
	return is_update;
}
static inline void tcp_option_static_item_update_probe(struct tcph_option *new_opt,struct tcph_option *old_opt,u8 *tcp_option_start,u8 *tcp_option_ref_buf,struct tcp_item_update *item_update,struct tcp_opt_update_trans_times *item_trans_time,int oa_max)
{

	if(memcmp(new_opt->offset + tcp_option_start,old_opt->offset + tcp_option_ref_buf,new_opt->len)){
		memset(item_trans_time,0,sizeof(struct tcp_opt_update_trans_times));
		item_update->static_update = true;
	}else if(item_trans_time->list_item_trans_times < oa_max)
		item_update->static_update = true;
	else 
		item_update->static_update = false;

}
static inline void tcp_option_cal_ts_bits_encode_set(struct comp_win_lsb *tswlsb,struct comp_win_lsb *tsecho_wlsb,struct tcph_options_update *new_update,u32 tsval,u32 tsecho)
{
	bool ts_can_encode = false;
	bool tsecho_can_encode = false;
	if(comp_wlsb_can_encode_type_uint(tswlsb,7,ROHC_LSB_TCP_TS_K_7_P,tsval)){
		ROHC_ENCODE_BITS_SET(&new_update->tsval_encode_bits,ROHC_ENCODE_BY_BITS(7));
		ts_can_encode = true;
	}else if(comp_wlsb_can_encode_type_uint(tswlsb,14,ROHC_LSB_TCP_TS_K_14_P,tsval)){
		ROHC_ENCODE_BITS_SET(&new_update->tsval_encode_bits,ROHC_ENCODE_BY_BITS(14));
		ts_can_encode = false;
	}else if(comp_wlsb_can_encode_type_uint(tswlsb,21,ROHC_LSB_TCP_TS_K_21_P,tsval)){
		ROHC_ENCODE_BITS_SET(&new_update->tsval_encode_bits,ROHC_ENCODE_BY_BITS(21));
		ts_can_encode  = true;
	}else if(comp_wlsb_can_encode_type_uint(tswlsb,29,ROHC_LSB_TCP_TS_K_29_P,tsval)){
		ROHC_ENCODE_BITS_SET(&new_update->tsval_encode_bits,ROHC_ENCODE_BY_BITS(29));
		ts_can_encode = true;
	}

	if(comp_wlsb_can_encode_type_uint(tsecho_wlsb,7,ROHC_LSB_TCP_TS_K_7_P,tsecho)){
		ROHC_ENCODE_BITS_SET(&new_update->tsecho_encode_bits,ROHC_ENCODE_BY_BITS(7));
		tsecho_can_encode = true;
	}else if(comp_wlsb_can_encode_type_uint(tsecho_wlsb,14,ROHC_LSB_TCP_TS_K_14_P,tsecho)){
		ROHC_ENCODE_BITS_SET(&new_update->tsecho_encode_bits,ROHC_ENCODE_BY_BITS(14));
		tsecho_can_encode = true;
	}else if(comp_wlsb_can_encode_type_uint(tsecho_wlsb,21,ROHC_LSB_TCP_TS_K_21_P,tsecho)){
		ROHC_ENCODE_BITS_SET(&new_update->tsecho_encode_bits,ROHC_ENCODE_BY_BITS(21));
		tsecho_can_encode = true;
	}if(comp_wlsb_can_encode_type_uint(tsecho_wlsb,29,ROHC_LSB_TCP_TS_K_29_P,tsecho)){
		ROHC_ENCODE_BITS_SET(&new_update->tsecho_encode_bits,ROHC_ENCODE_BY_BITS(29));
		tsecho_can_encode = true;
	}
	if(ts_can_encode && tsecho_can_encode)
		new_update->ts_can_encode = true;
}
void tcp_options_update_probe(struct tcph_option_context *opt_context,struct rohc_comp_packet_hdr_info *pkt_info,int oa_max,bool ack_seq_update)
{
	struct sk_buff *skb;
	struct tcphdr *tcph;
	struct tcph_options_update *opts_new_update;
	struct  tcp_item_update		*item_update;
	struct tcp_opt_update_trans_times *opts_trans_times;
	struct last_tcph_carryed_options *opts_ref;
	struct tcph_carryed_options	 *new_opts;
	struct tcph_option *new_opt,*old_opt;
	u8 *tcp_option_start;
	u8 *tcp_option_ref_buf;
	int i;

	enum rohc_tcp_item_type item_type;
	enum rohc_tcp_item_type item_follow = 0;
	struct item_to_index item_map[ROHC_TCP_ITEM_MAX] = {[0 ... ROHC_TCP_ITEM_MAX - 1] = {0}};
	bool is_content_update_not_defined_in_irr = false;
	skb = pkt_info->skb;
	
	opts_new_update = &opt_context->opts_update_by_packet;
	memset(opts_new_update,0,sizeof(struct tcph_options_update));
	opts_ref = &opt_context->tcph_opts_ref;
	opts_trans_times = opt_context->update_trans_times;
	new_opts = &pkt_info->tcph_options;
	item_update = opts_new_update->item_update;
	tcph = tcp_hdr(skb);
	tcp_option_start = (const u8 *)(tcph + 1);
	tcp_option_ref_buf = (const u8 *)opts_ref->opt_buff;
	//if(opt_context->is_first_packet)
	opts_new_update->list_structure_update = tcp_options_list_structrue_update_probe(opt_context,new_opts,&opt_context->list_structure_update_trans_time,item_map,oa_max);
	for(i = 0 ; i < new_opts->opt_num; i++){
		new_opt = &new_opts->tcp_options[i];
		item_type = new_opt->item_type;
		if(item_type > item_follow)
			item_follow = item_type;
		switch(item_type){
			case	ROHC_TCP_ITEM_WS:
				if(item_map[item_type].is_maped){
					old_opt = &opts_ref->tcp_options[item_map[item_type].index];
					tcp_option_static_item_update_probe(new_opt,old_opt,tcp_option_start,tcp_option_ref_buf,&item_update[item_type],&opts_trans_times[item_type],oa_max);
				}else{
					memset(&opts_trans_times[item_type],0,sizeof(struct tcp_opt_update_trans_times));
					item_update[item_type].static_update = true;
				}
				break;
			case ROHC_TCP_ITEM_MSS:
				if(item_map[item_type].is_maped){
					old_opt = &opts_ref->tcp_options[item_map[item_type].index];
					tcp_option_static_item_update_probe(new_opt,old_opt,tcp_option_start,tcp_option_ref_buf,&item_update[item_type],&opts_trans_times[item_type],oa_max);
				}else{
					memset(&opts_trans_times[item_type],0,sizeof(struct tcp_opt_update_trans_times));
					item_update[item_type].static_update = true;
				}

				break;
			case	ROHC_TCP_ITEM_TS:
				opts_new_update->tsval = ntohl(*((u32 *)(tcp_option_start + new_opt->offset + 2)));
				opts_new_update->tsecho = ntohl(*((u32 *)(tcp_option_start + new_opt->offset + 6)));
				tcp_option_cal_ts_bits_encode_set(opt_context->ts_wlsb,opt_context->tsecho_wlsb,opts_new_update,opts_new_update->tsval,opts_new_update->tsecho);
				opts_new_update->ts_carryed = true;
				if(opts_new_update->ts_can_encode){
					item_update[item_type].dynamic_update = true;
					
				}else{
					item_update[item_type].static_update = true;
				}
				break;
			case	ROHC_TCP_ITEM_SACK:
				if(item_map[item_type].is_maped){
					old_opt = &opts_ref->tcp_options[item_map[item_type].index];
					if(ack_seq_update || (new_opt->len != old_opt->len) || (memcmp(tcp_option_start + new_opt->offset,tcp_option_ref_buf + old_opt->offset,new_opt->len))){
						item_update[item_type].dynamic_update = true;
						opts_trans_times[item_type].irr_chain_trans_times = 0;
					}else if(opts_trans_times[item_type].irr_chain_trans_times < oa_max)
						item_update[item_type].dynamic_update = true;
					else
						item_update[item_type].dynamic_update = false;
				}else{
					memset(&opts_trans_times[item_type],0,sizeof(struct tcp_opt_update_trans_times));
					item_update[item_type].static_update = true;
				}
			case	ROHC_TCP_ITEM_EOL:
				if(item_map[item_type].is_maped){
					old_opt = &opts_ref->tcp_options[item_map[item_type].index];
					if(new_opt->len != old_opt->len){
						item_update[item_type].static_update = true;
						opts_trans_times[item_type].list_item_trans_times = 0;
					}else if(opts_trans_times[item_type].list_item_trans_times < oa_max)
						item_update[item_type].static_update = true;
					else
						item_update[item_type].static_update = false;
				}else{
					memset(&opts_trans_times[item_type],0,sizeof(struct tcp_opt_update_trans_times));
					item_update[item_type].static_update = true;
				}
				break;
			case ROHC_TCP_ITEM_NOP:
				break;
			default:
				if(item_map[item_type].is_maped){
					old_opt = &opts_ref->tcp_options[item_map[item_type].index];
					if((new_opt->kind != old_opt->kind) || (new_opt->len != old_opt->len)){
						item_update[item_type].static_update = true;
						opts_trans_times[item_type].list_item_trans_times = true;
					}else if(opts_trans_times[item_type].list_item_trans_times < oa_max)
						item_update[item_type].static_update = true;
					else{
						item_update[item_type].static_update = false;
						if(memcmp(tcp_option_start + new_opt->offset  , tcp_option_ref_buf + old_opt->offset,new_opt->len)){
							item_update[item_type].dynamic_update = true;
							opts_trans_times[item_type].irr_chain_trans_times = 0;

						}else if(opts_trans_times[item_type].irr_chain_trans_times < oa_max)
							item_update[item_type].dynamic_update = true;
						else
							item_update[item_type].dynamic_update = false;
					}
				}else{
					memset(&opts_trans_times[item_type],0,sizeof(struct tcp_opt_update_trans_times));
					item_update[item_type].static_update = true;
				}
				break;
					
		}
		if(item_update[item_type].static_update){
			rohc_pr(ROHC_DTCP,"item_type : %d ,static_update\n",item_type);
			is_content_update_not_defined_in_irr = true;
		}
	}
	opts_new_update->item_type_max = item_follow;
	opts_new_update->content_update_not_defined_in_irr = is_content_update_not_defined_in_irr;
}

static inline int tcp_options_cal_xi_table_len(int m,bool ps)
{
	int xi_len;
	if(ps)
		xi_len = m;
	else
		xi_len = (m + 1) / 2;

	return xi_len;
}

static inline bool tcp_option_item_need_carry(struct tcp_item_update *item_update,enum rohc_packet_type packet_type)
{
	bool is_need  = false;
	if(rohc_packet_is_covered_by_crc8(packet_type) || item_update->static_update)
		is_need = true;
	return is_need;
}



int rohc_comp_tcp_options_analyze(const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{

	u8 *opt_start;
	struct tcphdr *tcph;
	struct tcph_carryed_options *new_opts;
	struct tcph_option *new_opt;
	u8 kind;
	int opt_num;
	int len;
	int offset;
	int opt_len;
	int retval = 0;
	tcph = tcp_hdr(skb);
	new_opts = &pkt_info->tcph_options;
	opt_start = (u8 *)(tcph + 1);
	len = (tcph->doff * 4) - sizeof(struct tcphdr);
	opt_num = 0;
	offset = 0;
	while(len > 0){
		new_opt = &new_opts->tcp_options[opt_num];
		kind = *opt_start;
		new_opt->kind = kind;
		rohc_pr(ROHC_DTCP,"opt_num %d,kind %d,len=%d\n",opt_num,kind,len);
		switch(kind){
			case TCPOPT_EOL:
				new_opt->len = len;
				new_opt->offset = offset;
				opt_num++;
				goto out;
			case TCPOPT_NOP:
				opt_len = 1;
				break;
			default:
				opt_len = *(opt_start + 1);
				break;
		}
		new_opt->len = opt_len;
		opt_num++;
		new_opt->offset = offset;
		offset += opt_len;
		len -= opt_len;
		opt_start += opt_len;
	}
out:
	new_opts->opt_num = opt_num;
	if(opt_num > ROHC_TCP_COMP_LIST_MAX){
		rohc_pr(ROHC_DTCP,"tcp header carry options more than 15 ,so can't support TCP profile");
		retval = -EFAULT;
	}else{
		rohc_pr(ROHC_DTCP,"befor len=%d,opt_num = %d\n",pkt_info->to_comp_pkt_hdr_len,opt_num);
		pkt_info->to_comp_pkt_hdr_len += ((tcph->doff * 4) - sizeof(struct tcphdr));
		rohc_pr(ROHC_DTCP,"after len=%d,off = %d,len = %d\n",pkt_info->to_comp_pkt_hdr_len,tcph->doff * 4 - sizeof(struct tcphdr),len);
		retval = 0;
	}
	return retval;
}

int tcp_option_build_item_nop(struct tcph_option_context *opt_context,u8 *to,struct tcph_option *tcp_option,const struct sk_buff *skb,int *build_len)
{
	*build_len = 0;
	return 0;
}


static int tcp_option_build_item_eol(struct tcph_option_context *opt_context,u8 *to,struct tcph_option *tcp_option,const struct sk_buff *skb,int *build_len)
{
	*to = (tcp_option->len - 1) * 8;
	*build_len = 1;
	return 0;
}

static int tcp_option_build_item_mss(struct tcph_option_context *opt_context,u8 *to,struct tcph_option *tcp_option,const struct sk_buff *skb,int *build_len)
{
	u8 *from;
	from = (u8 *)(tcp_hdr(skb) + 1);
	from += tcp_option->offset + 2;
	*(u16 *)to = *((u16 *)from);
	*build_len = 2;
	return 0;
}

static int tcp_option_build_item_ws(struct tcph_option_context *opt_context,u8 *to,struct tcph_option *tcp_option,const struct sk_buff *skb,int *build_len)
{
	u8 *from;
	from = (u8 *)(tcp_hdr(skb) + 1);
	from += tcp_option->offset + 2;
	*to = *from;
	*build_len = 1;
	return 0;
}

static int tcp_option_build_item_ts(struct tcph_option_context *opt_context,u8 *to,struct tcph_option *tcp_option,const struct sk_buff *skb,int *build_len)
{
	u8 *from;
	u32 ts;
	u32 tsecho;
	from = (u8 *)(tcp_hdr(skb) + 1);
	from += tcp_option->offset + 2;
	/*carryed in network byte order.*/
	ts = *(u32 *)from;
	(*(u32 *)to) = ts;
	to += 4;
	from += 4;
	tsecho = *(u32 *)from;
	*(u32 *)to = tsecho;
	*build_len = 8;
	return 0;
}

int tcp_option_build_item_sackperm(struct tcph_option_context *opt_context,u8 *to,struct tcph_option *tcp_option,const struct sk_buff *skb,int *build_len)
{
	*build_len = 0;
	return 0;
}

static void tcp_option_sack_pure_lsb(u8 *to,u32 ref,u32 sack_field,int *build_len)
{
	u32 off;
	off = sack_field - ref;
	if(off <= 0x7fff){
		*to = (off >> 8) & 0x7f;
		to++;
		*to = off & 0xff;
		*build_len = 2;
	}else if(off <= 0x3fffff){
		*to = SACK_LSB_10 | ((off >> 16) & 0x3f);
		to++;
		*to = off >> 8;
		to++;
		*to = off;
		*build_len = 3;
	}else if(off <= 0x1fffffff){
		*to = SACK_LSB_110 | ((off >> 24) & 0x1f);
		to++;
		*to = off >> 16;
		to++;
		*to = off >> 8;
		to++;
		*to = off;
		*build_len = 4;
	}else{
		*to = SACK_LSB_FULL;
		to++;
		*to = off >> 24;
		to++;
		*to = off >> 16;
		to++;
		*to = off >> 8;
		to++;
		*to = off;
		*build_len = 5;
	}
}
static void tcp_option_sack_block_lsb(u32 ref,u32 block_start,u32 block_end,u8 *to,int *build_len)
{
	int len;
	tcp_option_sack_pure_lsb(to,ref,block_start,&len);
	*build_len = len;
	to += len;
	tcp_option_sack_pure_lsb(to,block_start,block_end,&len);
	(*build_len) += len;
}
static int tcp_option_build_item_sack(struct tcph_option_context *opt_context,u8 *to,struct tcph_option *tcp_option,const struct sk_buff *skb,int *build_len)
{
	u8 *from;
	u32 ack_seq,block_start,block_end,ref;
	int blocks,i,block_buid_len;
	int sack_build_len = 0;
	ack_seq = ntohl(tcp_hdr(skb)->ack_seq);
	from = (u8 *)(tcp_hdr(skb) + 1);
	from += tcp_option->offset + TCPOLEN_SACK_BASE;
	blocks = (tcp_option->len - TCPOLEN_SACK_BASE) / TCPOLEN_SACK_PERBLOCK;
	*to = blocks;
	to++;
	sack_build_len++;
	ref = ack_seq;
	for(i = 0 ; i < blocks ;i++,ref = block_end){
		block_start = ntohl(*(u32 *)from);
		block_end = ntohl(*(u32 *)(from + 4));
		from += TCPOLEN_SACK_PERBLOCK;
		tcp_option_sack_block_lsb(ref,block_start,block_end,to,&block_buid_len);
		to += block_buid_len;
		sack_build_len += block_buid_len;
	}
	*build_len = sack_build_len;
	return 0;
}

static int tcp_option_build_item_generic(struct tcph_option_context *opt_context,u8 *to,struct tcph_option *tcp_option,const struct sk_buff *skb,int *build_len)
{
	u8 *from;
	from = (u8 *)(tcp_hdr(skb) + 1);
	from += tcp_option->offset + 2;
	*to = tcp_option->kind;
	to++;
	*to = (0 << 7) | (tcp_option->len & 0x7f);
	to++;
	memcpy(to,from,tcp_option->len - 2);
	*build_len = tcp_option->len;
	return 0;
}


static inline void tcp_option_build_ts_lsb(u32 ts_v,struct  rohc_bits_encode_set *bit_set,u8 *to,int *build_len)
{
	enum rohc_sd_vl_type type;
	if(ROHC_ENCODE_BITS_TEST(bit_set,ROHC_ENCODE_BY_BITS(7)))
		type = ROHC_SD_VL_TYPE_0;
	else if(ROHC_ENCODE_BITS_TEST(bit_set,ROHC_ENCODE_BY_BITS(14)))
		type = ROHC_SD_VL_TYPE_10;
	else if(ROHC_ENCODE_BITS_TEST(bit_set,ROHC_ENCODE_BY_BITS(21)))
		type = ROHC_SD_VL_TYPE_110;
	else 
		type = ROHC_SD_VL_TYPE_111;
	rohc_sd_vl_encode(to,build_len,ts_v,type);
}	

static int tcp_option_build_irrchain_ts(struct tcph_option_context *opt_context,u8 *to,struct tcph_option *tcp_option,const struct sk_buff *skb,int *build_len)
{
	u8 *from;
	int ts_build_len;
	struct tcph_options_update *opts_new_update;
	u32 tsval,tsecho;
	opts_new_update = &opt_context->opts_update_by_packet;
	tsval = opts_new_update->tsval;
	tsecho = opts_new_update->tsecho;
	tcp_option_build_ts_lsb(tsval,&opts_new_update->tsval_encode_bits,to,&ts_build_len);
	to += ts_build_len;
	*build_len = ts_build_len;
	tcp_option_build_ts_lsb(tsecho,&opts_new_update->tsecho_encode_bits,to,&ts_build_len);
	(*build_len) += ts_build_len;
	return 0;
}

static int tcp_option_build_irrchain_sack(struct tcph_option_context *opt_context,u8 *to,struct tcph_option *tcp_option,const struct sk_buff *skb,int *build_len)
{
	u8 *from;
	struct tcph_options_update *opts_new_update;
	u32 ack_seq,block_start,block_end,ref;
	int blocks,i,block_buid_len;
	int sack_build_len = 0;
	opts_new_update = &opt_context->opts_update_by_packet;
	ack_seq = ntohl(tcp_hdr(skb)->ack_seq);
	from = (u8 *)(tcp_hdr(skb) + 1);
	from += tcp_option->offset + TCPOLEN_SACK_BASE;
	blocks = (tcp_option->len - TCPOLEN_SACK_BASE) / TCPOLEN_SACK_PERBLOCK;
	if(!opts_new_update->item_update[ROHC_TCP_ITEM_SACK].dynamic_update){
		/*sack unchanged
		 */
		*to = 0;
		*build_len = 1;
		goto out;
	}
	*to = blocks;
	to++;
	sack_build_len++;
	ref = ack_seq;
	for(i = 0 ; i < blocks ;i++,ref = block_end){
		block_start = ntohl(*(u32 *)from);
		block_end = ntohl(*(u32 *)(from + 4));
		from += TCPOLEN_SACK_PERBLOCK;
		tcp_option_sack_block_lsb(ref,block_start,block_end,to,&block_buid_len);
		to += block_buid_len;
		sack_build_len += block_buid_len;
	}
	*build_len = sack_build_len;
out:
	return 0;
}


static int tcp_option_build_irrchain_generic(struct tcph_option_context *opt_context,u8 *to,struct tcph_option *tcp_option,const struct sk_buff *skb,int *build_len)
{
	u8 *from;
	struct tcph_options_update *opts_new_update;
	opts_new_update = &opt_context->opts_update_by_packet;
	from = (u8 *)(tcp_hdr(skb) + 1);
	from += tcp_option->offset + 2;
	if(opts_new_update->item_update[tcp_option->item_type].dynamic_update){
		*to = 0;
		to++;
		memcpy(to,from,tcp_option->len - 2);
		*build_len = 1 + tcp_option->len - 2;
	}else{
		/*that can change,but currently is unchanged*/
		*to = 0xff;
		*build_len = 1;
	}
	return 0;
}

static int tcp_option_build_irrchain_common(struct tcph_option_context *opt_context,u8 *to,struct tcph_option *tcp_option,const struct sk_buff *skb,int *build_len)
{
	*build_len = 0;
	return 0;
}

static const struct tcp_item_table_ops item_ops[ROHC_TCP_ITEM_MAX] = {
	{
		.item_type = ROHC_TCP_ITEM_NOP,
		.build_item = tcp_option_build_item_nop,
		.build_irr_chain = tcp_option_build_irrchain_common,
	},
	{
		.item_type = ROHC_TCP_ITEM_EOL,
		.build_item = tcp_option_build_item_eol,
		.build_irr_chain = tcp_option_build_irrchain_common,
	},
	{
		.item_type = ROHC_TCP_ITEM_MSS,
		.build_item = tcp_option_build_item_mss,
		.build_irr_chain = tcp_option_build_irrchain_common,
	},
	{
		.item_type = ROHC_TCP_ITEM_WS,
		.build_item = tcp_option_build_item_ws,
		.build_irr_chain = tcp_option_build_irrchain_common,
	},
	{
		.item_type = ROHC_TCP_ITEM_TS,
		.build_item = tcp_option_build_item_ts,
		.build_irr_chain = tcp_option_build_irrchain_ts,
	},
	{
		.item_type = ROHC_TCP_ITEM_SACK_PERM,
		.build_item = tcp_option_build_item_sackperm,
		.build_irr_chain = tcp_option_build_irrchain_common,
	},
	{
		.item_type = ROHC_TCP_ITEM_SACK,
		.build_item = tcp_option_build_item_sack,
		.build_irr_chain = tcp_option_build_irrchain_sack,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC7,
		.build_item = tcp_option_build_item_generic,
		.build_irr_chain = tcp_option_build_irrchain_generic,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC8,
		.build_item = tcp_option_build_item_generic,
		.build_irr_chain = tcp_option_build_irrchain_generic,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC9,
		.build_item = tcp_option_build_item_generic,
		.build_irr_chain = tcp_option_build_irrchain_generic,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC10,
		.build_item = tcp_option_build_item_generic,
		.build_irr_chain = tcp_option_build_irrchain_generic,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC11,
		.build_item = tcp_option_build_item_generic,
		.build_irr_chain = tcp_option_build_irrchain_generic,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC12,
		.build_item = tcp_option_build_item_generic,
		.build_irr_chain = tcp_option_build_irrchain_generic,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC13,
		.build_item = tcp_option_build_item_generic,
		.build_irr_chain = tcp_option_build_irrchain_generic,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC14,
		.build_item = tcp_option_build_item_generic,
		.build_irr_chain = tcp_option_build_irrchain_generic,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC15,
		.build_item = tcp_option_build_item_generic,
		.build_irr_chain = tcp_option_build_irrchain_generic,
	}

};


int tcp_options_build_clist(struct tcph_option_context *option_context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *clist_start;
	u8 *item_start;
	struct tcphdr *tcph;
	struct sk_buff *skb;
	struct tcp_opt_update_trans_times *update_trans_times;
	struct tcph_options_update *opts_new_update;
	struct tcph_carryed_options *new_opts;
	struct tcp_item_update *item_new_updates;
	struct tcp_item_update *item_new_update;
	struct tcph_option *new_opt;
	enum rohc_packet_type packet_type;
	bool	item_need_carryed;
	int ps;
	int opt_num;
	int call_len;
	int xi_len;
	int i;
	int clist_len = 0;
	int retval = 0;
	packet_type = pkt_info->packet_type;
	opts_new_update = &option_context->opts_update_by_packet;
	update_trans_times = option_context->update_trans_times;
	item_new_updates = opts_new_update->item_update;
	tcph = &pkt_info->tcph;
	skb = pkt_info->skb;
	new_opts = &pkt_info->tcph_options;
	opt_num = new_opts->opt_num;
	if(opts_new_update->item_type_max > 7)
		ps = 1;
	else
		ps = 0;
	clist_start = skb_tail_pointer(comp_skb);
	/*first byte : 3 bits resved ,one bit ps and 4 bits m */
	*clist_start = (ps << 4) | (opt_num & 0xf);
	clist_start++;
	clist_len++;
	/*next field is XI talbe */
	xi_len = tcp_options_cal_xi_table_len(opt_num,ps);
	item_start = clist_start + xi_len;
	clist_len += xi_len;
	for(i = 0 ; i < opt_num;i++){
		new_opt = &new_opts->tcp_options[i];
		item_new_update = &item_new_updates[new_opt->item_type];
		item_need_carryed = tcp_option_item_need_carry(item_new_update,packet_type);
		rohc_pr(ROHC_DTCP,"item_type:%d,static update:%d,need:%d\n",new_opt->item_type,item_new_update->static_update,item_need_carryed);
		/*fill the xi field*/
		if(ps){
			*clist_start = (!!item_need_carryed << 7) | (new_opt->item_type & 0xf);
			clist_start++;
		}else{
			if(!(i % 2)){
				*clist_start = (item_need_carryed << 7) | ((new_opt->item_type & 0x7) << 4);
			}else{
				(*clist_start) |= (item_need_carryed << 3) | (new_opt->item_type & 0x7);
				clist_start++;
			}
		}
		if(item_need_carryed){
			retval = item_ops[new_opt->item_type].build_item(option_context,item_start,new_opt,skb,&call_len);
			if(retval){
				rohc_pr(ROHC_DTCP," tcp build item-%d failed\n",new_opt->item_type);
				goto out;
			}else
				rohc_pr(ROHC_DTCP,"type %d,call_len %d\n",new_opt->item_type,call_len);

			item_start += call_len;
			clist_len += call_len;
			item_new_update->carryed_by_list = true;
			update_trans_times[new_opt->item_type].list_item_trans_times++;
			update_trans_times[new_opt->item_type].irr_chain_trans_times++;

		}
	}
	if(opt_num & 1){
	/*add pading*/
	}
	option_context->list_structure_update_trans_time++;
out:
	rohc_pr(ROHC_DTCP,"tcp comp list total len is %d,opt_num is %d,xi_len=%d,ps=%d,packet_type=%d\n",clist_len,opt_num,xi_len,ps,packet_type);
	skb_put(comp_skb,clist_len);
	pkt_info->comp_hdr_len += clist_len;
	return retval;
}

int tcp_options_build_irr_chain(struct tcph_option_context *option_context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *irrchain_start;
	struct tcphdr *tcph;
	struct sk_buff *skb;
	struct tcp_opt_update_trans_times *update_trans_times;
	struct tcph_options_update *opts_new_update;
	struct tcph_carryed_options *new_opts;
	struct tcp_item_update *item_new_updates;
	struct tcp_item_update *item_new_update;
	struct tcph_option *new_opt;
	enum rohc_tcp_item_type item_type;
	int opt_num;
	int call_len;
	int i;
	int irrchain_len = 0;
	int retval = 0;
	skb = pkt_info->skb;
	opts_new_update = &option_context->opts_update_by_packet;
	update_trans_times = option_context->update_trans_times;
	new_opts = &pkt_info->tcph_options;
	item_new_updates = opts_new_update->item_update;
	opt_num = new_opts->opt_num;
	irrchain_start = skb_tail_pointer(comp_skb);
	for(i = 0;i < opt_num;i++){
		new_opt = &new_opts->tcp_options[i];
		item_type = new_opt->item_type;
		item_new_update = &item_new_updates[item_type];
		if(item_new_update->carryed_by_list)
			continue;
		switch(item_type){
			case	ROHC_TCP_ITEM_MSS:
			case	ROHC_TCP_ITEM_SACK_PERM:
			case	ROHC_TCP_ITEM_EOL:
			case	ROHC_TCP_ITEM_NOP:
			case	ROHC_TCP_ITEM_WS:
				break;
			default:
					retval = item_ops[item_type].build_irr_chain(option_context,irrchain_start,new_opt,skb,&call_len);
					if(retval){
						rohc_pr(ROHC_DTCP,"tcp build irr chian failed for item-%d\n",item_type);
						retval = -EFAULT;
						goto out;
					}
					if(item_new_update->dynamic_update)
						update_trans_times[item_type].irr_chain_trans_times++;
					irrchain_len += call_len;
					irrchain_start += call_len;
				break;

		}
	}
out:
	skb_put(comp_skb,irrchain_len);
	pkt_info->comp_hdr_len += irrchain_len;
	return retval;
}

