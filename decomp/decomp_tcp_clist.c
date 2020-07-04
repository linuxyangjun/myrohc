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
#include <net/tcp.h>
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
#include "../lsb.h"
#include "../rohc_bits_encode.h"
#include "../profile/tcp_profile.h"
#include "rohc_decomp_wlsb.h"
#include "decomp_tcp_clist.h"
#include "rohc_decomp.h"

static inline int tcp_options_cal_xi_table_len(int m,bool ps)
{
	int xi_len;
	if(ps)
		xi_len = m;
	else
		xi_len = (m + 1) / 2;

	return xi_len;
}





int tcp_option_rebuild(struct decomp_tcph_options_context *opt_context,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info,int *option_total_len)
{
	u8 *opts_to;
	struct tcp_decode_options *opts_decode;
	opts_decode = &opt_context->update_by_packet.decode_options;

	if(!opts_decode->opt_num){
		*option_total_len = 0;
		return 0;
	}
	opts_to = skb_tail_pointer(decomp_skb);
	memcpy(opts_to,opts_decode->opt_buff,opts_decode->opt_total_len);
	skb_put(decomp_skb,opts_decode->opt_total_len);
	pkt_info->rebuild_hdr_len += opts_decode->opt_total_len;
	*option_total_len = opts_decode->opt_total_len;
	rohc_pr(ROHC_DTCP,"tcp option length is %d\n",*option_total_len);
	return 0;
}
int tcp_option_analyze_item_nop(struct decomp_tcph_options_context *opt_context,u8 *from,struct tcp_analyze_item *item,int *analyze_len)
{
	*analyze_len = 0;
	item->kind = TCPOPT_NOP;
	item->len = 1;
	return 0;
}

int tcp_option_analyze_item_sackperm(struct decomp_tcph_options_context *opt_context,u8 *from,struct tcp_analyze_item *item,int *analyze_len)
{
	*analyze_len = 0;
	return 0;
}

int tcp_option_analyze_item_eol(struct decomp_tcph_options_context *opt_context,u8 *from,struct tcp_analyze_item *item,int *analyze_len)
{
	 item->len = ((*from) / 8) + 1;
	 item->kind = TCPOPT_EOL;
	*analyze_len = 1;
	return 0;
}

int tcp_option_analyze_item_mss(struct decomp_tcph_options_context *opt_context,u8 *from,struct tcp_analyze_item *item,int *analyze_len)
{
	u16 mss_v;
	struct wlsb_analyze_field *mss;
	mss = &item->item_field;
	mss_v = *(u16 *)from;
	decomp_wlsb_fill_analyze_field(mss,mss_v,16,false);
	*analyze_len = 2;
	return 0;
}

int tcp_option_analyze_item_ws(struct decomp_tcph_options_context *opt_context,u8 *from,struct tcp_analyze_item *item,int *analyze_len)
{
	struct wlsb_analyze_field *ws;
	ws = &item->item_field;
	decomp_wlsb_fill_analyze_field(ws,*from,8,false);
	*analyze_len = 1;
	return 0;
}

int tcp_option_analyze_item_ts(struct decomp_tcph_options_context *opt_context,u8 *from,struct tcp_analyze_item *item,int *analyze_len)
{
	u32 *ts_v,*tsecho_v;
	struct wlsb_analyze_field *ts,*tsecho;
	ts = &item->item_fields[0];
	tsecho = &item->item_fields[1];
	/*network byte order*/
	ts_v = (u32 *)from;
	decomp_wlsb_fill_analyze_field(ts,*ts_v,32,false);
	from += 4;
	tsecho_v = (u32 *)from;
	decomp_wlsb_fill_analyze_field(tsecho,*tsecho_v,32,false);
	*analyze_len = 8;
	return 0;
}


static void tcp_option_analyze_sack_pure_lsb(u8 *from,struct wlsb_analyze_field *sack_field,int *analyze_len)
{
	int len;
	u32 encode_v;
	u32 encode_bits;
	if(*from == SACK_LSB_FULL){
		from++;
		encode_v = *from;
		from++;
		encode_v = (encode_v << 8) | (*from);
		from++;
		encode_v = (encode_v << 8) | (*from);
		from++;
		encode_v = (encode_v << 8) | (*from);
		len = 5;
		encode_bits = 32;
	}else if(!BYTE_BIT_7(*from)){

		encode_v = BYTE_BITS_7(*from,0);
		from++;
		encode_v = (encode_v << 8) | (*from);
		len = 2;
		encode_bits = 15;
	}else if(BYTE_BITS_6_7(*from) == SACK_LSB_10){
		encode_v = BYTE_BITS_6(*from,0);
		from++;
		encode_v = (encode_v << 8) | (*from);
		from++;
		encode_v = (encode_v << 8) | (*from);
		len = 3;
		encode_bits = 22;
	}else{
		encode_v = BYTE_BITS_5(*from,0);
		from++;
		encode_v = (encode_v << 8) | (*from);
		from++;
		encode_v = (encode_v << 8) | (*from);
		from++;
		encode_v = (encode_v << 8) | (*from);
		len = 4;
		encode_bits = 29;
	}
	decomp_wlsb_fill_analyze_field(sack_field,encode_v,encode_bits,true);
	*analyze_len = len;
}
static void tcp_option_analyze_block_sack(u8 *from,struct wlsb_analyze_field *block_start,struct wlsb_analyze_field *block_end,int *analyze_len)
{
	int len;
	tcp_option_analyze_sack_pure_lsb(from,block_start,&len);
	from += len;
	*analyze_len = len;
	tcp_option_analyze_sack_pure_lsb(from,block_end,&len);
	(*analyze_len) += len;
}
int tcp_option_analyze_item_sack(struct decomp_tcph_options_context *opt_context,u8 *from,struct tcp_analyze_item *item,int *analyze_len)
{
	struct wlsb_analyze_field *start_off,*end_off;

	int block_len,sack_analyze_len;
	int blocks,i;
	blocks = *from;
	from++;
	sack_analyze_len = 1;
	for(i = 0 ; i < blocks;i++){
		start_off = &item->item_fields[i * 2];
		end_off = &item->item_fields[i * 2 + 1];
		tcp_option_analyze_block_sack(from,start_off,end_off,&block_len);
		from += block_len;
		sack_analyze_len += block_len;
	}
	*analyze_len = sack_analyze_len;
	item->field_num = blocks * 2;
	return 0;
}


int tcp_option_analyze_item_generic(struct decomp_tcph_options_context *opt_context,u8 *from,struct tcp_analyze_item *item,int *analyze_len)
{
	struct analyze_vl_field *generic_filed;
	generic_filed = &item->item_vl_field;
	item->kind = *from;
	from++;
	item->is_static = !!BYTE_BIT_7(*from);
	item->len = BYTE_BITS_7(*from,0);
	from++;
	decomp_fill_analyze_vl_field(generic_filed,from,item->len - 2);
	*analyze_len = item->len;
	return 0;
}

static inline void tcp_option_analyze_ts_lsb(u8 *from,struct wlsb_analyze_field *ts,int *analyze_len)
{
	u32 encode_v,encode_bits;
	int encode_p;
	int encode_len;
	rohc_sd_vl_decode(from,&encode_len,&encode_v);
	switch(encode_len){
		case 1:
			encode_bits = 7;
			encode_p = ROHC_LSB_TCP_TS_K_7_P;
			break;
		case 2:
			encode_bits = 14;
			encode_p = ROHC_LSB_TCP_TS_K_14_P;
			break;
		case 3:
			encode_bits = 21;
			encode_p = ROHC_LSB_TCP_TS_K_21_P;
			break;
		case 4:
			encode_bits = 29;
			encode_p = ROHC_LSB_TCP_TS_K_29_P;
			break;
		default:
			pr_err("%s : not support var len:%d\n",__func__,encode_len);
	}
	decomp_wlsb_fill_analyze_field_contain_p(ts,encode_v,encode_bits,encode_p,true);
	*analyze_len = encode_len;

}

int tcp_option_analyze_irrchain_ts(struct decomp_tcph_options_context *opt_context,u8 *from,struct tcp_analyze_item *item,int *analyze_len)
{
	struct wlsb_analyze_field *ts,*tsecho;
	int ts_analyze_len;
	ts = &item->item_fields[0];
	tsecho = &item->item_fields[1];
	tcp_option_analyze_ts_lsb(from,ts,&ts_analyze_len);
	from += ts_analyze_len;
	*analyze_len = ts_analyze_len;
	tcp_option_analyze_ts_lsb(from,tsecho,&ts_analyze_len);
	(*analyze_len) += ts_analyze_len;
	return 0;
}

int tcp_option_analyze_irrchain_sack(struct decomp_tcph_options_context *opt_context,u8 *from,struct tcp_analyze_item *item,int *analyze_len)
{
	struct wlsb_analyze_field *start_off,*end_off;
	int blocks,i;
	int sack_analyze_len,block_len;
	blocks = *from;
	from++;
	sack_analyze_len = 1;
	item->field_num = blocks  * 2;
	for(i = 0;i < blocks;i++){
		start_off = &item->item_fields[i * 2];
		end_off = &item->item_fields[i * 2 + 1];
		tcp_option_analyze_block_sack(from,start_off,end_off,&block_len);
		from += block_len;
		sack_analyze_len += block_len;
	}
	*analyze_len = sack_analyze_len;
	return 0;
}

int tcp_option_analyze_irrchain_generic(struct decomp_tcph_options_context *opt_context,u8 *from,struct tcp_analyze_item *analyze_item,int *analyze_len)
{
	struct item_to_index *map;
	struct last_decomped_tcp_options *opts_ref;
	struct tcph_option *old_opt;
	struct analyze_vl_field *generic_filed;
	generic_filed = &analyze_item->item_vl_field;
	if(!analyze_item->len){
		/*compressed list is carryed,but not in the compressed list,include in the irregular list,so we need to get the length from last packet*/
		opts_ref = &opt_context->tcp_opt_ref;
		map = &opts_ref->last_map[analyze_item->item_type];
		old_opt = &opts_ref->tcp_options[map->index];
		analyze_item->len = old_opt->len;
		analyze_item->kind = old_opt->kind;
	}
	if(!(*from)){
		from++;
		decomp_fill_analyze_vl_field(generic_filed,from,analyze_item->len - 2);
		*analyze_len = analyze_item->len - 2 + 1;
	}else
		*analyze_len = 1;
	return 0;
}
int tcp_option_analyze_irrchain_common(struct decomp_tcph_options_context *opt_context,u8 *from,struct tcp_analyze_item *item,int *analyze_len)
{
	*analyze_len = 0;
	return 0;
}

int tcp_decode_option_nop(struct decomp_tcph_options_context *opt_context,struct tcp_analyze_item *analyze_item,const struct tcphdr *tcph)
{
	u8 *to;
	struct item_to_index *map;
	struct tcp_decode_options *decode_opts;
	struct tcph_option *new_opt;
	decode_opts = &opt_context->update_by_packet.decode_options;
	new_opt = &decode_opts->tcp_options[decode_opts->opt_num];
	map = &decode_opts->new_map[ROHC_TCP_ITEM_NOP];
	map->is_maped = true;
	map->index = decode_opts->opt_num;

	to = decode_opts->opt_buff + decode_opts->opt_total_len;
	new_opt->offset = decode_opts->opt_total_len;
	new_opt->kind = TCPOPT_NOP;
	new_opt->item_type = ROHC_TCP_ITEM_NOP;
	new_opt->len = 1;
	*to = TCPOPT_NOP;
	decode_opts->opt_total_len += new_opt->len;
	decode_opts->opt_num++;
	return 0;
}

int tcp_decode_option_sackperm(struct decomp_tcph_options_context *opt_context,struct tcp_analyze_item *analyze_item,const struct tcphdr *tcph)
{
	u8 *to;
	struct item_to_index *map;
	struct tcp_decode_options *decode_opts;
	struct tcph_option *new_opt;
	decode_opts = &opt_context->update_by_packet.decode_options;
	new_opt = &decode_opts->tcp_options[decode_opts->opt_num];
	map = &decode_opts->new_map[ROHC_TCP_ITEM_SACK_PERM];
	map->is_maped = true;
	map->index = decode_opts->opt_num;

	to = decode_opts->opt_buff + decode_opts->opt_total_len;
	new_opt->offset = decode_opts->opt_total_len;
	new_opt->kind = TCPOPT_SACK_PERM;
	new_opt->item_type = ROHC_TCP_ITEM_SACK_PERM;
	new_opt->len = 2;
	*to = TCPOPT_SACK_PERM;
	to++;
	*to = new_opt->len;
	decode_opts->opt_total_len += new_opt->len;
	decode_opts->opt_num++;
	return 0;
}

int tcp_decode_option_eol(struct decomp_tcph_options_context *opt_context,struct tcp_analyze_item *analyze_item,const struct tcphdr *tcph)
{
	u8 *to;
	struct item_to_index *map,*old_map;
	struct last_decomped_tcp_options *opts_ref;
	struct tcp_decode_options *decode_opts;
	struct tcph_option *new_opt,*old_opt;
	decode_opts = &opt_context->update_by_packet.decode_options;

	new_opt = &decode_opts->tcp_options[decode_opts->opt_num];
	map = &decode_opts->new_map[ROHC_TCP_ITEM_EOL];
	map->is_maped = true;
	map->index = decode_opts->opt_num;

	to = decode_opts->opt_buff + decode_opts->opt_total_len;
	new_opt->offset = decode_opts->opt_total_len;
	new_opt->kind = TCPOPT_EOL;
	new_opt->item_type = ROHC_TCP_ITEM_EOL;
	if(!analyze_item->len){
		/*compressed list is carryed,but the eol item isn't carryed in the list,so we must get the length from last packet*/
		opts_ref = &opt_context->tcp_opt_ref;
		old_map = &opts_ref->last_map[ROHC_TCP_ITEM_EOL];
		BUG_ON(!old_map->is_maped);
		old_opt = &opts_ref->tcp_options[old_map->index];
		analyze_item->len = old_opt->len;
	}
	new_opt->len = analyze_item->len;
	*to  = TCPOPT_EOL;
	decode_opts->opt_total_len += new_opt->len;
	decode_opts->opt_num++;
	/*clear the memery after eol when has pading after eol*/
	to++;
	memset(to,0,new_opt->len - 1);

	return 0;
}

int tcp_decode_option_mss(struct decomp_tcph_options_context *opt_context,struct tcp_analyze_item *analyze_item,const struct tcphdr *tcph)
{
	u8 *to,*ref;
	struct item_to_index *map,*old_map;
	struct last_decomped_tcp_options *opts_ref;
	struct tcp_decode_options *decode_opts;
	struct tcph_option *new_opt,*old_opt;
	struct wlsb_analyze_field *mss;
	u16 mss_v;
	decode_opts = &opt_context->update_by_packet.decode_options;
	opts_ref = &opt_context->tcp_opt_ref;

	mss = &analyze_item->item_field;

	new_opt = &decode_opts->tcp_options[decode_opts->opt_num];
	map = &decode_opts->new_map[ROHC_TCP_ITEM_MSS];
	map->is_maped = true;
	map->index = decode_opts->opt_num;
	to = decode_opts->opt_buff + decode_opts->opt_total_len;
	new_opt->offset = decode_opts->opt_total_len;
	new_opt->kind = TCPOPT_MSS;
	new_opt->item_type = ROHC_TCP_ITEM_MSS;
	new_opt->len = 4;
	/*fill the kind and length*/
	*to = TCPOPT_MSS;
	to++;
	*to = new_opt->len;
	to++;
	if(decomp_wlsb_analyze_field_is_carryed(mss)){
		mss_v = mss->encode_v & 0xffff;
		memcpy(to,&mss_v,2);
	}else{
		/*Can be obtained from the last packet when the
		 * content is unchannged*/
		old_map = &opts_ref->last_map[ROHC_TCP_ITEM_MSS];
		BUG_ON(!old_map->is_maped);
		old_opt = &opts_ref->tcp_options[old_map->index];
		ref = opts_ref->opt_buff + old_opt->offset + 2;
		memcpy(to,ref,2);
	}
	decode_opts->opt_total_len += new_opt->len;
	decode_opts->opt_num++;
	return 0;
}

int tcp_decode_option_ws(struct decomp_tcph_options_context *opt_context,struct tcp_analyze_item *analyze_item,const struct tcphdr *tcph)
{
	u8 *to,*ref;
	struct item_to_index *map,*old_map;
	struct last_decomped_tcp_options *opts_ref;
	struct tcp_decode_options *decode_opts;
	struct tcph_option *new_opt,*old_opt;
	struct wlsb_analyze_field *ws;
	u8 ws_v;
	decode_opts = &opt_context->update_by_packet.decode_options;
	opts_ref = &opt_context->tcp_opt_ref;
	ws = &analyze_item->item_field;
	new_opt = &decode_opts->tcp_options[decode_opts->opt_num];
	map = &decode_opts->new_map[ROHC_TCP_ITEM_WS];
	map->is_maped = true;
	map->index = decode_opts->opt_num;

	new_opt->offset = decode_opts->opt_total_len;
	new_opt->kind = TCPOPT_WINDOW;
	new_opt->item_type = ROHC_TCP_ITEM_WS;
	new_opt->len = 3;
	to = decode_opts->opt_buff + decode_opts->opt_total_len;
	/*fill the kind and length */
	*to = TCPOPT_WINDOW;
	to++;
	*to = new_opt->len;
	to++;
	if(decomp_wlsb_analyze_field_is_carryed(ws)){
		ws_v = ws->encode_v & 0xff;
		memcpy(to,&ws_v,1);
	}else{
		/*Can be obtained from the last packet when the
		 * content is unchannged*/
		old_map = &opts_ref->last_map[ROHC_TCP_ITEM_WS];
		BUG_ON(!old_map->is_maped);
		old_opt = &opts_ref->tcp_options[old_map->index];
		ref = opts_ref->opt_buff + old_opt->offset + 2;
		memcpy(to,ref,1);
	}
	decode_opts->opt_num++;
	decode_opts->opt_total_len += new_opt->len;
	rohc_pr(ROHC_DTCP,"ws=%d\n",*to);
	return 0;
}

static inline int decode_option_ts(struct rohc_decomp_wlsb *wlsb,struct wlsb_analyze_field *field,u32 *tsv)
{
	int retval;
	if(!field->is_comp){
		/*network byte order*/
		*tsv = field->encode_v;
		retval = 0;
	}else{
		retval = rohc_decomp_lsb_decode(wlsb,field->encode_bits,field->encode_p,field->encode_v,tsv,false);
		if(!retval){
			/*here need change to network byte order*/
			*tsv = htonl(*tsv);
		}
	}
	return retval;
}
int tcp_decode_option_ts(struct decomp_tcph_options_context *opt_context,struct tcp_analyze_item *analyze_item,const struct tcphdr *tcph)
{
	u8 *to;
	struct item_to_index *map;
	struct tcp_decode_options *decode_opts;
	struct tcph_option *new_opt;
	struct rohc_decomp_wlsb *ts_wlsb,*tsecho_wlsb;
	struct wlsb_analyze_field *ts,*tsecho;
	u32 tsv,tsechov;
	int retval = 0;

	decode_opts = &opt_context->update_by_packet.decode_options;
	ts_wlsb = opt_context->ts_wlsb;
	tsecho_wlsb = opt_context->tsecho_wlsb;
	ts = &analyze_item->item_fields[0];
	tsecho = &analyze_item->item_fields[1];
	new_opt = &decode_opts->tcp_options[decode_opts->opt_num];
	map = &decode_opts->new_map[ROHC_TCP_ITEM_TS];
	map->is_maped = true;
	map->index = decode_opts->opt_num;

	new_opt->offset = decode_opts->opt_total_len;
	new_opt->kind = TCPOPT_TIMESTAMP;
	new_opt->item_type = ROHC_TCP_ITEM_TS;
	new_opt->len = 10;
	to = decode_opts->opt_buff + decode_opts->opt_total_len;
	/*fill the kind and length*/
	*to = TCPOPT_TIMESTAMP;
	to++;
	*to = new_opt->len;
	to++;

	if(decode_option_ts(ts_wlsb,ts,&tsv)){
		pr_err("tcp decode timestamp failed\n");
		retval = -EFAULT;
		goto out;
	}
	if(decode_option_ts(tsecho_wlsb,tsecho,&tsechov)){
		pr_err("tcp decode timestamp echo failed\n");
		retval = -EFAULT;
		goto out;
	}
	/*fill timestamp and echo timestamp*/
	memcpy(to,&tsv,4);
	to += 4;
	memcpy(to,&tsechov,4);
	decode_opts->opt_num++;
	decode_opts->opt_total_len += new_opt->len;

	opt_context->update_by_packet.ts = ntohl(tsv);
	opt_context->update_by_packet.tsecho = ntohl(tsechov);
	opt_context->update_by_packet.ts_present = true;
out:
	return retval;

}


static void decode_sack_block(u32 *ref,u32 *block_start,u32 *block_end)
{
	*block_start = *block_start + *ref;
	*block_end = *block_end + *block_start;
	*ref = *block_end;
	/*change to network byte order*/
	*block_start = htonl(*block_start);
	*block_end = htonl(*block_end);
}
int tcp_decode_option_sack(struct decomp_tcph_options_context *opt_context,struct tcp_analyze_item *analyze_item,const struct tcphdr *tcph)
{
	u8 *to,*sack_ref;
	struct item_to_index *map,*old_map;
	struct tcp_decode_options *decode_opts;
	struct last_decomped_tcp_options *opts_ref;
	struct tcph_option *new_opt,*old_opt;
	struct wlsb_analyze_field *start,*end;
	u32 ref,block_start,block_end;
	int blocks,i;

	decode_opts = &opt_context->update_by_packet.decode_options;
	opts_ref = &opt_context->tcp_opt_ref;
	new_opt = &decode_opts->tcp_options[decode_opts->opt_num];
	map = &decode_opts->new_map[ROHC_TCP_ITEM_SACK];
	map->is_maped = true;
	map->index = decode_opts->opt_num;

	new_opt->kind = TCPOPT_SACK;
	new_opt->offset = decode_opts->opt_total_len;
	new_opt->item_type = ROHC_TCP_ITEM_SACK;
	blocks = analyze_item->field_num / 2;
	to = decode_opts->opt_buff + decode_opts->opt_total_len;
	/*fill the kind*/
	*to = TCPOPT_SACK;
	to++;

	if(blocks){
		new_opt->len = TCPOLEN_SACK_BASE + blocks * TCPOLEN_SACK_PERBLOCK;
		/*fill the length*/
		*to = new_opt->len;
		to++;
		ref = ntohl(tcph->ack_seq);

		for(i = 0 ; i < blocks ;i++){
			start = &analyze_item->item_fields[i * 2];
			end = &analyze_item->item_fields[i * 2 + 1];
			block_start = start->encode_v;
			block_end = end->encode_v;
			decode_sack_block(&ref,&block_start,&block_end);
			memcpy(to,&block_start,4);
			to += 4;
			memcpy(to,&block_end,4);
			to += 4;
		}
	}else{
		/*Can be obtained from the last packet when the
		 * content is unchannged*/
		old_map = &opts_ref->last_map[ROHC_TCP_ITEM_SACK];
		BUG_ON(!old_map->is_maped);
		old_opt = &opts_ref->tcp_options[old_map->index];

		new_opt->len = old_opt->len;
		/*fill the length*/
		*to = old_opt->len;
		to++;
		/*fill the sack block*/
		sack_ref = opts_ref->opt_buff + old_opt->offset + TCPOLEN_SACK_BASE;
		memcpy(to,sack_ref,new_opt->len - TCPOLEN_SACK_BASE);
		rohc_pr(ROHC_DTCP,"last sack length:%d,type %d\n",old_opt->len,old_opt->item_type);
	}
	decode_opts->opt_num++;
	decode_opts->opt_total_len += new_opt->len;
	rohc_pr(ROHC_DTCP,"decode SACK LEN:%d,blocks=%d\n",new_opt->len,blocks);
	return 0;
}

int tcp_decode_option_generic(struct decomp_tcph_options_context *opt_context,struct tcp_analyze_item *analyze_item,const struct tcphdr *tcph)
{
	u8 *to,*ref;
	struct item_to_index *map,*old_map;
	struct tcp_decode_options *decode_opts;
	struct last_decomped_tcp_options *opts_ref;
	struct tcph_option *new_opt,*old_opt;
	struct analyze_vl_field *vl_field;

	decode_opts = &opt_context->update_by_packet.decode_options;
	vl_field = &analyze_item->item_vl_field;

	new_opt = &decode_opts->tcp_options[decode_opts->opt_num];
	map = &decode_opts->new_map[analyze_item->item_type];
	map->is_maped = true;
	map->index = decode_opts->opt_num;

	new_opt->kind = analyze_item->kind;
	new_opt->len = analyze_item->len;
	new_opt->offset = decode_opts->opt_total_len;
	new_opt->item_type = analyze_item->item_type;

	to = decode_opts->opt_buff + decode_opts->opt_total_len;
	/*fill the kind and length*/
	*to = new_opt->kind;
	to++;
	*to = new_opt->len;
	to++;
	if(analyze_vl_field_is_carryed(vl_field)){
		memcpy(to,vl_field->buff,vl_field->len);
	}else{
		/*Can be obtained from the last packet when the
		 * content is unchannged*/
		opts_ref = &opt_context->tcp_opt_ref;
		old_map = &opts_ref->last_map[analyze_item->item_type];
		BUG_ON(!old_map->is_maped);
		old_opt = &opts_ref->tcp_options[old_map->index];
		ref = opts_ref->opt_buff + old_opt->offset + 2;
		memcpy(to,ref,new_opt->len - 2);
	}
	decode_opts->opt_num++;
	decode_opts->opt_total_len += new_opt->len;
	return 0;
}

int decomp_tcp_option_init_context(struct decomp_tcph_options_context *opt_context)
{
	int retval = 0;
	opt_context->ts_wlsb = rohc_decomp_lsb_alloc(TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(opt_context->ts_wlsb)){
		retval = -ENOMEM;
		goto err0;
	}
	opt_context->tsecho_wlsb = rohc_decomp_lsb_alloc(TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(opt_context->tsecho_wlsb)){
		retval = -ENOMEM;
		goto err1;
	}
	return 0;
err1:
	rohc_decomp_lsb_free(opt_context->ts_wlsb);
err0:
	return retval;
}

void decomp_tcp_option_destroy_context(struct decomp_tcph_options_context *opt_context)
{
	rohc_decomp_lsb_free(opt_context->ts_wlsb);
	rohc_decomp_lsb_free(opt_context->tsecho_wlsb);
}

void tcp_option_update_context(struct decomp_tcph_options_context *opt_context)
{
	struct last_decomped_tcp_options *opts_ref;
	struct decomp_tcp_options_update *opts_update;
	struct tcp_decode_options *decoded_opts;

	struct tcph_option *new_opt,*to_opt;
	struct item_to_index *new_map,*to_map;
	int i;

	opts_ref = &opt_context->tcp_opt_ref;
	opts_update = &opt_context->update_by_packet;

	decoded_opts = &opts_update->decode_options;
	opts_ref->opt_num = decoded_opts->opt_num;

	if(opts_ref->opt_num)
		memcpy(opts_ref->opt_buff,decoded_opts->opt_buff,decoded_opts->opt_total_len);

	for(i = 0;i < decoded_opts->opt_num; i++){
		new_opt = &decoded_opts->tcp_options[i];
		to_opt = &opts_ref->tcp_options[i];
		new_map = &decoded_opts->new_map[new_opt->item_type];
		to_map = &opts_ref->last_map[new_opt->item_type];
		memcpy(to_opt,new_opt,sizeof(struct tcph_option));
		memcpy(to_map,new_map,sizeof(struct item_to_index));
	}
	if(opts_update->ts_present){
		rohc_decomp_lsb_setup_ref(opt_context->ts_wlsb,opts_update->ts);
		rohc_decomp_lsb_setup_ref(opt_context->tsecho_wlsb,opts_update->tsecho);
	}
}
static const struct decomp_tcp_item_ops decomp_tcp_item_table[] = {
	{
		.item_type = ROHC_TCP_ITEM_NOP,
		.analyze_item = tcp_option_analyze_item_nop,
		.analyze_irr_chain = tcp_option_analyze_irrchain_common,
		.decode_option = tcp_decode_option_nop,
	},
	{
		.item_type = ROHC_TCP_ITEM_EOL,
		.analyze_item = tcp_option_analyze_item_eol,
		.analyze_irr_chain = tcp_option_analyze_irrchain_common,
		.decode_option = tcp_decode_option_eol,
	},
	{
		.item_type = ROHC_TCP_ITEM_MSS,
		.analyze_item = tcp_option_analyze_item_mss,
		.analyze_irr_chain = tcp_option_analyze_irrchain_common,
		.decode_option = tcp_decode_option_mss,
	},
	{
		.item_type = ROHC_TCP_ITEM_WS,
		.analyze_item = tcp_option_analyze_item_ws,
		.analyze_irr_chain = tcp_option_analyze_irrchain_common,
		.decode_option = tcp_decode_option_ws,
	},
	{
		.item_type = ROHC_TCP_ITEM_TS,
		.analyze_item = tcp_option_analyze_item_ts,
		.analyze_irr_chain = tcp_option_analyze_irrchain_ts,
		.decode_option = tcp_decode_option_ts,
	},
	{
		.item_type = ROHC_TCP_ITEM_SACK_PERM,
		.analyze_item = tcp_option_analyze_item_sackperm,
		.analyze_irr_chain = tcp_option_analyze_irrchain_common,
		.decode_option = tcp_decode_option_sackperm,
	},
	{
		.item_type = ROHC_TCP_ITEM_SACK,
		.analyze_item = tcp_option_analyze_item_sack,
		.analyze_irr_chain = tcp_option_analyze_irrchain_sack,
		.decode_option = tcp_decode_option_sack,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC7,
		.analyze_item = tcp_option_analyze_item_generic,
		.analyze_irr_chain = tcp_option_analyze_irrchain_generic,
		.decode_option = tcp_decode_option_generic,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC8,
		.analyze_item = tcp_option_analyze_irrchain_generic,
		.analyze_irr_chain = tcp_option_analyze_irrchain_generic,
		.decode_option = tcp_decode_option_generic,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC9,
		.analyze_item = tcp_option_analyze_item_generic,
		.analyze_irr_chain = tcp_option_analyze_irrchain_generic,
		.decode_option = tcp_decode_option_generic,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC10,
		.analyze_item = tcp_option_analyze_item_generic,
		.analyze_irr_chain = tcp_option_analyze_irrchain_generic,
		.decode_option = tcp_decode_option_generic,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC11,
		.analyze_item = tcp_option_analyze_item_generic,
		.analyze_irr_chain = tcp_option_analyze_irrchain_generic,
		.decode_option = tcp_decode_option_generic,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC12,
		.analyze_item = tcp_option_analyze_item_generic,
		.analyze_irr_chain = tcp_option_analyze_irrchain_generic,
		.decode_option = tcp_decode_option_generic,

	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC13,
		.analyze_item = tcp_option_analyze_item_generic,
		.analyze_irr_chain = tcp_option_analyze_irrchain_generic,
		.decode_option = tcp_decode_option_generic,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC14,
		.analyze_item = tcp_option_analyze_item_generic,
		.analyze_irr_chain = tcp_option_analyze_irrchain_generic,
		.decode_option = tcp_decode_option_generic,
	},
	{
		.item_type = ROHC_TCP_ITEM_GENERIC15,
		.analyze_item = tcp_option_analyze_item_generic,
		.analyze_irr_chain = tcp_option_analyze_irrchain_generic,
		.decode_option = tcp_decode_option_generic,
	},
};


int tcp_options_analyze_clist(struct decomp_tcph_options_context *opt_context,const struct sk_buff *skb,struct	rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *list_start,*item_start;
	struct decomp_tcp_options_update *new_opt_update;
	struct tcp_carryed_items *carryed_items;
	struct tcp_analyze_item *analyze_item;
	bool ps;
	int opt_num,i;
	int item_analyze_len;
	int analyze_len = 0;
	int retval = 0;
	new_opt_update = &opt_context->update_by_packet;
	carryed_items = &new_opt_update->carryed_items;
	carryed_items->is_list_present = true;

	list_start = skb->data + pkt_info->decomped_hdr_len;
	/*first ,analyze ps and m*/
	ps = !!BYTE_BIT_4(*list_start);
	opt_num = BYTE_BITS_4(*list_start,0);
	analyze_len++;
	list_start++;
	analyze_len += tcp_options_cal_xi_table_len(opt_num,ps);
	item_start = list_start + tcp_options_cal_xi_table_len(opt_num,ps);

	carryed_items->opt_num = opt_num;
	for(i = 0 ; i < opt_num;i++){
		analyze_item = &carryed_items->analyze_items[i];
		if(ps){
			analyze_item->carryed_by_list = !!BYTE_BIT_7(*list_start);
			analyze_item->item_type = BYTE_BITS_4(*list_start,0);
			list_start++;

		}else{
			if(!(i % 2)){
				analyze_item->carryed_by_list = !!BYTE_BIT_7(*list_start);
				analyze_item->item_type = BYTE_BITS_3(*list_start,4);
			}else{
				analyze_item->carryed_by_list = !!BYTE_BIT_3(*list_start);
				analyze_item->item_type = BYTE_BITS_3(*list_start,0);
				list_start++;
			}
		}
		if(analyze_item->carryed_by_list){
			retval = decomp_tcp_item_table[analyze_item->item_type].analyze_item(opt_context,item_start,analyze_item,&item_analyze_len);
			if(retval){
				pr_err("analyze tcp option item-%d failed\n",analyze_item->item_type);
				goto out;
			}
			rohc_pr(ROHC_DTCP,"item_type %d,item_analyze_len:%d\n",analyze_item->item_type,item_analyze_len);
			analyze_len += item_analyze_len;
			item_start += item_analyze_len;
		}
	}
	rohc_pr(ROHC_DTCP,"list tot_len %d,xi_len %d,ps %d,opt_num %d\n",analyze_len,tcp_options_cal_xi_table_len(opt_num,ps),ps,opt_num);
	pkt_info->decomped_hdr_len += analyze_len;
out:
	return retval;
}


int tcp_options_analyze_irr_chain(struct decomp_tcph_options_context *opt_context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *irr_chain;
	struct decomp_tcp_options_update *new_opt_update;
	struct tcp_carryed_items *carryed_items;
	struct tcp_analyze_item *analyze_item;
	enum rohc_tcp_item_type item_type;
	int irr_analyze_len;
	int i;
	int analyze_len = 0;
	int retval = 0;
	new_opt_update = &opt_context->update_by_packet;
	carryed_items = &new_opt_update->carryed_items;
	irr_chain = skb->data + pkt_info->decomped_hdr_len;
	if(!carryed_items->is_list_present)
		tcp_option_batch_update_item_type(new_opt_update,&opt_context->tcp_opt_ref);
	for(i = 0; i < carryed_items->opt_num;i++){
		analyze_item = &carryed_items->analyze_items[i];
		item_type = analyze_item->item_type;
		if(analyze_item->carryed_by_list)
			continue;
		switch(item_type){
			case ROHC_TCP_ITEM_MSS:
			case ROHC_TCP_ITEM_WS:
			case ROHC_TCP_ITEM_EOL:
			case ROHC_TCP_ITEM_NOP:
			case ROHC_TCP_ITEM_SACK_PERM:
				break;
			default:
				retval = decomp_tcp_item_table[item_type].analyze_irr_chain(opt_context,irr_chain,analyze_item,&irr_analyze_len);
				if(retval){
					rohc_pr(ROHC_DTCP,"analyze irr chain failed,item-%d\n",item_type);
					goto out;
				}
				irr_chain += irr_analyze_len;
				analyze_len += irr_analyze_len;
		}
	}
	pkt_info->decomped_hdr_len += analyze_len;
out:
	return retval;
}


int tcp_options_decode(struct decomp_tcph_options_context *opt_context,struct rohc_decomp_pkt_hdr_info *pkt_info,const struct tcphdr *tcph)
{
	struct decomp_tcp_options_update *new_opt_update;
	struct tcp_carryed_items *carryed_items;
	struct tcp_analyze_item *analyze_item;
	enum rohc_tcp_item_type item_type;
	int i;
	int retval = 0;
	new_opt_update = &opt_context->update_by_packet;
	carryed_items = &new_opt_update->carryed_items;
	for(i = 0 ; i < carryed_items->opt_num; i++){
		analyze_item = &carryed_items->analyze_items[i];
		retval = decomp_tcp_item_table[analyze_item->item_type].decode_option(opt_context,analyze_item,tcph);
		if(retval){
			pr_err("decode tcp option item-%d failed\n ",analyze_item->item_type);
			goto out;
		}
	}
out:
	return retval;
}

