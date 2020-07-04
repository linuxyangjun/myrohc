/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	date: 2020/5/21
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
#include "../profile/rtp_profile.h"

#include "rohc_decomp.h"
#include "rohc_decomp_wlsb.h"
#include "rohc_decomp_v2_common.h"
#include "decomp_udp_v2.h"
#include "rohc_decomp_packet.h"
#include "decomp_rtp_common.h"
#include "decomp_rtp_clist.h"
#include "decomp_rtp_v2.h"

static inline int rohc_v2_profile_1_7_flags1_analyze(u8 *from,struct decomp_iph_field_update *iph_update,struct last_decomped_iph *iph_ref,enum rohc_v2_reordering_ratio *rr,bool *inner_ttl_hl,bool *inner_toc_tc,int ind)
{
	if(!ind)
		return 0;
	iph_update->iph_fields.outer_ind = !!BYTE_BIT_7(*from);
	*inner_ttl_hl = !!BYTE_BIT_6(*from);
	*inner_toc_tc = !!BYTE_BIT_5(*from);
	fill_innermost_iph_dynamic_fields(iph_update,iph_ref,IPH_FIELD_DF,!!BYTE_BIT_4(*from));
	fill_innermost_iph_dynamic_fields(iph_update,iph_ref,IPH_FIELD_IPID_BH,BYTE_BITS_2(*from,2));
	*rr = (*from) & 0x3;
	return 1;
}

static inline int rohc_v2_profile_1_flags2_analyze(u8 *from,struct rtph_dynamic_fields *rtp_dynamic_fields,bool *list_ind,bool *pt_ind,int flag)
{
	if(!flag)
		return 0;
	*list_ind = !!BYTE_BIT_7(*from);
	*pt_ind = !!BYTE_BIT_6(*from);
	decomp_fill_analyze_field(&rtp_dynamic_fields->p,!!BYTE_BIT_4(*from));
	decomp_fill_analyze_field(&rtp_dynamic_fields->x,!!BYTE_BIT_3(*from));
	return 1;
}

static inline int sdvl_analyze(u8 *from,struct analyze_field *ana_field)
{
	u32 encode_v;
	int analyze_len = 0;
	if(BYTE_BIT_7(*from) == SDVL_LSB_TYPE_0){

		encode_v = BYTE_BITS_7(*from,0);
		analyze_len = 1;
	}else if(BYTE_BITS_2(*from,6) == SDVL_LSB_TYPE_1){

		encode_v = BYTE_BITS_6(*from,0);
		from++;
		encode_v = (encode_v << 8) | (*from);

		analyze_len = 2;
	}else if(BYTE_BITS_3(*from,5) == SDVL_LSB_TYPE_2){

		encode_v = BYTE_BITS_5(*from,0);
		from++;
		encode_v = (encode_v << 8) | (*from);
		from++;
		encode_v = (encode_v << 8) | (*from);
		analyze_len = 3;
	}else if(BYTE_BITS_4(*from,4) == SDVL_LSB_TYPE_3){

		encode_v = BYTE_BITS_4(*from,0);
		from++;
		encode_v = (encode_v << 8) | (*from);
		from++;
		encode_v = (encode_v << 8) | (*from);
		from++;
		encode_v = (encode_v << 8) | (*from);
		analyze_len = 4;
	}else if(*from == SDVL_LSB_TYPE_4){
		from++;
		memcpy(&encode_v,from,4);
		encode_v = ntohl(encode_v);
		analyze_len = 5;
	}else{
		rohc_pr(ROHC_DV2,"%s,not support the sdvl lsb analyze\n",__func__);
	}
	decomp_fill_analyze_field(ana_field,encode_v);
	return analyze_len;
}

static inline int sdvl_lsb_analyze(u8 *from,struct wlsb_analyze_field *ana_field)
{
	u32 encode_v;
	int analyze_len = 0;
	if(BYTE_BIT_7(*from) == SDVL_LSB_TYPE_0){
		decomp_wlsb_fill_analyze_field(ana_field,BYTE_BITS_7(*from,0),7,true);
		analyze_len = 1;
	}else if(BYTE_BITS_2(*from,6) == SDVL_LSB_TYPE_1){
		decomp_wlsb_fill_analyze_field(ana_field,BYTE_BITS_6(*from,0),6,true);
		from++;
		decomp_wlsb_analyze_field_append_bits(ana_field,*from,8,true);
		analyze_len = 2;
	}else if(BYTE_BITS_3(*from,5) == SDVL_LSB_TYPE_2){
		decomp_wlsb_fill_analyze_field(ana_field,BYTE_BITS_5(*from,0),5,true);
		from++;
		decomp_wlsb_analyze_field_append_bits(ana_field,*from,8,true);
		from++;
		decomp_wlsb_analyze_field_append_bits(ana_field,*from,8,true);
		analyze_len = 3;
	}else if(BYTE_BITS_4(*from,4) == SDVL_LSB_TYPE_3){
		decomp_wlsb_fill_analyze_field(ana_field,BYTE_BITS_4(*from,0),4,true);
		from++;
		decomp_wlsb_analyze_field_append_bits(ana_field,*from,8,true);
		from++;
		decomp_wlsb_analyze_field_append_bits(ana_field,*from,8,true);
		from++;
		decomp_wlsb_analyze_field_append_bits(ana_field,*from,8,true);
		analyze_len = 4;
	}else if(*from == SDVL_LSB_TYPE_4){
		from++;
		memcpy(&encode_v,from,4);
		encode_v = ntohl(encode_v);
		decomp_wlsb_fill_analyze_field(ana_field,encode_v,32,false);
		analyze_len = 5;
	}else{
		rohc_pr(ROHC_DV2,"%s,not support the sdvl lsb analyze\n",__func__);
	}

	return analyze_len;
}
int rtp_analyze_pt_0_crc7(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_rtp_v2_context *d_rt_context;
	struct wlsb_analyze_field *msn;
	struct pt_0_crc7_rtp *crc_rtp;

	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	msn = &co_context->co_update.msn;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		crc_rtp = (struct pt_0_crc7_rtp *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			crc_rtp = (struct pt_0_crc7_rtp *)analyze_data;
		else
			crc_rtp = (struct pt_0_crc7_rtp *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		decomp_wlsb_fill_analyze_field(msn,crc_rtp->msn0,4,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_analyze_field_append_bits(msn,crc_rtp->msn1,1,true);
	analyze_len += sizeof(struct pt_0_crc7_rtp) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int rtp_analyze_pt_1_rnd(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_rtp_v2_context *d_rtp_context;
	struct rtph_dynamic_fields *rtp_dynamic_fields;
	struct pt_1_rnd *rnd;

	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_v2_context *)co_context->inherit_context;

	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		rnd = (struct pt_1_rnd *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			rnd = (struct pt_1_rnd *)analyze_data;
		else
			rnd = (struct pt_1_rnd *)(analyze_data - 1);
		analyze_full = false;
	}
	rtp_dynamic_fields = &d_rtp_context->rtph_context.update_by_packet.rtph_fields.dynamic_fields;
	if(analyze_first){
		decomp_fill_analyze_field(&rtp_dynamic_fields->m,rnd->m);
		decomp_wlsb_fill_analyze_field(&co_context->co_update.msn,rnd->msn,4,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_fill_analyze_field(&rtp_dynamic_fields->ts_scaled,rnd->ts_scaled,5,true);
	analyze_len += sizeof(struct pt_1_rnd) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int rtp_analyze_co_common(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_rtp_v2_context *d_rtp_context;
	struct decomp_rtp_csrc_context *csrc_context;

	struct rtph_dynamic_fields *rtp_dynamic_fields;
	struct rohc_v2_decomp_iph_context *iph_context;
	struct decomp_iph_field_update *iph_update;
	struct last_decomped_iph *iph_ref;
	struct profile_rtp_co_common *co_common;
	struct wlsb_analyze_field *ipid;

	enum rohc_v2_reordering_ratio new_rr;
	bool analyze_full= false;
	bool inner_tos_tc_ind= false;
	bool inner_ttl_hl_ind= false;
	bool pt_ind,list_ind=false;
	u16 ipid_off;
	int call_len;
	int analyze_len = 0;
	int retval = 0;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;

	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		co_common = (struct profile_rtp_co_common *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			co_common = (struct profile_rtp_co_common *)analyze_data;
		else
			co_common = (struct profile_rtp_co_common *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	d_rtp_context = (struct decomp_rtp_v2_context *)co_context->inherit_context;
	rtp_dynamic_fields = &d_rtp_context->rtph_context.update_by_packet.rtph_fields.dynamic_fields;

	decomp_fill_analyze_field(&rtp_dynamic_fields->m,co_common->mark);
	analyze_len += sizeof(struct profile_rtp_co_common) - 1;
	analyze_data += analyze_len;
	/*next fields is variable length fields*/

	/*field.1 ip header falgs*/
	iph_update = &co_context->iph_context.update_by_packet;
	iph_ref = &co_context->iph_context.iph_ref;

	call_len = rohc_v2_profile_1_7_flags1_analyze(analyze_data,iph_update,iph_ref,&new_rr,&inner_ttl_hl_ind,&inner_tos_tc_ind,co_common->flag1_ind);
	analyze_data += call_len;
	analyze_len += call_len;
	/*field.2 rtph flags*/
	call_len = rohc_v2_profile_1_flags2_analyze(analyze_data,rtp_dynamic_fields,&list_ind,&pt_ind,co_common->flag2_ind);
	analyze_data += call_len;
	analyze_len += call_len;
	/*innermost iph header toc_tc*/
	if(inner_tos_tc_ind){
		fill_innermost_iph_dynamic_fields(iph_update,iph_ref,IPH_FIELD_TOS_TC,*analyze_data);
		analyze_data++;
		analyze_len++;
	}
	/*innermost ip header ttl hl*/
	if(inner_ttl_hl_ind){
		fill_innermost_iph_dynamic_fields(iph_update,iph_ref,IPH_FIELD_TTL_HL,*analyze_data);
		analyze_data++;
		analyze_len++;
	}
	/*rtp header packte type*/
	if(pt_ind){
		decomp_fill_analyze_field(&rtp_dynamic_fields->pt,BYTE_BITS_7(*analyze_data,0));
		analyze_data++;
		analyze_len++;
	}
	rohc_pr(ROHC_DRTP2,"%s:analyze_len = %d,decomped_hdr_len=%d\n",__func__,analyze_len,pkt_info->decomped_hdr_len);
	/*seq num[msn]*/
	call_len = sdvl_lsb_analyze(analyze_data,&co_context->co_update.msn);
	rohc_pr(ROHC_DRTP2,"ana msn:%d,len=%d\n",co_context->co_update.msn.encode_v,call_len);
	analyze_data += call_len;
	analyze_len += call_len;
	/*inner ip header ipid*/
	ipid = pick_innermost_ipid_field(iph_update,iph_ref);
	if(ipid){
		if(co_common->ipid_ind){
			/*keep network byte order*/
			memcpy(&ipid_off,analyze_data,2);
			decomp_wlsb_fill_analyze_field(ipid,ipid_off,16,false);
			analyze_data += 2;
			analyze_len += 2;
		}else{
			ipid_off = *analyze_data;
			decomp_wlsb_fill_analyze_field(ipid,ipid_off,8,true);
			analyze_len++;
			analyze_data++;
		}
		rohc_pr(ROHC_DRTP2,"%s[%d]:analyze_len = %d,decomped_hdr_len=%d\n",__func__,__LINE__,analyze_len,pkt_info->decomped_hdr_len);
	}
	/*timestatmp or timestatmp-scaled*/
	if(!co_common->tsc_ind){
		call_len = sdvl_lsb_analyze(analyze_data,&rtp_dynamic_fields->ts);
		analyze_data += call_len;
		analyze_len += call_len;
		rohc_pr(ROHC_DRTP2,"%s[%d]:analyze_len = %d,decomped_hdr_len=%d\n",__func__,__LINE__,analyze_len,pkt_info->decomped_hdr_len);

	}else{
		call_len = sdvl_lsb_analyze(analyze_data,&rtp_dynamic_fields->ts_scaled);
		analyze_data += call_len;
		analyze_len += call_len;
		rohc_pr(ROHC_DRTP2,"%s[%d]:analyze_len = %d,decomped_hdr_len=%d\n",__func__,__LINE__,analyze_len,pkt_info->decomped_hdr_len);

	}
	/*ts stride*/
	if(co_common->tss_ind){
		call_len = sdvl_analyze(analyze_data,&rtp_dynamic_fields->ts_stride);
		analyze_len += call_len;
		analyze_data += call_len;
		rohc_pr(ROHC_DRTP2,"%s[%d]:analyze_len = %d,decomped_hdr_len=%d\n",__func__,__LINE__,analyze_len,pkt_info->decomped_hdr_len);

	}
	/*csrc list*/
	if(list_ind){
		pkt_info->decomped_hdr_len += analyze_len;
		analyze_len = 0;
		retval = rtp_v2_csrc_analyze_clist(&d_rtp_context->csrc_context,skb,pkt_info);
		if(retval)
			rohc_pr(ROHC_DV2,"profiev2 rtp analyze csrc list failed\n");
	}

out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int rtp_analyze_pt_1_seq_id(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_iph_field_update *iph_update;
	struct last_decomped_iph *iph_ref;
	struct pt_1_seq_id_rtp *seq_id;
	struct wlsb_analyze_field *ipid;

	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	iph_update = &co_context->iph_context.update_by_packet;
	iph_ref = &co_context->iph_context.iph_ref;
	ipid = pick_innermost_ipid_field(iph_update,iph_ref);
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		seq_id = (struct pt_1_seq_id_rtp *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			seq_id = (struct pt_1_seq_id_rtp *)analyze_data;
		else
			seq_id = (struct pt_1_seq_id_rtp *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		decomp_wlsb_fill_analyze_field(ipid,seq_id->ipid_off,4,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_fill_analyze_field(&co_context->co_update.msn,seq_id->msn,5,true);
	analyze_len += sizeof(struct pt_1_seq_id_rtp) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;

}

int rtp_analyze_pt_1_seq_ts(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_rtp_v2_context *d_rtp_context;
	struct rtph_dynamic_fields *rtp_dynamic_fields;
	struct pt_1_seq_ts *seq_ts;

	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_v2_context *)co_context->inherit_context;
	rtp_dynamic_fields = &d_rtp_context->rtph_context.update_by_packet.rtph_fields.dynamic_fields;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		seq_ts = (struct pt_1_seq_ts *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			seq_ts = (struct pt_1_seq_ts *)analyze_data;
		else
			seq_ts = (struct pt_1_seq_ts *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		decomp_fill_analyze_field(&rtp_dynamic_fields->m,seq_ts->m);
		decomp_wlsb_fill_analyze_field(&co_context->co_update.msn,seq_ts->msn,4,true);
		analyze_len = 1;
	}

	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_fill_analyze_field(&rtp_dynamic_fields->ts_scaled,seq_ts->ts_scaled,5,true);

	analyze_len += sizeof(struct pt_1_seq_ts) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int rtp_analyze_pt_2_rnd(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_rtp_v2_context *d_rtp_context;
	struct rtph_dynamic_fields *rtp_dynamic_fields;
	struct pt_2_rnd *rnd;

	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_v2_context *)co_context->inherit_context;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		rnd = (struct pt_2_rnd *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			rnd = (struct pt_2_rnd *)analyze_data;
		else
			rnd = (struct pt_2_rnd *)(analyze_data - 1);
		analyze_full = false;
	}

	if(analyze_first){
		decomp_wlsb_fill_analyze_field(&co_context->co_update.msn,rnd->msn0,5,true);
		analyze_len = 1;
	}

	if(!analyze_full && analyze_first)
		goto out;

	decomp_wlsb_analyze_field_append_bits(&co_context->co_update.msn,rnd->msn1,2,true);
	decomp_fill_analyze_field(&rtp_dynamic_fields->m,rnd->m);
	decomp_wlsb_fill_analyze_field(&rtp_dynamic_fields->ts_scaled,rnd->ts_scaled,6,true);

	analyze_len += sizeof(struct pt_2_rnd) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int rtp_analyze_pt_2_seq_id(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_iph_field_update *iph_update;
	struct last_decomped_iph *iph_ref;
	struct pt_2_seq_id_rtp *seq_id;
	struct wlsb_analyze_field *ipid;

	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		seq_id = (struct pt_2_seq_id_rtp *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			seq_id = (struct pt_2_seq_id_rtp *)analyze_data;
		else
			seq_id = (struct pt_2_seq_id_rtp *)(analyze_data - 1);
		analyze_full = false;
	}

	if(analyze_first){
		decomp_wlsb_fill_analyze_field(&co_context->co_update.msn,seq_id->msn0,3,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_analyze_field_append_bits(&co_context->co_update.msn,seq_id->msn1,4,true);
	iph_update = &co_context->iph_context.update_by_packet;
	iph_ref = &co_context->iph_context.iph_ref;
	ipid = pick_innermost_ipid_field(iph_update,iph_ref);
	decomp_wlsb_fill_analyze_field(ipid,seq_id->ipid_off0,4,true);
	decomp_wlsb_analyze_field_append_bits(ipid,seq_id->ipid_off1,1,true);
	analyze_len += sizeof(struct pt_2_seq_id_rtp) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}


int rtp_analyze_pt_2_seq_both(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_rtp_v2_context *d_rtp_context;
	struct decomp_iph_field_update *iph_update;
	struct last_decomped_iph *iph_ref;
	struct rtph_dynamic_fields *rtp_dynamic_fields;
	struct pt_2_seq_both *seq_both;
	struct wlsb_analyze_field *ipid;
	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_v2_context *)co_context->inherit_context;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		seq_both = (struct pt_2_seq_both *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			seq_both = (struct pt_2_seq_both *)analyze_data;
		else
			seq_both = (struct pt_2_seq_both *)(analyze_data - 1);
		analyze_full = false;
	}

	if(analyze_first){
		decomp_wlsb_fill_analyze_field(&co_context->co_update.msn,seq_both->msn0,3,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_analyze_field_append_bits(&co_context->co_update.msn,seq_both->msn1,4,true);
	iph_update = &co_context->iph_context.update_by_packet;
	iph_ref = &co_context->iph_context.iph_ref;
	ipid = pick_innermost_ipid_field(iph_update,iph_ref);
	decomp_wlsb_fill_analyze_field(ipid,seq_both->ipid_off0,4,true);
	decomp_wlsb_analyze_field_append_bits(ipid,seq_both->ipid_off1,1,true);
	rtp_dynamic_fields = &d_rtp_context->rtph_context.update_by_packet.rtph_fields.dynamic_fields;
	decomp_wlsb_fill_analyze_field(&rtp_dynamic_fields->ts_scaled,seq_both->ts_scaled,7,true);
	decomp_fill_analyze_field(&rtp_dynamic_fields->m,seq_both->m);
	analyze_len += sizeof(struct pt_2_seq_both) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int rtp_analyze_pt_2_seq_ts(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_rtp_v2_context *d_rtp_context;
	struct rtph_dynamic_fields *rtp_dynamic_fields;
	struct pt_2_seq_ts *seq_ts;

	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		seq_ts = (struct pt_2_seq_ts *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			seq_ts = (struct pt_2_seq_ts *)analyze_data;
		else
			seq_ts = (struct pt_2_seq_ts *)(analyze_data - 1);
		analyze_full = false;
	}

	if(analyze_first){
		decomp_wlsb_fill_analyze_field(&co_context->co_update.msn,seq_ts->msn0,4,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_analyze_field_append_bits(&co_context->co_update.msn,seq_ts->msn1,3,true);
	d_rtp_context = (struct decomp_rtp_v2_context *)co_context->inherit_context;
	rtp_dynamic_fields = &d_rtp_context->rtph_context.update_by_packet.rtph_fields.dynamic_fields;
	decomp_wlsb_fill_analyze_field(&rtp_dynamic_fields->ts_scaled,seq_ts->ts_scaled,5,true);
	decomp_fill_analyze_field(&rtp_dynamic_fields->m,seq_ts->m);
	analyze_len += sizeof(struct pt_2_seq_ts) - 1;

out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int decomp_rtp_v2_analyze_irr_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	int retval;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_rtp_v2_context *d_rtp_context;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_v2_context *)co_context->inherit_context;
	retval = rohc_v2_decomp_analyze_ip_irr_chain(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DUDP2,"profile udp v2 analyze irr chain failed\n");
		goto out;
	}
	retval = rohc_v2_analyze_udp_irr_chain(context,skb,pkt_info);
	rtp_csrc_copy_static_clist(&d_rtp_context->csrc_context);
	rohc_pr(ROHC_DRTP2,"%s : decomped_hdr_len=%d\n",__func__,pkt_info->decomped_hdr_len);
out:
	return retval;
}

int rtp_analyze_co_header(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
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
			analyze_co_func = rtp_analyze_co_common;
			break;
		case ROHC_PACKET_TYPE_PT_0_CRC3:
			analyze_co_func = rohc_v2_decomp_analyze_pt_0_crc3;
			break;
		case ROHC_PACKET_TYPE_PT_0_CRC7:
			analyze_co_func = rtp_analyze_pt_0_crc7;
			break;
		case ROHC_PACKET_TYPE_PT_1_RND:
			analyze_co_func = rtp_analyze_pt_1_rnd;
			break;
		case ROHC_PACKET_TYPE_PT_1_SEQ_ID:
			analyze_co_func = rtp_analyze_pt_1_seq_id;
			break;
		case ROHC_PACKET_TYPE_PT_1_SEQ_TS:
			analyze_co_func = rtp_analyze_pt_1_seq_ts;
			break;
		case ROHC_PACKET_TYPE_PT_2_RND:
			analyze_co_func = rtp_analyze_pt_2_rnd;
			break;
		case ROHC_PACKET_TYPE_PT_2_SEQ_ID:
			analyze_co_func = rtp_analyze_pt_2_seq_id;
			break;
		case ROHC_PACKET_TYPE_PT_2_SEQ_TS:
			analyze_co_func = rtp_analyze_pt_2_seq_ts;
			break;
		case ROHC_PACKET_TYPE_PT_2_SEQ_BOTH:
			analyze_co_func = rtp_analyze_pt_2_seq_both;
			break;
		default:
			rohc_pr(ROHC_DV2,"profile v2 rtp can't support the decompress packet:%d\n",packet_type);
			break;
	}
	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		pkt_info->decomped_hdr_len += pkt_info->cid_len;
		retval = analyze_co_func(context,skb,pkt_info,true);
	}else{
		analyze_co_func(context,skb,pkt_info,true);
		pkt_info->decomped_hdr_len += pkt_info->cid_len;
		analyze_co_func(context,skb,pkt_info,false);
	}

	retval = decomp_rtp_v2_analyze_irr_chain(context,skb,pkt_info);

	return retval;
}

int rohc_v2_analyze_rtp_static_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_rtp_v2_context *d_rtp_context;
	struct rtph_static_fields *rtp_static_fields;
	struct profile_rtp_static *rtp_static;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_v2_context *)co_context->inherit_context;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	rtp_static = (struct profile_rtp_static *)analyze_data;
	rtp_static_fields = &d_rtp_context->rtph_context.update_by_packet.rtph_fields.static_fields;
	rtp_static_fields->ssrc = rtp_static->ssrc;
	rtp_static_fields->update = true;

	pkt_info->decomped_hdr_len += sizeof(struct profile_rtp_static);
	return 0;
}

int rohc_v2_analyze_rtp_dyamic_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_rtp_v2_context *d_rtp_context;
	struct rtph_dynamic_fields *rtp_dynamic_fields;
	struct profile_v2_rtp_dynamic *rtp_dynamic;

	int call_len;
	int analyze_len = 0;
	int retval = 0;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_v2_context *)co_context->inherit_context;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	rtp_dynamic = (struct profile_v2_rtp_dynamic *)analyze_data;
	rtp_dynamic_fields = &d_rtp_context->rtph_context.update_by_packet.rtph_fields.dynamic_fields;

	decomp_fill_analyze_field(&rtp_dynamic_fields->version,rtp_dynamic->r_ratio);
	decomp_fill_analyze_field(&rtp_dynamic_fields->p,rtp_dynamic->pad_bit);
	decomp_fill_analyze_field(&rtp_dynamic_fields->x,rtp_dynamic->ext);
	decomp_fill_analyze_field(&rtp_dynamic_fields->m,rtp_dynamic->mark);
	decomp_fill_analyze_field(&rtp_dynamic_fields->pt,rtp_dynamic->pt);
	decomp_wlsb_fill_analyze_field(&co_context->co_update.msn,ntohs(rtp_dynamic->seq),16,false);
	decomp_wlsb_fill_analyze_field(&rtp_dynamic_fields->ts,rtp_dynamic->ts,32,false);
	analyze_len = sizeof(struct profile_v2_rtp_dynamic);
	analyze_data += analyze_len;
	/*the following is variable length fields*/
	/*ts_stride*/
	if(rtp_dynamic->tss_ind){
		call_len = sdvl_analyze(analyze_data,&rtp_dynamic_fields->ts_stride);
		analyze_data += call_len;
		analyze_len += call_len;
	}
	/*csrc list*/
	if(rtp_dynamic->list_ind){
		pkt_info->decomped_hdr_len += analyze_len;
		analyze_len = 0;
		retval = rtp_v2_csrc_analyze_clist(&d_rtp_context->csrc_context,skb,pkt_info);
	}
	if(analyze_len)
		pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int rohc_v2_decode_rtp_header(struct decomp_v2_rtph_context *rtph_context,struct rohc_decomp_pkt_hdr_info *pkt_info,u32 msn)
{
	struct rtphdr *new_rtph,*old_rtph;
	struct last_decomped_rth *rtph_ref;
	struct rtph_dynamic_fields *rtp_dynamic_fields;
	struct rtph_static_fields	*rtp_static_fields;
	struct rtp_decode_rtph *decoded_rtph;
	struct wlsb_analyze_field *ts,*ts_scaled;

	u32 new_ts_stride,new_ts,new_ts_scaled,new_ts_residue;
	u32 ref_msn,ref_ts;
	u16 seq;
	int retval = 0;
	rtp_static_fields = &rtph_context->update_by_packet.rtph_fields.static_fields;
	rtp_dynamic_fields = &rtph_context->update_by_packet.rtph_fields.dynamic_fields;
	decoded_rtph = &rtph_context->update_by_packet.decoded_rtph;
	rtph_ref = &rtph_context->rtph_ref;
	new_rtph = &decoded_rtph->rtph;
	old_rtph = &rtph_ref->rtph;
	seq = msn & 0xffff;
	/*decode static fields*/
	if(rtp_static_fields->update){
		new_rtph->ssrc = rtp_static_fields->ssrc;
	}else
		new_rtph->ssrc = old_rtph->ssrc;

	/*decode dynamic fields*/
	if(analyze_field_is_carryed(&rtp_dynamic_fields->version))
		new_rtph->version = rtp_dynamic_fields->version.value;
	else
		new_rtph->version = old_rtph->version;

	if(analyze_field_is_carryed(&rtp_dynamic_fields->x))
		new_rtph->x = rtp_dynamic_fields->x.value;
	else
		new_rtph->x = old_rtph->x;
	if(analyze_field_is_carryed(&rtp_dynamic_fields->p))
		new_rtph->p = rtp_dynamic_fields->p.value;
	else
		new_rtph->p = old_rtph->p;
	if(analyze_field_is_carryed(&rtp_dynamic_fields->m))
		new_rtph->m = rtp_dynamic_fields->m.value;
	else
		new_rtph->m = old_rtph->m;
	if(analyze_field_is_carryed(&rtp_dynamic_fields->pt))
		new_rtph->pt = rtp_dynamic_fields->pt.value;
	else
		new_rtph->pt = old_rtph->pt;
	if(analyze_field_is_carryed(&rtp_dynamic_fields->ts_stride))
		new_ts_stride = rtp_dynamic_fields->ts_stride.value;
	else
		new_ts_stride = rtph_ref->ts_stride;
	rohc_pr(ROHC_DRTP2,"new_ts_stride=%d\n",new_ts_stride);
	ts_scaled = &rtp_dynamic_fields->ts_scaled;
	ts = &rtp_dynamic_fields->ts;
	if(decomp_wlsb_analyze_field_is_carryed(ts_scaled)){
		if(rohc_decomp_lsb_decode(rtph_context->ts_scaled_wlsb,ts_scaled->encode_bits,ROHC_LSB_RTP_TS_K_TO_P(ts_scaled->encode_bits),ts_scaled->encode_v,&new_ts_scaled,false)){
			rohc_pr(ROHC_DV2,"profiev2 rtp decode ts scaled faield\n");
			retval = -EFAULT;
			goto out;
		}
		new_ts = new_ts_stride * new_ts_scaled + rtph_ref->ts_residue;
		decomp_wlsb_fill_analyze_field(ts_scaled,new_ts_scaled,32,false);
		new_rtph->ts = htonl(new_ts);
	}else if(decomp_wlsb_analyze_field_is_carryed(ts)){
		if(!ts->is_comp){
			new_ts = ts->encode_v;
			new_ts = ntohl(new_ts);
		}else{
			if(rohc_decomp_lsb_decode(rtph_context->ts_wlsb,ts->encode_bits,ROHC_LSB_RTP_TS_K_TO_P(ts->encode_bits),ts->encode_v,&new_ts,false)){
				rohc_pr(ROHC_DV2,"profiev2 rtp decode ts faield\n");
				retval = -EFAULT;
				goto out;
			}

		}
		if(new_ts_stride){
			rtp_field_scaling(new_ts_stride,&new_ts_scaled,new_ts,&new_ts_stride);
			decomp_fill_analyze_field(&rtp_dynamic_fields->ts_residue,new_ts_stride);
			decomp_wlsb_fill_analyze_field(ts_scaled,new_ts_scaled,32,false);
		}
		new_rtph->ts = htonl(new_ts);
	}else{
		rohc_decomp_lsb_pick_ref_with_msn(rtph_context->ts_wlsb,&ref_ts,&ref_msn,false);
		ref_ts = ((msn - ref_msn) & 0xffff) * new_ts_stride + ref_ts;
		rohc_pr(ROHC_DRTP2,"msn:%d,ref_msn:%d,ref_ts:%lu,new_ts_stride:%d\n",msn,ref_msn,ref_ts,new_ts_stride);
		new_rtph->ts = htonl(ref_ts);
		//new_rtph->ts = old_rtph->ts;
	}
	new_rtph->seq = htons(seq);

out:
	return retval;
}

int rohc_v2_rebuild_rtp_header(struct decomp_v2_rtph_context *rtph_context,struct decomp_rtp_csrc_context *csrc_context,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct rtphdr *to_rtph,*decode_rtph;
	int rebuild_len,cc;
	to_rtph = (struct rtphdr *)skb_tail_pointer(decomp_skb);
	decode_rtph = &rtph_context->update_by_packet.decoded_rtph.rtph;
	memcpy(to_rtph,decode_rtph,sizeof(struct rtphdr));
	skb_put(decomp_skb,sizeof(struct rtphdr));
	pkt_info->rebuild_hdr_len += sizeof(struct rtphdr);
	rtp_csrc_rebuild_csrc_list(csrc_context,decomp_skb,pkt_info,&cc);
	to_rtph->cc = cc;
	return 0;
}

int rohc_v2_update_rtph_context(struct decomp_v2_rtph_context *rtph_context,u32 msn)
{
	struct rtphdr *to_rtph,*new_rtph;
	struct last_decomped_rth *rtph_ref;
	struct rtph_dynamic_fields *rtp_dynamic_fields;
	struct rtp_decode_rtph *decoded_rtph;
	rtph_ref = &rtph_context->rtph_ref;
	rtp_dynamic_fields = &rtph_context->update_by_packet.rtph_fields.dynamic_fields;
	decoded_rtph = &rtph_context->update_by_packet.decoded_rtph;
	to_rtph = &rtph_ref->rtph;
	new_rtph = &decoded_rtph->rtph;
	memcpy(to_rtph,decoded_rtph,sizeof(struct rtphdr));
	if(analyze_field_is_carryed(&rtp_dynamic_fields->ts_residue))
		rtph_ref->ts_residue = rtp_dynamic_fields->ts_residue.value;
	if(analyze_field_is_carryed(&rtp_dynamic_fields->ts_stride))
		rtph_ref->ts_stride = rtp_dynamic_fields->ts_stride.value;
	rohc_decomp_lsb_setup_ref_with_msn(rtph_context->ts_wlsb,ntohl(new_rtph->ts),msn);
	if(decomp_wlsb_analyze_field_is_carryed(&rtp_dynamic_fields->ts_scaled))
		rohc_decomp_lsb_setup_ref(rtph_context->ts_scaled_wlsb,rtp_dynamic_fields->ts_scaled.encode_v);
	return 0;
}

int rohc_v2_decomp_rtp_init_context(struct decomp_v2_rtph_context *rtph_context)
{
	int retval = 0;
	rtph_context->ts_wlsb = rohc_decomp_lsb_alloc(TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(rtph_context->ts_wlsb)){
		pr_err("rtpv2 alloc decomp timestatmp wlsb failed\n");
		retval = -ENOMEM;
		goto err0;
	}
	rtph_context->ts_scaled_wlsb = rohc_decomp_lsb_alloc(TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(rtph_context->ts_scaled_wlsb)){
		pr_err("rtpv2 alloc decomp timestatmp scaled wlsb failed\n");
		retval = -ENOMEM;
		goto err1;
	}
	return 0;
err1:
	rohc_decomp_lsb_free(rtph_context->ts_wlsb);
err0:
	return retval;
}

enum rohc_packet_type decomp_rtp_v2_adjust_packet_type(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct rohc_v2_decomp_common_context *co_context;
	struct rohc_v2_decomp_iph_context *iph_context;
	struct decomp_iph_field_update *iph_update;
	struct last_decomped_iph *iph_ref;

	enum rohc_packet_type packet_type;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	iph_context = &co_context->iph_context;

	iph_ref = &iph_context->iph_ref;
	iph_update = &iph_context->update_by_packet;
	if(DECOMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		analyze_data = skb->data + pkt_info->decomped_hdr_len + pkt_info->cid_len;
	}else
		analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(rohc_packet_is_co_repair(analyze_data))
		packet_type = ROHC_PACKET_TYPE_CO_REPAIR;
	else if(rohc_packet_is_generic_co_common(analyze_data))
		packet_type = ROHC_PACKET_TYPE_CO_COMMON;
	else if(rohc_packet_is_pt_0_crc3(analyze_data))
		packet_type = ROHC_PACKET_TYPE_PT_0_CRC3;
	else if(rohc_packet_is_pt_0_crc7_rtp(analyze_data))
		packet_type = ROHC_PACKET_TYPE_PT_0_CRC7;
	else if(pick_innermost_ipid_field(iph_update,iph_ref)){
		if(rohc_packet_is_pt_1_seq_id_rtp(analyze_data))
			packet_type = ROHC_PACKET_TYPE_PT_1_SEQ_ID;
		else if(rohc_packet_is_pt_1_seq_ts)
			packet_type = ROHC_PACKET_TYPE_PT_1_SEQ_TS;
		else if(rohc_packet_is_pt_2_seq_id_rtp(analyze_data))
			packet_type = ROHC_PACKET_TYPE_PT_2_SEQ_ID;
		else if(rohc_packet_is_pt_2_seq_ts(analyze_data))
			packet_type = ROHC_PACKET_TYPE_PT_2_SEQ_TS;
		else if(rohc_packet_is_pt_2_seq_both(analyze_data))
			packet_type = ROHC_PACKET_TYPE_PT_2_SEQ_BOTH;
		else{
			rohc_pr(ROHC_DRTP2,"%s :rtpv2 not support the packet_type:%x",__func__,*analyze_data);
			packet_type = ROHC_PACKET_TYPE_UNDECIDE;
		}
	}else{
		if(rohc_packet_is_pt_1_rnd(analyze_data))
			packet_type = ROHC_PACKET_TYPE_PT_1_RND;
		else if(rohc_packet_is_pt_2_rnd(analyze_data))
			packet_type = ROHC_PACKET_TYPE_PT_2_RND;
		else{
			rohc_pr(ROHC_DRTP2,"%s :rtpv2 not support the rnd  packet_type:%x",__func__,*analyze_data);
			packet_type = ROHC_PACKET_TYPE_UNDECIDE;
		}
	}
	rohc_pr(ROHC_DRTP2,"analyze packet type:%d\n",packet_type);
	return packet_type;
}

int decomp_rtp_v2_analyze_packet_header(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
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
			retval = rtp_analyze_co_header(context,skb,pkt_info);
			break;
	}
	rohc_pr(ROHC_DRTP2,"decomped_hdr_len = %d\n",pkt_info->decomped_hdr_len);
	return retval;
}

int decomp_rtp_v2_analyze_static_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	int retval;
	retval = rohc_v2_decomp_analyze_ip_static_chain(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DRTP2,"profile rtp v2 analyze ip static chain failed\n");
		retval = -EFAULT;
		goto out;
	}
	rohc_v2_analyze_udp_static_chain(context,skb,pkt_info);
	rohc_v2_analyze_rtp_static_chain(context,skb,pkt_info);

out:
	return retval;
}

int decomp_rtp_v2_analyze_dynamic_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	int retval;
	retval = rohc_v2_decomp_analyze_ip_dynamic_chain(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DRTP2,"profile rtp v2 analyze ip dynamic chain failed\n");
		retval = -EFAULT;
		goto out;
	}
	rohc_v2_analyze_udp_dynamic_chain(context,skb,pkt_info);
	retval = rohc_v2_analyze_rtp_dyamic_chain(context,skb,pkt_info);
out:
	return retval;
}

int decomp_rtp_v2_decode_packet_header(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	int retval;
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_rtp_v2_context *d_rtp_context;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_v2_context *)co_context->inherit_context;

	retval = rohc_v2_decode_common_msn(co_context);
	if(retval){
		rohc_pr(ROHC_DRTP2,"rtpv2 cid-%d decode msn faield\n",context->cid);
		goto out;
	}
	retval = rohc_v2_decode_ip_header(&co_context->iph_context,pkt_info,co_context->co_decode.new_msn);
	if(retval){
		rohc_pr(ROHC_DRTP2,"rtpv2 cid-%d decode ip header failed\n",context->cid);
		goto out;
	}
	retval = rohc_v2_decode_udp_header(&d_rtp_context->udph_context,pkt_info);
	if(retval)
		goto out;
	retval = rohc_v2_decode_rtp_header(&d_rtp_context->rtph_context,pkt_info,co_context->co_decode.new_msn);
	if(retval)
		goto out;
	retval = rtp_csrc_decode_ssr(&d_rtp_context->csrc_context,pkt_info);
out:
	return retval;
}

int decomp_rtp_v2_rebuild_packet_header(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_rtp_v2_context *d_rtp_context;
	struct sk_buff *decomp_skb;
	int retval;
	decomp_skb = context->decomp_skb;

	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_v2_context *)co_context->inherit_context;

	rohc_v2_rebuild_ip_header(&co_context->iph_context,decomp_skb,pkt_info);
	rohc_v2_rebuild_udp_header(&d_rtp_context->udph_context,decomp_skb,pkt_info);
	rohc_v2_rebuild_rtp_header(&d_rtp_context->rtph_context,&d_rtp_context->csrc_context,decomp_skb,pkt_info);
	return 0;
}

int decomp_rtp_v2_recover_net_packet_header(struct rohc_decomp_context *context,struct sk_buff *skb ,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct iphdr *iph;
	struct udphdr *udph;
	struct sk_buff *decomp_skb;

	struct rohc_v2_decomp_common_context *co_context;
	struct last_decomped_iph *iph_ref;
	int off;

	decomp_skb = context->decomp_skb;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;

	iph_ref = &co_context->iph_context.iph_ref;

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
	rohc_v2_rtp_net_header_dump(skb,context->cid,co_context->co_decode.new_msn,false);
	return 0;
}

u32 decomp_rtp_v2_last_decompressed_sn(struct rohc_decomp_context *context)
{
	struct rohc_v2_decomp_common_context *co_context;
	struct rohc_decomp_wlsb *msn_wlsb;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	msn_wlsb = co_context->msn_wlsb;
	return rohc_decomp_lsb_pick_ref(msn_wlsb,false);
}

u8 decomp_rtp_v2_sn_bit_width(struct rohc_decomp_context *context)
{
	return 16;
}

int decomp_rtp_v2_init_context(struct rohc_decomp_context *context)
{
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_rtp_v2_context *d_rtp_context;
	int retval;
	co_context = kzalloc(sizeof(struct rohc_v2_decomp_common_context),GFP_ATOMIC);
	if(!co_context){
		pr_err("profie rtpv2 alloc memery for decomp common context failed\n");
		retval = -ENOMEM;
		goto err0;
	}
	d_rtp_context = kzalloc(sizeof(struct decomp_rtp_v2_context),GFP_ATOMIC);
	if(!d_rtp_context){
		pr_err("profie rtpv2 alloc memery for rtp context failed\n");
		retval = -ENOMEM;
		goto err1;
	}
	co_context->msn_wlsb = rohc_decomp_lsb_alloc(TYPE_USHORT,GFP_ATOMIC);
	if(IS_ERR(co_context->msn_wlsb)){
		pr_err("alloc msn wlsb for rtp profile-v2 failed\n");
		retval = -ENOMEM;
		goto err2;
	}
	retval = rohc_v2_ip_init_context(&co_context->iph_context);
	if(retval){
		pr_err("init ip context for rtpv2 failed\n");
		goto err3;
	}
	retval = rohc_v2_decomp_rtp_init_context(&d_rtp_context->rtph_context);
	if(retval){
		goto err4;
	}
	context->inherit_context = co_context;
	co_context->inherit_context = d_rtp_context;
	return 0;
err4:
	rohc_v2_ip_destroy_context(&co_context->iph_context);
err3:
	rohc_decomp_lsb_free(co_context->msn_wlsb);
err2:
	kfree(d_rtp_context);
err1:
	kfree(co_context);
err0:
	return retval;
}

int decomp_rtp_v2_update_context(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_rtp_v2_context *d_rtp_context;
	u32 msn;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_v2_context *)co_context->inherit_context;

	msn = co_context->co_decode.new_msn;

	rohc_v2_ip_context_update(&co_context->iph_context,msn);
	rohc_v2_udp_update_context(&d_rtp_context->udph_context);
	rohc_v2_update_rtph_context(&d_rtp_context->rtph_context,msn);
	decomp_rtp_csrc_update_context(&d_rtp_context->csrc_context);
	rohc_decomp_lsb_setup_ref(co_context->msn_wlsb,msn);
	return 0;
}

static inline void decomp_rtp_v2_reset_update_by_packet(struct rohc_decomp_context *context)
{
	struct rohc_v2_decomp_common_context *co_context;
	struct decomp_rtp_v2_context *d_rtp_context;
	co_context = (struct rohc_v2_decomp_common_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_v2_context *)co_context->inherit_context;

	memset(&co_context->iph_context.update_by_packet,0,sizeof(struct decomp_iph_field_update));
	memset(&d_rtp_context->udph_context.update_by_packet,0,sizeof(struct decomp_udph_field_update));
	memset(&d_rtp_context->rtph_context.update_by_packet,0,sizeof(struct decomp_rtph_field_update));
	memset(&d_rtp_context->csrc_context.update_by_packet,0,sizeof(struct decomp_rtp_csrc_update));

	memset(&co_context->co_update,0,sizeof(struct rohc_v2_common_update));
	memset(&co_context->co_decode,0,sizeof(struct rohc_v2_common_decode));
}
int decomp_rtp_v2_decompress(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct rohc_decomp_profile_ops *decomp_prof_ops;
	int retval;
	decomp_prof_ops = context->decomp_profile->pro_ops;

	decomp_rtp_v2_reset_update_by_packet(context);
	retval = decomp_prof_ops->analyze_packet_header(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DRTP2,"profie-v2 rtp analyze header failed,cid :%d\n",context->cid);
		goto out;
	}
	retval = decomp_prof_ops->decode_packet_header(context,pkt_info);
	if(retval){
		rohc_pr(ROHC_DRTP2,"profie-v2 rtp decode header failed,cid :%d\n",context->cid);
		goto out;
	}
	retval = decomp_prof_ops->rebuild_packet_header(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DRTP2,"profie-v2 rtp rebuild header failed,cid :%d\n",context->cid);
		goto out;
	}
	decomp_prof_ops->update_context(context,pkt_info);
out:
	return retval;
}

struct rohc_decomp_profile_ops decomp_profv2_rtp_ops = {
	.adjust_packet_type = decomp_rtp_v2_adjust_packet_type,
	.analyze_packet_header = decomp_rtp_v2_analyze_packet_header,
	.analyze_static_chain = decomp_rtp_v2_analyze_static_chain,
	.analyze_dynamic_chain = decomp_rtp_v2_analyze_dynamic_chain,
	.decode_packet_header = decomp_rtp_v2_decode_packet_header,
	.rebuild_packet_header = decomp_rtp_v2_rebuild_packet_header,
	.recover_net_packet_header = decomp_rtp_v2_recover_net_packet_header,
	.decompress = decomp_rtp_v2_decompress,
	.last_decompressed_sn = decomp_rtp_v2_last_decompressed_sn,
	.sn_bit_width = decomp_rtp_v2_sn_bit_width,
	.init_context = decomp_rtp_v2_init_context,
	.update_context = decomp_rtp_v2_update_context,
};

struct rohc_decomp_profile decomp_profile_rtp_v2 = {
	.profile = ROHC_V2_PROFILE_RTP,
	.pro_ops = &decomp_profv2_rtp_ops,
};
