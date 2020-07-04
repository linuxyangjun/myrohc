/*
 *	rohc
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	Date   :	2020-05-27
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
#include "../profile/rtp_profile.h"

#include "rohc_comp.h"
#include "rohc_comp_wlsb.h"
#include "rohc_comp_packet.h"
#include "rohc_comp_v2_common.h"
#include "comp_udp_v2.h"
#include "comp_rtp_common.h"
#include "comp_rtp_clist.h"
#include "comp_rtp_v2.h"


bool rohc_comp_packet_is_rtp(const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct iphdr *iph;
	struct rtphdr *rtph,*from_rtph;
	struct udphdr *udph; 
	struct rtp_new_csrcs *rtph_csrc;
	struct rtp_csrc *ssrc;
	u32 *from_ssrc,*to_ssrc;
	udph = &pkt_info->udph;
	int i;
	bool retval;
	iph = ip_hdr(skb);
	rtph_csrc = &pkt_info->rtph_csrc;
#if 0
	rtph = (struct rtphdr *)skb->data + pkt_info->to_comp_pkt_hdr_len;
	if((udph->len - sizeof(struct udphdr)) < 12){
		retval = false;
		goto out;
	}
	if(rtph->version != 2){
		retval = false;
		goto out;
	}
	if(rtph->cc){
		/*now not support csrc list*/
		if(udph->len - sizeof(struct udphdr) < (12 + 4 * rtph->cc)){
			retval = false;
			goto out;
		}
	}
#endif
	udph = (struct udphr *)(iph + 1);
	if(ntohs(udph->source) == 31104)
		retval = true;
	else
		retval = false;
	if(retval){
		rtph = &pkt_info->rtph;
		from_rtph = (struct rtphdr *)(udph + 1);
		if(from_rtph->version != 2){
			rohc_pr(ROHC_DRTP2,"%s : rtp error version\n",__func__);
			retval = false;
		}
		memcpy(rtph,from_rtph,sizeof(struct rtphdr));
		pkt_info->to_comp_pkt_hdr_len += sizeof(struct rtphdr);
		if(rtph->cc){
			from_ssrc = (u32 *)(from_rtph + 1);

			for(i = 0 ; i < rtph->cc;i++){
				ssrc = &rtph_csrc->rtp_csrcs[i];
				memcpy(&ssrc->ssrc,from_ssrc,4);
				from_ssrc++;
			}
			rohc_pr(ROHC_DRTP2,"rtp_cc = %d\n",rtph->cc);
		}
		rtph_csrc->cc = rtph->cc;
		pkt_info->to_comp_pkt_hdr_len += rtph->cc * 4;
	}
out:
	return retval;
}

static inline u8 profile_1_flags_indicator(struct rtph_field_update *rtph_update,struct rtp_csrc_update *csrc_update)
{
	u8 ind = 0;
	if(csrc_update->csrc_list_update || rtph_update->pt_update || rtph_update->ts_stride_update || rtph_update->p_update || rtph_update->x_update)
		ind = 1;
	return ind;
}

static inline int profile_1_flags_build(u8 *to,struct rtphdr *rtph,struct rtph_field_update *rtph_update,struct rtp_csrc_update *csrc_update,int ind)
{

	u8 flag = 0;
	if(!ind)
		return 0;
	if(csrc_update->csrc_list_update)
		flag |= 1 << 7;
	if(rtph_update->pt_update)
		flag |= 1 << 6;
	flag |= rtph->p << 4;
	flag |= rtph->x << 3;
	*to = flag;
	return 1;

}
static inline u8 rohc_v2_profile_1_7_flags_indicator(struct rohc_v2_iph_context *iph_context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct iphdr *iph;
	struct iph_field_update *iph_update;
	u8 ind;
	bool outer_update = false;

	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		iph_update = &iph_context->update_by_packet;
		if(iph_update->ttl_hl_update || iph_update->tos_tc_update)
			outer_update = true;
		iph_update = &iph_context->inner_update_by_packet;
	}else{
		iph = &pkt_info->iph;
		iph_update = &iph_context->update_by_packet;
	}

	if(outer_update || iph_update->ttl_hl_update || iph_update->tos_tc_update || iph_update->df_update || iph_update->ipid_bh_update)
		ind = 1;
	else
		ind = 0;
	return ind;
}

static inline int rohc_v2_profile_1_7_flag_build(u8 *to,struct rohc_v2_iph_context *iph_context,struct rohc_comp_packet_hdr_info *pkt_info,enum rohc_v2_reordering_ratio rr,int flag)
{
	struct iphdr *iph;
	struct iph_field_update *iph_update;
	u8 outer_ind = 0;
	if(!flag)
		return 0;
	iph_update = &iph_context->update_by_packet;
	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		if(iph_update->ttl_hl_update || iph_update->tos_tc_update)
			outer_ind = 1;
		iph_update = &iph_context->inner_update_by_packet;
	}else{
		iph = &pkt_info->iph;
	}
	*to = outer_ind << 7;
	if(iph_update->ttl_hl_update){
		(*to) |= 1 << 6;
		inc_spec_iph_dynamic_field_trans_times(iph_context,IPH_FIELD_TTL_HL,true,pkt_info->has_inner_iph);

	}
	if(iph_update->tos_tc_update){
		(*to) |= 1 << 5;
		inc_spec_iph_dynamic_field_trans_times(iph_context,IPH_FIELD_TOS_TC,true,pkt_info->has_inner_iph);
	}
	if(rohc_iph_is_v4(iph->version)){
		(*to) |= (!!(ntohs(iph->frag_off) & IP_DF) << 4);
		(*to) |= (iph_update->new_ipid_bh & 0x3) << 2;
		inc_spec_iph_dynamic_field_trans_times(iph_context,IPH_FIELD_DF,true,pkt_info->has_inner_iph);
		inc_spec_iph_dynamic_field_trans_times(iph_context,IPH_FIELD_IPID_BH,true,pkt_info->has_inner_iph);
	}
	(*to) |= rr & 0x3;

	if(outer_ind){
		inc_spec_iph_dynamic_field_trans_times(iph_context,IPH_FIELD_TOS_TC,false,pkt_info->has_inner_iph);
		inc_spec_iph_dynamic_field_trans_times(iph_context,IPH_FIELD_TTL_HL,false,pkt_info->has_inner_iph);
	}
	return 1;
}
static inline int rohc_v2_sdvl_lsb_build(u8 *to,struct rohc_bits_encode_set *encode_set,u32 value)
{
	int encode_len;
	if(ROHC_ENCODE_BITS_TEST(encode_set,ROHC_ENCODE_BY_BITS(7))){
		*to = (SDVL_LSB_TYPE_0 << 7) | (value & 0x7f);
		encode_len = 1;
	}else if(ROHC_ENCODE_BITS_TEST(encode_set,ROHC_ENCODE_BY_BITS(14))){
		*to = (SDVL_LSB_TYPE_1 << 6) | ((value >> 8) & 0x3f);
		to++;
		*to = value & 0xff;
		encode_len = 2;
	}else if(ROHC_ENCODE_BITS_TEST(encode_set,ROHC_ENCODE_BY_BITS(21))){
		*to = ((SDVL_LSB_TYPE_2 << 5) | ((value >> 16) & 0x1f));
		to++;
		*to = (value >> 8) & 0xff;
		to++;
		*to = value & 0xff;
		encode_len = 3;
	}else if(ROHC_ENCODE_BITS_TEST(encode_set,ROHC_ENCODE_BY_BITS(28))){
		*to = (SDVL_LSB_TYPE_3 << 4) | ((value >> 24) & 0xf);
		to++;
		*to = (value >> 16) & 0xff;
		to++;
		*to = (value >> 8) & 0xff;
		to++;
		*to = value & 0xff;
		encode_len = 4;
	}else{
		*to = SDVL_LSB_TYPE_4;
		to++;
		/*change to network byte order*/
		value = htonl(value);
		memcpy(to,&value,4);
		encode_len = 5;
	}
	return encode_len;
}

static int rohc_v2_sdvl_or_static_build(u8 *to,u32 value,int ind)
{
	int encode_len ;
	if(!ind)
		return 0;
	if(value < (1 << 7)){
		*to = (SDVL_LSB_TYPE_0 << 7) | (value & 0x7f);
		encode_len = 1;
	}else if(value < (1 << 14)){
		*to = (SDVL_LSB_TYPE_1 << 6) | ((value >> 8) & 0x3f);
		to++;
		*to = value & 0xff;
		encode_len = 2;
	}else if(value < (1 << 21)){
		*to = ((SDVL_LSB_TYPE_2 << 5) | ((value >> 16) & 0x1f));
		to++;
		*to = (value >> 8) & 0xff;
		to++;
		*to = value & 0xff;
		encode_len = 3;
	}else if(value < (1 << 28)){
		*to = (SDVL_LSB_TYPE_3 << 4) | ((value >> 24) & 0xf);
		to++;
		*to = (value >> 16) & 0xff;
		to++;
		*to = (value >> 8) & 0xff;
		to++;
		*to = value & 0xff;
		encode_len = 4;
	}else{
		*to = SDVL_LSB_TYPE_4;
		to++;
		/*change to network byte order*/
		value = htonl(value);
		memcpy(to,&value,4);
		encode_len = 5;
	}
	return encode_len;
}
static inline void rtph_v2_cal_ts_encode_set(struct comp_win_lsb *ts_wlsb,struct rohc_bits_encode_set *ts_set,u32 new_ts)
{
	/*sdvl lsb support encode 7bits,14bits,21 bits,28bits,and 32bits*/
	if(comp_wlsb_can_encode_type_uint(ts_wlsb,7,ROHC_LSB_RTP_TS_K_TO_P(7),new_ts))
		ROHC_ENCODE_BITS_SET(ts_set,ROHC_ENCODE_BY_BITS(7));
	if(comp_wlsb_can_encode_type_uint(ts_wlsb,14,ROHC_LSB_RTP_TS_K_TO_P(14),new_ts))
		ROHC_ENCODE_BITS_SET(ts_set,ROHC_ENCODE_BY_BITS(14));
	if(comp_wlsb_can_encode_type_uint(ts_wlsb,21,ROHC_LSB_RTP_TS_K_TO_P(21),new_ts))
		ROHC_ENCODE_BITS_SET(ts_set,ROHC_LSB_RTP_TS_K_TO_P(21));
	if(comp_wlsb_can_encode_type_uint(ts_wlsb,28,ROHC_LSB_RTP_TS_K_TO_P(28),new_ts))
		ROHC_ENCODE_BITS_SET(ts_set,ROHC_ENCODE_BY_BITS(28));
}

static inline void rtph_v2_cal_ts_scaled_encode_set(struct comp_win_lsb *ts_scaled_wlsb,struct rohc_bits_encode_set *ts_scaled_set,u32 ts_scaled)
{
	/*sdvl ts scaled support encode 7bits,14,bits,21 bits,28 bits,and 32 bits*/
	if(comp_wlsb_can_encode_type_uint(ts_scaled_wlsb,7,ROHC_LSB_RTP_TS_K_TO_P(7),ts_scaled))
		ROHC_ENCODE_BITS_SET(ts_scaled_set,ROHC_ENCODE_BY_BITS(7));
	if(comp_wlsb_can_encode_type_uint(ts_scaled_wlsb,14,ROHC_LSB_RTP_TS_K_TO_P(14),ts_scaled))
		ROHC_ENCODE_BITS_SET(ts_scaled_set,ROHC_ENCODE_BY_BITS(14));
	if(comp_wlsb_can_encode_type_uint(ts_scaled_wlsb,21,ROHC_LSB_RTP_TS_K_TO_P(21),ts_scaled))
		ROHC_ENCODE_BITS_SET(ts_scaled_set,ROHC_ENCODE_BY_BITS(21));
	if(comp_wlsb_can_encode_type_uint(ts_scaled_wlsb,28,ROHC_LSB_RTP_TS_K_TO_P(28),ts_scaled))
		ROHC_ENCODE_BITS_SET(ts_scaled_set,ROHC_ENCODE_BY_BITS(28));

	if(comp_wlsb_can_encode_type_uint(ts_scaled_wlsb,5,ROHC_LSB_RTP_TS_K_TO_P(5),ts_scaled))
		ROHC_ENCODE_BITS_SET(ts_scaled_set,ROHC_ENCODE_BY_BITS(5));
	if(comp_wlsb_can_encode_type_uint(ts_scaled_wlsb,6,ROHC_LSB_RTP_TS_K_TO_P(6),ts_scaled))
		ROHC_ENCODE_BITS_SET(ts_scaled_set,ROHC_ENCODE_BY_BITS(6));
}
void rohc_v2_rtph_update_probe(struct v2_rtph_context *rtp_context,struct rohc_comp_packet_hdr_info *pkt_info,int oa_max)
{
	struct rtphdr *new_rtph,*old_rtph;
	struct last_comped_rtp *rtph_ref;
	struct rtph_field_update *rtph_update;
	struct rtph_update_trans_times *update_trans_times;
	u32 ts_stride,ts_residue,ts_scaled;
	rtph_ref = &rtp_context->rtph_ref;
	rtph_update = &rtp_context->update_by_packet;
	update_trans_times = &rtp_context->update_trans_times;
	new_rtph = &pkt_info->rtph;
	old_rtph = &rtph_ref->rtph;
	memset(rtph_update,0,sizeof(struct rtph_field_update));

	net_header_field_update_probe(new_rtph->ts,old_rtph->ts,&rtph_update->ts_update,&update_trans_times->ts_trans_times,oa_max);
	net_header_field_update_probe(new_rtph->m,old_rtph->m,&rtph_update->m_update,&update_trans_times->m_trans_times,oa_max);
	net_header_field_update_probe(new_rtph->p,old_rtph->p,&rtph_update->p_update,&update_trans_times->p_trans_times,oa_max);
	net_header_field_update_probe(new_rtph->pt,old_rtph->pt,&rtph_update->pt_update,&update_trans_times->pt_trans_times,oa_max);
	net_header_field_update_probe(new_rtph->x,old_rtph->x,&rtph_update->x_update,&update_trans_times->x_trans_times,oa_max);
	if(rtp_context->is_first_packet){
		rtph_update->ts_stride_use = TS_STRIDE_DEFAULT;
		rtph_update->ts_stride_true = TS_STRIDE_DEFAULT;
	}else{
		ts_stride = ntohl(new_rtph->ts) - ntohl(old_rtph->ts);
		rtp_field_scaling(ts_stride,&ts_scaled,ntohl(new_rtph->ts),&ts_residue);
		net_header_field_update_probe(ts_stride,rtph_ref->ts_stride,&rtph_update->ts_stride_update,&update_trans_times->ts_stride_trans_times,oa_max);
		if(ts_stride){
			net_header_field_update_probe(ts_residue,rtph_ref->ts_residue,&rtph_update->ts_residue_update,&update_trans_times->ts_residue_trans_times,oa_max);
		}else{
			rtph_update->ts_residue_update = true;
			rtph_update->ts_stride_update = true;
		}
		rtph_update->ts_stride_true = ts_stride;
		if(ts_stride){
			rtph_update->ts_stride_use = ts_stride;
		}else
			rtph_update->ts_stride_use = rtph_ref->ts_residue;
		rtph_update->ts_scaled = ts_scaled;
		rtph_update->ts_residue = ts_residue;
		rtph_v2_cal_ts_encode_set(rtp_context->ts_wlsb,&rtph_update->ts_encode_bits,ntohl(new_rtph->ts));
		rtph_v2_cal_ts_scaled_encode_set(rtp_context->ts_scaled_wlsb,&rtph_update->ts_scaled_encode_bits,ts_scaled);
	}

}


int rohc_v2_rtp_build_pt_1_rnd(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	struct rtphdr *rtph;
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct rohc_v2_common_context *co_context;
	struct comp_rtp_v2_context *c_rtp_context;
	struct v2_rtph_context *rtp_context;
	struct rtph_field_update *rtph_update;
	struct pt_1_rnd	*rnd1;

	u16 msn;
	bool build_full;
	int encode_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_common_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_v2_context *)co_context->inherit_context;
	rtp_context = &c_rtp_context->rtph_context;
	rtph_update = &rtp_context->update_by_packet;

	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	rtph = &pkt_info->rtph;

	msn = context->co_fields.msn;
	if(COMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		rnd1 = (struct pt_1_rnd *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			rnd1 = (struct pt_1_rnd *)comp_hdr;
		else
			rnd1 = (struct pt_1_rnd *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		rnd1->disc = ROHC_PACKET_PT_1_RND >> 5;
		rnd1->msn = msn & 0xf;
		rnd1->m = rtph->m;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	rnd1->ts_scaled = rtph_update->ts_scaled & 0x1f;
	rnd1->crc = 0;

	encode_len += sizeof(struct pt_1_rnd);
	inc_rtph_dyanmic_field_trans_times(&c_rtp_context->rtph_context.update_trans_times,RTPH_FIELD_M);
	inc_rtph_dyanmic_field_trans_times(&c_rtp_context->rtph_context.update_trans_times,RTPH_FIELD_TS_SCALED);
out:
	pkt_info->comp_hdr_len += encode_len;
	skb_put(comp_skb,encode_len);
	return retval;
}


int rohc_v2_rtp_build_pt_1_seq_id(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct rohc_v2_common_context *co_context;
	struct rohc_v2_iph_context *iph_context;
	struct pt_1_seq_id_rtp *seq_id;
	u16 msn,ipid_off;
	bool build_full;
	int encode_len = 0;
	int retval = 0;
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	iph_context = &co_context->iph_context;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);

	if(COMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		seq_id = (struct pt_1_seq_id_rtp *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			seq_id = (struct pt_1_seq_id_rtp *)comp_hdr;
		else
			seq_id = (struct pt_1_seq_id_rtp *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		seq_id->disc = ROHC_PACKET_PT_1_SEQ_ID_RTP >> 4;
		pick_innermost_seq_ipid_offset(iph_context,pkt_info->has_inner_iph,&ipid_off);
		seq_id->ipid_off = ipid_off & 0xf;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	msn = context->co_fields.msn;
	seq_id->msn = msn & 0x1f;
	seq_id->crc = 0;
	encode_len += sizeof(struct pt_1_seq_id_rtp) - 1;
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rohc_v2_rtp_build_pt_1_seq_ts(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	struct rtphdr *rtph;
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct rohc_v2_common_context *co_context;
	struct comp_rtp_v2_context *c_rtp_context;
	struct rtph_field_update *rtph_update;
	struct pt_1_seq_ts *seq_ts;
	u16 msn;
	bool build_full;
	int encode_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_common_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_v2_context *)co_context->inherit_context;
	rtph_update = &c_rtp_context->rtph_context.update_by_packet;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);

	rtph = &pkt_info->rtph;

	if(COMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		seq_ts = (struct pt_1_seq_ts *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			seq_ts = (struct pt_1_seq_ts *)comp_hdr;
		else
			seq_ts = (struct pt_1_seq_ts *)(comp_hdr - 1);
		build_full = false;
	}
	msn = context->co_fields.msn;
	if(build_first){
		seq_ts->disc = ROHC_PACKET_PT_1_SEQ_TS >> 5;
		seq_ts->m = rtph->m;
		seq_ts->msn = msn & 0xf;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	seq_ts->ts_scaled = rtph_update->ts_scaled & 0x1f;
	seq_ts->crc = 0;
	encode_len += sizeof(struct pt_1_seq_ts) - 1;
	inc_rtph_dyanmic_field_trans_times(&c_rtp_context->rtph_context.update_trans_times,RTPH_FIELD_M);
	inc_rtph_dyanmic_field_trans_times(&c_rtp_context->rtph_context.update_trans_times,RTPH_FIELD_TS_SCALED);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rohc_v2_rtp_build_pt_2_rnd(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct rtphdr *rtph;
	struct rohc_v2_common_context *co_context;
	struct comp_rtp_v2_context *c_rtp_context;
	struct rtph_field_update *rtph_update;
	struct pt_2_rnd *rnd;
	u16 msn;
	bool build_full;
	int encode_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_common_context *)context->prof_context;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);

	msn = context->co_fields.msn;
	if(COMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		rnd = (struct pt_2_rnd *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			rnd = (struct pt_2_rnd *)comp_hdr;
		else
			rnd = (struct pt_2_rnd *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		rnd->disc = ROHC_PACKET_PT_2_RND >> 5;
		rnd->msn0 = (msn >> 2) & 0x1f;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	rnd->msn1 = msn & 0x3;
	c_rtp_context = (struct comp_rtp_v2_context *)co_context->inherit_context;
	rtph_update = &c_rtp_context->rtph_context.update_by_packet;
	rnd->ts_scaled = rtph_update->ts_scaled & 0x3f;
	rtph = &pkt_info->rtph;
	rnd->m = rtph->m;
	rnd->crc = 0;

	encode_len += sizeof(struct pt_2_rnd) - 1;
	inc_rtph_dyanmic_field_trans_times(&c_rtp_context->rtph_context.update_trans_times,RTPH_FIELD_M);
	inc_rtph_dyanmic_field_trans_times(&c_rtp_context->rtph_context.update_trans_times,RTPH_FIELD_TS_SCALED);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}


int rohc_v2_rtp_build_pt_2_seq_id(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct rohc_v2_common_context *co_context;
	struct rohc_v2_iph_context *iph_context;
	struct pt_2_seq_id_rtp *seq_id;
	u16 msn,ipid_off;
	bool build_full;
	int encode_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_common_context *)context->prof_context;
	iph_context = &co_context->iph_context;

	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	msn = context->co_fields.msn;
	if(COMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		seq_id = (struct pt_2_seq_id_rtp *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			seq_id = (struct pt_2_seq_id_rtp *)comp_hdr;
		else
			seq_id = (struct pt_2_seq_id_rtp *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		seq_id->disc = ROHC_PACKET_PT_2_SEQ_ID_RTP >> 3;
		seq_id->msn0 = (msn >> 4) & 0x7;
		encode_len = 1;
	}

	if(!build_full && build_first)
		goto out;
	seq_id->msn1 = msn & 0xf;
	pick_innermost_seq_ipid_offset(iph_context,pkt_info->has_inner_iph,&ipid_off);
	seq_id->ipid_off0 = (ipid_off >> 1) & 0xf;
	seq_id->ipid_off1 = ipid_off & 0x1;

	encode_len += sizeof(struct pt_2_seq_id_rtp) - 1;
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rohc_v2_rtp_build_pt_2_seq_both(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct rtphdr *rtph;
	struct sk_buff *comp_skb;
	struct rohc_v2_common_context *co_context;
	struct rohc_v2_iph_context *iph_context;
	struct comp_rtp_v2_context *c_rtp_context;
	struct rtph_field_update *rtph_update;
	struct pt_2_seq_both *seq_both;
	u16 msn,ipid_off;
	bool build_full;

	int encode_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_common_context *)context->prof_context;

	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	msn = context->co_fields.msn;

	if(COMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		seq_both = (struct pt_2_seq_both *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			seq_both = (struct pt_2_seq_both *)comp_hdr;
		else
			seq_both = (struct pt_2_seq_both *)(comp_hdr - 1);
		build_full = false;
	}

	if(build_first){
		seq_both->disc = ROHC_PACKET_PT_2_SEQ_BOTH >> 3;
		seq_both->msn0 = msn >> 4;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	seq_both->msn1 = msn & 0xf;
	iph_context = &co_context->iph_context;
	c_rtp_context = (struct comp_rtp_v2_context *)co_context->inherit_context;
	rtph_update = &c_rtp_context->rtph_context.update_by_packet;

	rtph = &pkt_info->rtph;

	pick_innermost_seq_ipid_offset(iph_context,pkt_info->has_inner_iph,&ipid_off);
	seq_both->ipid_off0 = ipid_off >> 1;

	seq_both->ipid_off1 = ipid_off & 0x1;
	seq_both->crc = 0;
	seq_both->m = rtph->m;
	seq_both->ts_scaled = rtph_update->ts_scaled & 0x7f;

	encode_len += sizeof(struct pt_2_seq_both) - 1;

	inc_rtph_dyanmic_field_trans_times(&c_rtp_context->rtph_context.update_trans_times,RTPH_FIELD_M);
	inc_rtph_dyanmic_field_trans_times(&c_rtp_context->rtph_context.update_trans_times,RTPH_FIELD_TS_SCALED);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rohc_v2_rtp_build_pt_2_seq_ts(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct rtphdr *rtph;
	struct sk_buff *comp_skb;
	struct rohc_v2_common_context *co_context;
	struct comp_rtp_v2_context *c_rtp_context;
	struct rtph_field_update *rtph_update;
	struct pt_2_seq_ts *seq_ts;

	u16 msn;
	bool build_full;
	int encode_len = 0;
	int retval = 0;
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_v2_context *)co_context->inherit_context;

	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);

	if(COMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		seq_ts = (struct pt_2_seq_ts *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			seq_ts = (struct pt_2_seq_ts *)comp_hdr;
		else
			seq_ts= (struct pt_2_seq_ts *)(comp_hdr - 1);
		build_full = false;
	}

	if(build_first){
		seq_ts->disc = ROHC_PACKET_PT_2_SEQ_TS >> 4;
		seq_ts->msn0 = msn >> 3;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	seq_ts->msn1 = msn & 0x7;
	rtph_update = &c_rtp_context->rtph_context.update_by_packet;
	rtph = &pkt_info->rtph;
	seq_ts->ts_scaled = rtph_update->ts_scaled & 0x1f;
	seq_ts->m = rtph->m;
	seq_ts->crc = 0;
	encode_len += sizeof(struct pt_2_seq_ts) - 1;
	inc_rtph_dyanmic_field_trans_times(&c_rtp_context->rtph_context.update_trans_times,RTPH_FIELD_M);
	inc_rtph_dyanmic_field_trans_times(&c_rtp_context->rtph_context.update_trans_times,RTPH_FIELD_TS_SCALED);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rohc_v2_rtp_build_pt_0_crc7(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct pt_0_crc7_rtp *crc_rtp;

	u16 msn;
	bool build_full;
	int encode_len = 0;
	int retval = 0;

	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	if(COMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		crc_rtp = (struct pt_0_crc7_rtp *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			crc_rtp = (struct pt_0_crc7_rtp *)comp_hdr;
		else
			crc_rtp = (struct pt_0_crc7_rtp *)(comp_hdr - 1);
		build_full = false;
	}
	msn = context->co_fields.msn;
	if(build_first){
		crc_rtp->disc = ROHC_PACKET_PT_0_CRC7_RTP >> 4;
		crc_rtp->msn0 = msn >> 1;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	crc_rtp->msn1 = msn & 0x1;
	crc_rtp->crc = 0;
	encode_len += sizeof(struct pt_0_crc7_rtp) - 1;
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rohc_v2_rtp_build_co_common(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct rtphdr *rtph;
	struct rohc_v2_common_context *co_context;
	struct comp_rtp_v2_context *c_rtp_context;
	struct rohc_v2_iph_context *iph_context;
	struct rtph_field_update *rtph_update;
	struct rtp_csrc_update *csrc_update;
	struct iph_field_update *innermost_iph_update;
	struct profile_rtp_co_common *co_common;
	u16 msn;
	bool build_full;
	int call_len;
	int encode_len = 0;
	int retval = 0;
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	iph_context = &co_context->iph_context;
	c_rtp_context = (struct comp_rtp_v2_context *)co_context->inherit_context;

	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	msn = context->co_fields.msn;

	if(COMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		co_common = (struct profile_rtp_co_common *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			co_common = (struct profile_rtp_co_common *)comp_hdr;
		else
			co_common = (struct profile_rtp_co_common *)(comp_hdr - 1);
		build_full = false;
	}

	if(build_first){
		co_common->disc = ROHC_PACKET_GENERIC_CO_COMMON;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	rtph = &pkt_info->rtph;
	co_common->mark = rtph->m;
	co_common->crc = 0;
	co_common->ctrl_crc = 0;
	if(innermost_ipid_bh_is_seq(iph_context,pkt_info)){
		if(innermost_ipid_encode_set_test(iph_context,pkt_info->has_inner_iph,ROHC_ENCODE_BY_BITS(8)))
			co_common->ipid_ind = 0;
		else
			co_common->ipid_ind = 1;
	}else
		co_common->ipid_ind = 0;

	rtph_update = &c_rtp_context->rtph_context.update_by_packet;
	csrc_update = &c_rtp_context->csrc_context.update_by_packet;
	co_common->flag1_ind = rohc_v2_profile_1_7_flags_indicator(iph_context,pkt_info);
	co_common->flag2_ind = profile_1_flags_indicator(rtph_update,csrc_update);

	co_common->tss_ind = rohc_v2_field_static_or_irreg_indicator(rtph_update->ts_stride_update && rtph_update->ts_stride_update);
	co_common->tsc_ind = !rohc_v2_field_static_or_irreg_indicator(rtph_update->ts_stride_update | rtph_update->ts_residue_update);

	encode_len += sizeof(struct profile_rtp_co_common) - 1;
	comp_hdr += encode_len;
	/*next fields are varibale length fields*/
	/*filed.1 iph filed indicator*/
	call_len = rohc_v2_profile_1_7_flag_build(comp_hdr,iph_context,pkt_info,REORDER_R_NONE,co_common->flag1_ind);
	comp_hdr += call_len;
	encode_len += call_len;
	call_len = profile_1_flags_build(comp_hdr,rtph,rtph_update,csrc_update,co_common->flag2_ind);
	comp_hdr += call_len;
	encode_len += call_len;
	if(pkt_info->has_inner_iph)
		innermost_iph_update = &iph_context->inner_update_by_packet;
	else
		innermost_iph_update = &iph_context->update_by_packet;
	/*innermost iph tos*/
	call_len = innermost_iph_field_static_or_irreg_build(comp_hdr,pkt_info,innermost_iph_update->tos_tc_update,IPH_FIELD_TOS_TC);
	comp_hdr += call_len;
	encode_len += call_len;
	/*innermost iph ttl hl*/
	call_len = innermost_iph_field_static_or_irreg_build(comp_hdr,pkt_info,innermost_iph_update->ttl_hl_update,IPH_FIELD_TTL_HL);
	comp_hdr += call_len;
	encode_len += call_len;
	/*rtph pt*/
	if(rtph_update->pt_update){
		*comp_hdr = rtph->pt & 0x7f;
		comp_hdr++;
		encode_len++;
	}
	rohc_pr(ROHC_DRTP2,"%s:encode_len = %d,comp_hdr_len=%d\n",__func__,encode_len,pkt_info->comp_hdr_len);
	/*seq num*/
	call_len = rohc_v2_sdvl_lsb_build(comp_hdr,&co_context->co_update.msn_encode_bits,msn);
	rohc_pr(ROHC_DRTP2,"BUILD_COMMON:msn %d,len=%d\n",msn & ((1 << (call_len * 8)) - 1),call_len);
	comp_hdr += call_len;
	encode_len += call_len;
	/*innermost iph ipid*/
	call_len = innermost_seq_ipid_variable_build(comp_hdr,pkt_info,iph_context,co_common->ipid_ind);
	comp_hdr += call_len;
	encode_len += call_len;

	/*timestamp or timestamp scaled*/
	if(!co_common->tsc_ind){
		call_len = rohc_v2_sdvl_lsb_build(comp_hdr,&rtph_update->ts_encode_bits,ntohl(rtph->ts));
		comp_hdr += call_len;
		encode_len += call_len;
		rohc_pr(ROHC_DRTP2,"%s[%d]:encode_len = %d,comp_hdr_len=%d\n",__func__,__LINE__,encode_len,pkt_info->comp_hdr_len);
	}else{
		call_len += rohc_v2_sdvl_lsb_build(comp_hdr,&rtph_update->ts_scaled_encode_bits,rtph_update->ts_scaled);
		comp_hdr += call_len;
		encode_len += call_len;
		rohc_pr(ROHC_DRTP2,"%s[%d]:encode_len = %d,comp_hdr_len=%d\n",__func__,__LINE__,encode_len,pkt_info->comp_hdr_len);
	}
	call_len = rohc_v2_sdvl_or_static_build(comp_hdr,rtph_update->ts_stride_use,co_common->tss_ind);
	comp_hdr += call_len;
	encode_len += call_len;
	/*last csrc list*/
	if(csrc_update->csrc_list_update){
		skb_put(comp_skb,encode_len);
		pkt_info->comp_hdr_len += encode_len;
		encode_len = 0;
		retval = rtp_v2_csrc_build_clist(&c_rtp_context->csrc_context,comp_skb,pkt_info);
		if(retval)
			rohc_pr(ROHC_DV2,"profile rtp v2 build csrc compresst list failed when build rtp common packet\n");
		else
			rohc_pr(ROHC_DRTP2,"csrc list update\n");
	}
	rohc_pr(ROHC_DRTP2,"%s:encode_len = %d,comp_hdr_len=%d\n",__func__,encode_len,pkt_info->comp_hdr_len);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}


int rohc_v2_build_rtp_static_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct rtphdr *rtph;
	struct profile_rtp_static *rtp_static;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	rtph = &pkt_info->rtph;

	rtp_static = (struct profile_rtp_static *)comp_hdr;
	rtp_static->ssrc = rtph->ssrc;
	skb_put(comp_skb,sizeof(struct profile_rtp_static));
	pkt_info->comp_hdr_len += sizeof(struct profile_rtp_static);
	return 0;
}

int rohc_v2_build_rtp_dynamic_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct rtphdr *rtph;
	struct sk_buff *comp_skb;
	struct rohc_v2_common_context *co_context;
	struct comp_rtp_v2_context *c_rtp_context;
	struct profile_v2_rtp_dynamic *rtp_dynamic;
	struct rtph_field_update *rtph_update;
	int call_len;

	u32 msn;
	int encode_len = 0;
	int retval = 0;
	rtph = &pkt_info->rtph;
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_v2_context *)co_context->inherit_context;
	rtph_update = &c_rtp_context->rtph_context.update_by_packet;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);

	rtp_dynamic = (struct profile_v2_rtp_dynamic *)comp_hdr;
	rtp_dynamic->r_ratio = rtph->version;
	rtp_dynamic->list_ind = 1;

	rtp_dynamic->tss_ind = rohc_v2_field_static_or_irreg_indicator(rtph_update->ts_stride_update && rtph_update->ts_stride_use);
	rtp_dynamic->tis_ind = 0;
	rtp_dynamic->pad_bit = rtph->p;
	rtp_dynamic->ext = rtph->x;
	rtp_dynamic->mark = rtph->m;
	rtp_dynamic->pt = rtph->pt;
	rtp_dynamic->seq = rtph->seq;
	rtp_dynamic->ts = rtph->ts;
	encode_len = sizeof(struct profile_v2_rtp_dynamic);
	comp_hdr += encode_len;
	/*next fields is varibale length*/
	call_len = rohc_v2_sdvl_or_static_build(comp_hdr,rtph_update->ts_stride_use,rtp_dynamic->tss_ind);
	comp_hdr += call_len;
	encode_len += call_len;
	if(rtp_dynamic->list_ind){
		skb_put(comp_skb,encode_len);
		pkt_info->comp_hdr_len += encode_len;
		encode_len = 0;
		retval = rtp_v2_csrc_build_clist(&c_rtp_context->csrc_context,comp_skb,pkt_info);
	}
	if(encode_len){
		skb_put(comp_skb,encode_len);
		pkt_info->comp_hdr_len += encode_len;
	}
	return retval;
}

int comp_rtp_v2_build_irr_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct sk_buff *comp_skb;
	struct rohc_v2_common_context *co_context;
	struct rohc_v2_iph_context *iph_context;
	struct comp_rtp_v2_context *c_rtp_context;
	struct comp_udp_v2_context *udp_context;

	int retval;
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	iph_context = &co_context->iph_context;
	c_rtp_context = (struct comp_rtp_v2_context *)co_context->inherit_context;
	udp_context = &c_rtp_context->udph_context;

	comp_skb = context->comp_skb;
	rohc_comp_v2_build_ip_irr_chain(iph_context,comp_skb,pkt_info);
	rohc_v2_build_udp_irr_chain(udp_context,comp_skb,pkt_info);
	return 0;
}
int rohc_v2_rtp_build_co_header(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
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
			build_co_func = rohc_v2_rtp_build_co_common;
			break;
		case ROHC_PACKET_TYPE_PT_0_CRC3:
			build_co_func = rohc_comp_v2_build_pt_0_crc3;
			break;
		case ROHC_PACKET_TYPE_PT_0_CRC7:
			build_co_func = rohc_v2_rtp_build_pt_0_crc7;
			break;
		case ROHC_PACKET_TYPE_PT_1_RND:
			build_co_func = rohc_v2_rtp_build_pt_1_rnd;
			break;
		case ROHC_PACKET_TYPE_PT_1_SEQ_ID:
			build_co_func = rohc_v2_rtp_build_pt_1_seq_id;
			break;
		case ROHC_PACKET_TYPE_PT_1_SEQ_TS:
			build_co_func = rohc_v2_rtp_build_pt_1_seq_ts;
			break;
		case ROHC_PACKET_TYPE_PT_2_RND:
			build_co_func = rohc_v2_rtp_build_pt_2_rnd;
			break;
		case ROHC_PACKET_TYPE_PT_2_SEQ_ID:
			build_co_func = rohc_v2_rtp_build_pt_2_seq_id;
			break;
		case ROHC_PACKET_TYPE_PT_2_SEQ_TS:
			build_co_func = rohc_v2_rtp_build_pt_2_seq_ts;
			break;
		case ROHC_PACKET_TYPE_PT_2_SEQ_BOTH:
			build_co_func = rohc_v2_rtp_build_pt_2_seq_both;
			break;
		default:
			rohc_pr(ROHC_DV2,"profile v2 rtp not support the compress packet type:%d\n",packet_type);
			retval = -EFAULT;
			goto out;
			break;
	}

	if(COMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		retval = rohc_cid_encode(cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		pkt_info->comp_hdr_len += cid_encode_len;
		skb_put(comp_skb,pkt_info->comp_hdr_len);
		build_co_func(context,skb,pkt_info,true);
	}else{
		skb_put(comp_skb,pkt_info->comp_hdr_len);
		build_co_func(context,skb,pkt_info,true);
		comp_hdr = skb_tail_pointer(comp_skb);
		retval = rohc_cid_encode(cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		pkt_info->comp_hdr_len += cid_encode_len;
		skb_put(comp_skb,cid_encode_len);
		build_co_func(context,skb,pkt_info,false);
	}
	retval = comp_rtp_v2_build_irr_chain(context,skb,pkt_info);
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

enum rohc_packet_type rtp_v2_adjust_packet_type_so(struct rohc_v2_common_context *co_context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rohc_v2_iph_context *iph_context;
	struct comp_rtp_v2_context *c_rtp_context;
	struct comp_udp_v2_context *udp_context;
	struct rtph_field_update *rtph_update;
	struct rtp_csrc_update *csrc_update;
	struct rohc_bits_encode_set *msn_encode_bits,*ts_scaled_encode_bits;
	enum rohc_packet_type packet_type;

	iph_context = &co_context->iph_context;
	c_rtp_context = (struct comp_rtp_v2_context *)co_context->inherit_context;
	udp_context = &c_rtp_context->udph_context;
	rtph_update = &c_rtp_context->rtph_context.update_by_packet;
	csrc_update = &c_rtp_context->csrc_context.update_by_packet;
	msn_encode_bits = &co_context->co_update.msn_encode_bits;
	ts_scaled_encode_bits = &rtph_update->ts_scaled_encode_bits;
	if(udp_context->update_by_packet.check_bh_update || \
	   (!ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(4)) &&\
	    !ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(5)) &&\
	    !ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(7)) &&\
	    !ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(14))))
		packet_type = ROHC_PACKET_TYPE_IR_DYN;
	else if(outer_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_DF) || \
		outer_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_IPID_BH))
			packet_type = ROHC_PACKET_TYPE_IR_DYN;
	else if(innermost_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_DF) ||\
		innermost_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_IPID_BH) ||\
		innermost_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_TOS_TC) ||\
		innermost_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_TTL_HL) ||\
		outer_iph_dynamic_field_update(iph_context,pkt_info,IPH_FIELD_TOS_TC) ||\
		outer_iph_dynamic_field_update(iph_context,pkt_info,IPH_FIELD_TTL_HL) ||\
		csrc_update->csrc_list_update || \
		rtph_update->ts_stride_update || \
		rtph_update->ts_residue_update ||\
		rtph_update->p_update ||\
		rtph_update->x_update ||
		rtph_update->pt_update){
			packet_type = ROHC_PACKET_TYPE_CO_COMMON;
			rohc_pr(ROHC_DRTP2,"%s[%d],csrc_update=%d,ts_stride_update:%d,ts_residue_update=%d,ts_stride=%lu\n",__func__,__LINE__,csrc_update->csrc_list_update,rtph_update->ts_stride_update,rtph_update->ts_residue_update,rtph_update->ts_stride_use);
	}
	else{
		if(!innermost_ipid_bh_is_seq(iph_context,pkt_info)){
			if(!rtph_update->m_update){
				if(ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(4)))
					packet_type = ROHC_PACKET_TYPE_PT_0_CRC3;
				else if(ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(5)))
					packet_type = ROHC_PACKET_TYPE_PT_0_CRC7;
				else if(ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(7)) &&\
					ROHC_ENCODE_BITS_TEST(ts_scaled_encode_bits,ROHC_ENCODE_BY_BITS(6)))
					packet_type = ROHC_PACKET_TYPE_PT_2_RND;
				else{
					packet_type = ROHC_PACKET_TYPE_CO_COMMON;
					rohc_pr(ROHC_DRTP2,"%s[%d]\n",__func__,__LINE__);
				}
			}else{
				if(ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(4)) &&\
				   ROHC_ENCODE_BITS_TEST(ts_scaled_encode_bits,ROHC_ENCODE_BY_BITS(5)))
					packet_type = ROHC_PACKET_TYPE_PT_1_RND;
				else if(ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(7)) &&\
					ROHC_ENCODE_BITS_TEST(ts_scaled_encode_bits,ROHC_ENCODE_BY_BITS(6)))
					packet_type = ROHC_PACKET_TYPE_PT_2_RND;
				else{
					packet_type = ROHC_PACKET_TYPE_CO_COMMON;
					rohc_pr(ROHC_DRTP2,"%s[%d]\n",__func__,__LINE__);
				}
			}
		}else{
			if(!innermost_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_IPID_OFF) && \
			   !rtph_update->m_update && \
			   ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(4)))
					packet_type = ROHC_PACKET_TYPE_PT_0_CRC3;
			else if(!innermost_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_IPID_OFF) && \
				!rtph_update->m_update && \
				ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(5)))
					packet_type = ROHC_PACKET_TYPE_PT_0_CRC7;
			else if(!rtph_update->m_update && \
			         innermost_ipid_encode_set_test(iph_context,pkt_info->has_inner_iph,ROHC_ENCODE_BY_BITS(4)) &&\
			         ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(5)))
				packet_type = ROHC_PACKET_TYPE_PT_1_SEQ_ID;
			else if(!innermost_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_IPID_OFF) &&\
				ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(4)) && \
				ROHC_ENCODE_BITS_TEST(ts_scaled_encode_bits,ROHC_ENCODE_BY_BITS(5)))
				packet_type = ROHC_PACKET_TYPE_PT_1_SEQ_TS;
			else if(!rtph_update->m_update && \
				innermost_ipid_encode_set_test(iph_context,pkt_info->has_inner_iph,ROHC_ENCODE_BY_BITS(5)) &&\
				ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(7)))
				packet_type = ROHC_PACKET_TYPE_PT_2_SEQ_ID;
			else if(!innermost_iph_dynamic_field_update(iph_context,pkt_info->has_inner_iph,IPH_FIELD_IPID_OFF) &&\
				ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(7)) && \
				ROHC_ENCODE_BITS_TEST(ts_scaled_encode_bits,ROHC_ENCODE_BY_BITS(5)))
				packet_type = ROHC_PACKET_TYPE_PT_2_SEQ_TS;
			else if(ROHC_ENCODE_BITS_TEST(msn_encode_bits,ROHC_ENCODE_BY_BITS(7)) && \
				ROHC_ENCODE_BITS_TEST(ts_scaled_encode_bits,ROHC_ENCODE_BY_BITS(7)) && \
				innermost_ipid_encode_set_test(iph_context,pkt_info->has_inner_iph,ROHC_ENCODE_BY_BITS(5)))
				packet_type = ROHC_PACKET_TYPE_PT_2_SEQ_BOTH;
			else{
				packet_type = ROHC_PACKET_TYPE_CO_COMMON;
				rohc_pr(ROHC_DRTP2,"%s[%d]\n",__func__,__LINE__);
			}

		}
	}

	return packet_type;
}

void comp_rtp_v2_update_probe(struct rohc_v2_common_context *co_context,struct rohc_comp_packet_hdr_info *pkt_info,u32 msn)
{
	int oa_max;
	struct comp_rtp_v2_context *c_rtp_context;
	c_rtp_context = (struct comp_rtp_v2_context *)co_context->inherit_context;
	oa_max = co_context->oa_upward_pkts;
	c_rtp_context = (struct comp_rtp_v2_context *)co_context->inherit_context;
	/*ip header update probe*/
	rohc_v2_iph_update_probe(&co_context->iph_context,pkt_info,oa_max,msn);
	/*udp header update probe*/
	rohc_v2_udph_update_probe(&c_rtp_context->udph_context,pkt_info,oa_max);
	/*rtp header update probe*/
	rohc_v2_rtph_update_probe(&c_rtp_context->rtph_context,pkt_info,oa_max);
	/*rtp csrc update probe*/
	rtp_csrc_update_probe(&c_rtp_context->csrc_context,pkt_info,oa_max);
	memset(&co_context->co_update,0,sizeof(struct rohc_v2_common_update));
	rohc_v2_cal_msn_encode_bits_set(&co_context->co_update.msn_encode_bits,co_context->msn_wlsb,REORDER_R_NONE,msn,TYPE_USHORT);
}
enum rohc_packet_type comp_rtp_v2_adjust_packet_type(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rohc_v2_common_context *co_context;
	enum rohc_packet_type packet_type;

	co_context = (struct rohc_v2_common_context *)context->prof_context;
	comp_rtp_v2_update_probe(co_context,pkt_info,context->co_fields.msn);

	switch(context->context_state){
		case COMP_STATE_IR:
			packet_type = ROHC_PACKET_TYPE_IR;
			break;
		case COMP_STATE_FO:
			packet_type = ROHC_PACKET_TYPE_IR_DYN;
			break;
		default:
			packet_type = rtp_v2_adjust_packet_type_so(co_context,pkt_info);
			break;
	}
	rohc_pr(ROHC_DV2,"detect packet type:%d\n",packet_type);
	return packet_type;
}

void rohc_v2_rtp_update_context(struct v2_rtph_context *rtph_context,struct rohc_comp_packet_hdr_info *pkt_info,u32 msn)
{
	struct last_comped_rtp *rtph_ref;
	struct rtph_field_update *rtph_update;
	struct rtphdr *new_rtph,*to_rtph;

	rtph_ref = &rtph_context->rtph_ref;
	rtph_update = &rtph_context->update_by_packet;

	new_rtph = &pkt_info->rtph;
	to_rtph = &rtph_ref->rtph;
	memcpy(to_rtph,new_rtph,sizeof(struct rtphdr));
	if(rtph_update->ts_stride_use){
		rtph_ref->ts_stride = rtph_update->ts_stride_use;
		comp_wlsb_add(rtph_context->ts_scaled_wlsb,NULL,msn,rtph_update->ts_scaled);
		rtph_ref->ts_residue = rtph_update->ts_residue;
	}
	comp_wlsb_add(rtph_context->ts_wlsb,NULL,msn,ntohl(new_rtph->ts));
	rtph_context->is_first_packet = false;
}


int rohc_v2_rtp_init_context(struct v2_rtph_context *rtph_context,int oa_max)
{
	int retval;
	rtph_context->ts_wlsb = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(rtph_context->ts_wlsb)){
		pr_err("alloc timestamp wlsb failed for profilev2 rtp\n");
		retval = -ENOMEM;
		goto out;
	}
	rtph_context->ts_scaled_wlsb = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(rtph_context->ts_scaled_wlsb)){
		pr_err("alloc scaled timestamp wlsb failed for profilev2 rtp\n");
		retval = -ENOMEM;
		goto err1;
	}
	return 0;
err1:
	comp_wlsb_destroy(rtph_context->ts_wlsb);
out:
	return retval;
}


u32 comp_rtp_v2_new_msn(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u16 new_msn;
	struct rtphdr *rtph;
	rtph = &pkt_info->rtph;
	new_msn = ntohs(rtph->seq) & 0xffff;
	return new_msn;
}

int comp_rtp_v2_build_static_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	int retval;
	retval = rohc_comp_v2_build_ip_static_chain(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DRTP2,"rtpv2 cid-%d build ip static chain failed\n",context->cid);
		goto out;
	}
	retval = rohc_v2_build_udp_static_chain(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DRTP2,"rtpv2 cid-%d build udp static chain failed\n",context->cid);
		goto out;
	}
	retval = rohc_v2_build_rtp_static_chain(context,skb,pkt_info);
out:
	return retval;
}

int comp_rtp_v2_build_dynamic_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	int retval;
	retval = rohc_comp_v2_build_ip_dynamic_chain(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DRTP2,"rtpv2 cid-%d build ip dyanmic chain fialed\n",context->cid);
		goto out;
	}
	retval = rohc_v2_build_udp_dynamic_chain(context,skb,pkt_info);
	retval = rohc_v2_build_rtp_dynamic_chain(context,skb,pkt_info);
	if(retval){
		rohc_pr(ROHC_DRTP2,"rtpv2 cid-%d build rtp dynamic chain failed\n",context->cid);
	}
out:
	return retval;
}
int comp_rtp_v2_feedback_input(struct rohc_v2_common_context *co_context,int ack_type,u32 msn,int msn_width,bool sn_valid)
{

	struct v2_rtph_context *rtph_context;
	struct comp_udp_v2_context *udp_context;
	struct comp_rtp_v2_context *c_rtp_context;
	struct rtp_csrc_context *csrc_context;
	c_rtp_context = (struct comp_rtp_v2_context *)co_context->inherit_context;
	udp_context = &c_rtp_context->udph_context;
	rtph_context = &c_rtp_context->rtph_context;
	switch(ack_type){
		case ROHC_FEEDBACK_ACK:
			udp_context->update_trans_times.check_bh_trans_time = co_context->oa_upward_pkts;
			confident_rtph_all_trans_times(&rtph_context->update_trans_times,co_context->oa_upward_pkts);
			break;
		case ROHC_FEEDBACK_NACK:
		case ROHC_FEEDBACK_STATIC_NACK:
			udp_context->update_trans_times.check_bh_trans_time = 0;
			reset_rtph_all_trans_times(&rtph_context->update_trans_times);
			break;

	}
	return 0;
}
struct rohc_v2_prof_ops rtp_v2_prof_ops = {
	.feedback_input = comp_rtp_v2_feedback_input,
};
int comp_rtp_v2_init_context(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rohc_v2_common_context *co_context;
	struct comp_rtp_v2_context *c_rtp_context;
	int retval = 0;
	co_context = kzalloc(sizeof(struct rohc_v2_common_context),GFP_ATOMIC);
	if(!co_context){
		pr_err("alloc memery for v2 common context of rtp error\n");
		retval = -ENOMEM;
		goto err0;
	}
	c_rtp_context = kzalloc(sizeof(struct comp_rtp_v2_context),GFP_ATOMIC);
	if(!c_rtp_context){
		pr_err("alloc memery for rtp v2 context failed\n");
		retval = -ENOMEM;
		goto err1;
	}
	co_context->oa_upward_pkts = 3;
	co_context->prof_ops = &rtp_v2_prof_ops;
	co_context->msn_wlsb = comp_wlsb_alloc(co_context->oa_upward_pkts,TYPE_USHORT,TYPE_USHORT,GFP_ATOMIC);
	if(IS_ERR(co_context->msn_wlsb)){
		pr_err("alloc wlsb for msn failed\n");
		goto err2;
	}
	retval = rohc_v2_comp_init_ip_context(&co_context->iph_context,co_context->oa_upward_pkts);
	if(retval){
		pr_err("rtpv2 init ip context failed\n");
		goto err3;
	}
	retval = rohc_v2_rtp_init_context(&c_rtp_context->rtph_context,co_context->oa_upward_pkts);
	if(retval){
		pr_err("rtpv2 init rtp context failed\n");
		goto err4;
	}
	retval = rtp_csrc_init_context(&c_rtp_context->csrc_context);
	context->prof_context = co_context;
	co_context->inherit_context = c_rtp_context;

	return 0;
err4:
	rohc_v2_destroy_ip_context(&co_context->iph_context);
err3:
	comp_wlsb_destroy(co_context->msn_wlsb);
err2:
	kfree(c_rtp_context);
err1:
	kfree(co_context);
err0:
	return retval;
}

void comp_rtp_v2_update_context(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rohc_v2_common_context *co_context;
	struct comp_rtp_v2_context *c_rtp_context;
	struct comp_udp_v2_context *udph_context;
	struct v2_rtph_context *rtph_context;
	struct rtp_csrc_context *csrc_context;
	u32 msn;
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_v2_context *)co_context->inherit_context;
	rtph_context = &c_rtp_context->rtph_context;
	udph_context = &c_rtp_context->udph_context;
	csrc_context = &c_rtp_context->csrc_context;
	msn = context->co_fields.msn;
	comp_wlsb_add(co_context->msn_wlsb,NULL,msn,msn);
	rohc_v2_update_ip_context(&co_context->iph_context,pkt_info,msn);
	rohc_v2_update_udph_context(udph_context,pkt_info);
	rohc_v2_rtp_update_context(rtph_context,pkt_info,msn);
	rtp_csrc_update_context(csrc_context,pkt_info);
}

int comp_rtp_v2_build_comp_header(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,enum rohc_packet_type type)
{
	int retval;
	pkt_info->packet_type = type;
	switch(type){
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
			retval = rohc_v2_rtp_build_co_header(context,skb,pkt_info);
			break;
	}
	return retval;
}

int comp_rtp_v2_compress(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	int retval;
	enum rohc_packet_type packet_type;
	struct comp_profile_ops *prof_ops;
	prof_ops = context->comp_profile->pro_ops;
	context->co_fields.msn = prof_ops->new_msn(context,pkt_info);
	packet_type = prof_ops->adjust_packet_type(context,skb,pkt_info);

	retval = prof_ops->build_comp_header(context,skb,pkt_info,packet_type);
	if(!retval)
		prof_ops->update_context(context,pkt_info);
	else
		rohc_pr(ROHC_DRTP2,"rtpv2 build compressed header failed\n");
	rohc_v2_rtp_net_header_dump(skb,context->cid,context->co_fields.msn,true);
	return retval;
}

struct comp_profile_ops comp_rtp_v2_prof_ops = {
	.adjust_packet_type = comp_rtp_v2_adjust_packet_type,
	.new_msn = comp_rtp_v2_new_msn,
	.build_static_chain = comp_rtp_v2_build_static_chain,
	.build_dynamic_chain = comp_rtp_v2_build_dynamic_chain,
	.compress = comp_rtp_v2_compress,
	.build_comp_header = comp_rtp_v2_build_comp_header,
	.init_context = comp_rtp_v2_init_context,
	.update_context = comp_rtp_v2_update_context,
	.feedback_input = rohc_comp_v2_feedback_input,
};


struct rohc_comp_profile comp_profile_v2_rtp = {
	.profile = ROHC_V2_PROFILE_RTP,
	.pro_ops = &comp_rtp_v2_prof_ops,
};
