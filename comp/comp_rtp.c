/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	Date   :	2020-05-15
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */



#include "rohc_comp_v1_packet.h"

int rtp_ts_encode_len_align_up_to_sdvl(struct rohc_bits_encode_set *ts_encode_bits,struct rohc_bits_encode_set *ts_sdvl_encode_bits,int additional_bits)
{
	int new_bits;

#define	TS_ENCODE_BITS(a) ((a) <=32 ? (a) : 32)
	if(ROHC_ENCODE_BITS_TEST(ts_encode_bits,additional_bits)){
		new_bits = 0;
	}else if(ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(TS_ENCODE_BITS(7 + additional_bits)))){
		new_bits = 7;
		ROHC_ENCODE_BITS_SET(ts_sdvl_encode_bits,ROHC_ENCODE_BY_BITS(7));
	}else if(ROHC_ENCODE_BITS_TEST(ts_encode_bits,ROHC_ENCODE_BY_BITS(TS_ENCODE_BITS(14 + additional_bits)))){
		new_bits = 14;
		ROHC_ENCODE_BITS_SET(ts_sdvl_encode_bits,ROHC_ENCODE_BY_BITS(14));
	}else if(ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(TS_ENCODE_BITS(21 + additional_bits)))){
		new_bits = 21;
		ROHC_ENCODE_BITS_SET(ts_sdvl_encode_bits,ROHC_ENCODE_BY_BITS(21));
	}else if(ROHC_ENCODE_BITS_TEST(ts_encode_bits,ROHC_ENCODE_BY_BITS(TS_ENCODE_BITS(29 + additional_bits)))){
		new_bits = 29;
		ROHC_ENCODE_BITS_SET(ts_sdvl_encode_bits,ROHC_ENCODE_BY_BITS(29));
	}
	return new_bits;
}
#if 0
bool rohc_comp_packet_is_rtp(const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct rtphdr *rtph;
	struct udphdr *udph; 
	udph = udp_hdr(skb);
	boo retval;
	rtph = (struct rtphdr *)skb->data + pkt_info->to_comp_pkt_hdr_len;
	if((udph->len - sizeof(struct udphdr)) < 12){
		retval = false;
		goto out;
	}
	if(rtp->version != 2){
		retval = false;
		goto out;
	}
	if(rtp->cc){
		/*now not support csrc list*/
		retval = false;

		goto out;
	}
out:
	return retval;
}
#endif
static inline void ts_set_bits_set(struct rohc_bits_encode_set *bits_set,int min_encode_bits)
{
	switch(min_encode_bits){
		case 5:
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(6));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(8));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(16));
			/* add sdvl bits when carried ext3 base 5 bits*/

			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(12));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_SET(19));
	
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(26));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(32));

			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(7));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(14));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(21));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(29));

			break;
		case 6:
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(8));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(16));
			/* add sdvl bits when carried ext3 base 5 bits*/
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(12));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_SET(19));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(26));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(32));

			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(7));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(14));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(21));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(29));
		case 7:
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(8));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(16));
			/* add sdvl bits when carried ext3 base 5 bits*/
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(12));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_SET(19));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(26));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(32));
			break;
		case 8:
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(16));
			/* add sdvl bits when carried ext3 base 5 bits*/
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(12));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_SET(19));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(26));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(32));
			break;
		case 14:
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(16));
			/* add sdvl bits when carried ext3 base 5 bits*/
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_SET(19));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(26));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(32));
			break;
		case 16:
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_SET(19));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(26));
			ROHC_ENCODE_BITS_SET(bits_set,ROHC_ENCODE_BY_BITS(32));
			break;
		case 19:
	}
}
static void ts_cal_encode_bits_set(struct rohc_comp_wlsb *ts_wlsb,struct rohc_bits_encode_set *ts_encode_bits,struct u32 new_ts)
{
	int min_encode_bits;
	if(comp_wlsb_can_encode_type_uint(ts_wlsb,5,ROHC_LSB_RTP_TS_K_TO_P(5),new_ts)){
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(5));
		min_encode_bits = 5;
	}else if(comp_wlsb_can_encode_type_uint(ts_wlsb,ROHC_LSB_RTP_TS_K_TO_P(6),new_ts)){
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(6));
		min_encode_bits = 6;
	}else if(comp_wlsb_can_encode_type_uint(ts_wlsb,7,ROHC_LSB_RTP_TS_K_TO_P(7),new_ts)){
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(7));
		min_encode_bits = 7;
	}else if(comp_wlsb_can_encode_type_uint(ts_wlsb,8,ROHC_LSB_RTP_TS_K_TO_P(8),new_ts)){
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(8));
		min_encode_bits = 8;
	}else if(comp_wlsb_can_encode_type_uint(ts_wlsb,9,ROHC_LSB_RTP_TS_K_TO_P(9),new_ts)){
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(9));
		min_encode_bits = 9;
	}else if(comp_wlsb_can_encode_type_uint(ts_wlsb,12,ROHC_LSB_RTP_TS_K_TO_P(12),new_ts)){ //5+7
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(12));
		min_encode_bits = 12;
	}else if(comp_wlsb_can_encode_type_uint(ts_wlsb,13,ROHC_LSB_RTP_TS_K_TO_P(13),new_ts)){ // 6 + 7
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(13));
		min_encode_bits = 13;
	}else if(comp_wlsb_can_encode_type_uint(ts_wlsb,14,ROHC_LSB_RTP_TS_K_TO_P(14),new_ts)){
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(14));
		min_encode_bits = 14;
	}else if(comp_wlsb_can_encode_type_uint(ts_wlsb,19,ROHC_LSB_RTP_TS_K_TO_P(19),new_ts)){ // 5 + 14
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(19));
		min_encode_bits = 19;
	}else if(comp_wlsb_can_encode_type_uint(ts_wlsb,16,ROHC_LSB_RTP_TS_K_TO_P(16),new_ts)){ //5+11
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(16));
		min_encode_bits = 16;
	}else if(comp_wlsb_can_encode_type_uint(ts_wlsb,17,ROHC_LSB_RTP_TS_K_TO_P(17),new_ts)){//6 + 11
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(17));
		min_encode_bits = 17;
	}else if(comp_wlsb_can_encode_type_uint(ts_wlsb,20,ROHC_LSB_RTP_TS_K_TO_P(20),new_ts)){ //6 + 14
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(20));
		min_encode_bits = 20;
	}else if(comp_wlsb_can_encode_type_uint(ts_wlsb,26,ROHC_LSB_RTP_TS_K_TO_P(26),new_ts)){ //5 + 21
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(26));
		min_encode_bits = 26;
	}else if(comp_wlsb_can_encode_type_uint(ts_wlsb,27,ROHC_LSB_RTP_TS_K_TO_P(27),new_ts)){ // 6 + 21
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(27));
		min_encode_bits = 27;
	}else if(comp_wlsb_can_encode_type_uint(ts_wlsb,29,ROHC_LSB_RTP_TS_K_TO_P(29),new_ts)){
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(29));
		min_encode_bits = 29;
	}else{
		ROHC_ENCODE_BITS_SET(ts_encode_bits,ROHC_ENCODE_BY_BITS(32));
		min_encode_bits = 32;
	}
	/*this only applicable when p is a constant*/
	bitmap_set(ts_encode_bits,min_encode_bits,(32 - min_encode_bits));
	ts_encode_bits->min_k = min_encode_bits;
}


static void comp_rtph_update_proble(struct comp_rtp_context *c_rtp_context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rtp_context *rtp_context;
	struct rtphdr *new_rtph,*old_rtph;
	struct last_comped_rtp *rtp_ref;
	struct rtph_update *new_rtph_update;
	struct rtph_update_trans_times *update_trans_times;
	u32 new_ts_stride,ts_scaled,ts_residue;

	rtp_context = &c_rtp_context->rtp_context;
	rtp_ref = &rtp_context->rtph_ref;
	new_rtph_update = &rtp_context->update_by_packet;
	update_trans_times = &rtp_context->update_trans_times;
	new_rtph = &pkt_info->rtph;
	old_rtph = &rtp_ref->rtph;
	if(rtp_context->is_first_packet){
		new_rtph_update->ts_stride_use = 1;
	}else{
		net_header_field_update_probe(new_rtph->ts,old_rtph->ts,&new_rtph_update->ts_update,&update_trans_times->ts_trans_times,rtp_context->oa_upward_pkts);
		net_header_field_update_probe(new_rtph->x,old_rtph->x,&new_rtph_update->x_update,&update_trans_times->x_trans_times,rtp_context->oa_upward_pkts);
		net_header_field_update_probe(new_rtph->p,old_rtph->p,&new_rtph_update->p_update,&update_trans_times->p_trans_times,rtp_context->oa_upward_pkts);
		net_header_field_update_probe(new_rtph->pt,old_rtph->pt,&new_rtph_update->pt_update,&update_trans_times->pt_trans_times,rtp_context->oa_upward_pkts);
		new_ts_stride = new_rtph->ts - old_rtph->ts;
		if(new_ts_stride && comp_wlsb_cal_appear_rate(rtp_context->ts_stride_wlsb,new_ts_stride) <= 50)
			new_ts_stride = rtp_ref->ts_stride;

		if(!new_ts_stride)
			new_ts_stride = rtp_ref->ts_stride;
		rtp_field_scaling(new_ts_stride,&ts_scaled,new_rtph->ts,&ts_residue);
		if(new_ts_stride){
			net_header_field_update_probe(new_ts_stride,rtp_ref->ts_stride,&new_rtph_update->ts_stride_update,&update_trans_times->ts_stride_tran_times,rtp_context->oa_upward_pkts);

			net_header_field_update_probe(ts_residue,rtp_ref->ts_residue,&new_rtph_update->ts_residue_update,&update_trans_times->ts_residue_trans_times,rtp_context->oa_upward_pkts);
		}else{
			new_rtph_update->ts_residue_update = true;
			update_trans_times->ts_residue_trans_times = 0;
		}
		if(new_ts_stride){
			new_rtph_update->ts_stride_use = new_ts_stride;
			new_rtph_update->ts_scaled = ts_scaled;
			new_rtph_update->ts_residue = ts_residue;
		}
		new_rtph_update->ts_stride_true = new_rtph->ts - old_rtph->ts;
		if(new_rtph_update->ts_residue_update || new_rtph_update->ts_stride_update){
			/*if timestamp stride change or ts residue change,only can transmit 
			 * timestamp,can't be scaled*/
			new_rtph_update->tsc = 0;
		}else
			new_rtph_update->tsc = 1;
		net_header_field_update_probe(new_rtph_update->tsc,rtp_ref->tsc,&new_rtph_update->tsc_update,&update_trans_times->tsc_trans_times,rtp_context->oa_upward_pkts);
		ts_cal_encode_bits_set(rtp_context->ts_wlsb,&new_rtph_update->ts_encode_bits,new_rtph->ts);
		if(!new_rtph_update->tsc)
			ts_cal_encode_bits_set(rtp_context->ts_scaled_wlsb,&new_rtph_update->ts_scaled_encode_bits,ts_scaled);
	}
}

int comp_rtp_build_uo1(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct rtphdr *rtph;
	struct sk_buff *comp_skb;
	struct comp_profile_v1_context *v1_context;
	struct comp_rtp_context *c_rtp_context;
	struct rtp_context *rtp_context;
	struct rtph_update *new_rtph_update;
	struct profile_rtp_uo1 *uo1;
	enum rohc_cid_type cid_type;
	bool build_full;
	u16 msn;
	int encode_len = 0;
	int retval = 0;

	comp_skb = context->comp_skb;
	v1_context = (struct comp_profile_v1_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_context *)v1_context->prof_context;
	rtp_context = &c_rtp_context->rtp_context;
	new_rtph_update = &rtp_context->update_by_packet;
	comp_hdr = skb_tail_pointer(comp_skb);
	rtph = &pkt_info->rtph;

	cid_type = context->compresser->cid_type;

	if(cid_type == CID_TYPE_SMALL){
		uo1 = (struct profile_rtp_uo1 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			uo1 = (struct profile_rtp_uo1 *)comp_hdr;
		else
			uo1 = (struct profile_rtp_uo1 *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		uo1->dsc = ROHC_PACKET_UO_1 >> 6;
		if(new_rtph_update->tsc)
			uo1->ts = new_rtph_update->ts_scaled & 0x3f;
		else
			uo1->ts = rtph->ts & 0x3f;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	msn = context->co_fields.msn;
	uo1->m = rtph->m;
	uo1->sn = msn & 0xf;
	uo1->crc = 0;
	encode_len += sizeof(struct profile_rtp_uo1) - 1;

out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}


int comp_rtp_build_uo1_id(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct rtphdr *rtph;
	struct sk_buff *comp_skb;
	struct comp_profile_v1_context *v1_context;
	struct comp_rtp_context *c_rtp_context;
	struct rtp_context *rtp_context;
	struct rtph_update *new_rtph_update;
	struct rtph_update_trans_times *update_trans_times;
	struct  msn_encode_bits *msn_k_bits;
	struct profile_rtp_uo1_id *uo1_id;

	enum rohc_ext_type ext_type;
	enum rohc_cid_type cid_type;
	bool build_full,is_inner_iph;
	bool x;
	u16 msn,ipid_off;
	int encode_len = 0;
	int retval = 0;

	v1_context = (struct comp_profile_v1_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_context *)v1_context->prof_context;
	rtp_context = &c_rtp_context->rtp_context;

	new_rtph_update = &rtp_context->update_by_packet;
	update_trans_times = &rtp_context->update_trans_times;
	msn_k_bits = &v1_context->msn_k_bits;

	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);

	ext_type = v1_context->packet_info.ext_type;
	cid_type = context->compresser->cid_type;
	msn = context->co_fields.msn;
	if(ext_type != EXT_TYPE_NONE)
		x = true;
	else
		x = false;
	if(cid_type == CID_TYPE_SMALL){
		uo1_id = (struct profile_rtp_uo1_id *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			uo1_id = (struct profile_rtp_uo1_id *)comp_hdr;
		else
			uo1_id = (struct profile_rtp_uo1_id *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		uo1_id->dsc = ROHC_PACKET_UO_1 >> 6;
		uo1_id->t = 0;
		rohc_comp_pick_non_rnd_const_ipid(v1_context,pkt_info,&ipid_off,&is_inner_iph);
		if(x){
			switch(ext_type){
				case EXT_TYPE_2:
					uo1_id->ipid_off = ipid_off >> 11;
					break;
				case EXT_TYPE_0:
				case EXT_TYPE_1:
					uo1_id->ipid_off = ipid_off >> 3;
					break;
				case EXT_TYPE_3:
					if(!specfied_iph_ipid_off_need_full_transmit(&v1_context->ip_context,is_inner_iph) && \
					    spcified_iph_ipid_off_encode_bits_test(&v1_context->ip_context,is_inner_iph,5))
						uo1_id->ipid_off = ipid_off & 0x1f;
					else{
						/*ipid full transmit by extension 3 IP-ID field*/
						uo1_id->ipid_off = 0;
					}
					break;
			}
	      }else{
		uo1_id->ipid_off = ipid_off & 0x1f;
	      }
	      encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	uo1_id->x = x;
	switch(ext_type){
		case EXT_TYPE_NONE:
			uo1_id->sn = msn & 0xf;
			break;
		case EXT_TYPE_0:
		case EXT_TYPE_1:
		case EXT_TYPE_2:
			uo1_id->sn = (msn >> 3) & 0xf;
		case EXT_TYPE_3:
			if(msn_encode_bits_set_test(msn_k_bits,4))
				uo1_id->sn = msn & 0xf;
			else
				uo1_id->sn = (msn >> 8) & 0xf;

	}

	uo1_id->crc = 0;
	encode_len += sizeof(struct profile_rtp_uo1_id) - 1;
	if(x){
		skb_put(comp_skb,encode_len);
		pkt_info->comp_hdr_len += encode_len;
		encode_len = 0;
		retval = v1_context->prof_v1_ops->bulid_extension(context,pkt_info);
		if(retval)
			rohc_pr(ROHC_DRTP,"profile rtp build extension-%d failed\n",ext_type);
	}
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int comp_rtp_build_uo1_ts(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct rtphdr *rtph;
	struct sk_buff *comp_skb;
	struct comp_profile_v1_context *v1_context;
	struct comp_rtp_context *c_rtp_context;
	struct rtp_context *rtp_context;
	struct rtph_update *new_rtph_update;
	struct profile_rtp_uo1_ts *uo1_ts;

	enum rohc_cid_type cid_type;

	bool build_full;
	u16 msn;

	int encode_len = 0;
	int retval = 0;
	
	v1_context = (struct comp_profile_v1_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_context *)v1_context->prof_context;
	rtp_context = &c_rtp_context->rtp_context;
	new_rtph_update = &rtp_context->update_by_packet;

	rtph = &pkt_info->rtph;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	cid_type = context->compresser->cid_type;
	msn = context->co_fields.msn;

	if(cid_type == CID_TYPE_SMALL){
		uo1_ts = (struct profile_rtp_uo1_ts *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			uo1_ts = (struct profile_rtp_uo1_ts *)comp_hdr;
		else
			uo1_ts = (struct profile_rtp_uo1_ts *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		uo1_ts->dsc = ROHC_PACKET_UO_1 >> 6;
		uo1_ts->t = 1;
		if(new_rtph_update->tsc)
			uo1_ts->ts = new_rtph_update->ts_scaled & 0x1f;
		else
			uo1_ts->ts = rtph->ts & 0x1f;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	uo1_ts->m = rtph->m;
	uo1_ts->sn = msn & 0xf;
	uo1_ts->crc = 0;
	encode_len += sizeof(struct profile_rtp_uo1_ts) - 1;
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
	
}

int comp_rtp_build_uor2(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct rtphdr *rtph;
	struct sk_buff *comp_skb;
	struct comp_profile_v1_context *v1_context;
	struct comp_rtp_context *c_rtp_context;
	struct rtp_context *rtp_context;
	struct rtph_update *new_rtph_update;
	struct rohc_bits_encode_set *ts_encode_bits;
	struct profile_rtp_uor2 *uor2;

	enum rohc_ext_type ext_type;
	enum rohc_cid_type cid_type;

	bool build_full,x;
	int new_bits;
	u32 new_ts;
	u16 msn;

	int encode_len = 0;
	int retval = 0;
	
	v1_context = (struct comp_profile_v1_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_context *)v1_context->prof_context;
	rtp_context = &c_rtp_context->rtp_context;

	new_rtph_update = &rtp_context->update_by_packet;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);

	msn = context->co_fields.msn;
	cid_type = context->compresser->cid_type;
	ext_type = v1_context->packet_info.ext_type;
	if(ext_type != EXT_TYPE_NONE)
		x = true;
	else
		x = false;

	if(cid_type == CID_TYPE_SMALL){
		uor2 = (struct profile_rtp_uor2 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			uor2 = (struct profile_rtp_uor2 *)comp_hdr;
		else
			uor2 = (struct profile_rtp_uor2 *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){

		if(new_rtph_update->tsc)
			new_ts = new_rtph_update->ts_scaled;
		else
			new_ts = rtph->ts;
		uor2->dsc = ROHC_PACKET_URO_2 >> 5;
		if(x){
			if(new_rtph_update->tsc)
				ts_encode_bits = &new_rtph_update->ts_scaled_encode_bits;
			else
				ts_encode_bits = &new_rtph_update->ts_encode_bits;
			switch(ext_type){
				case EXT_TYPE_0:
				case EXT_TYPE_1:
					uor2->ts0 = (new_ts >> 4) & 0x1f;
					new_bits = 3;
					break;
				case EXT_TYPE_2:
					uor2->ts0 = (new_ts >> 12) & 0x1f;
					new_bits = 11;
					break;
				case EXT_TYPE_3:
					new_bits = rtp_ts_encode_len_align_up_to_sdvl(ts_encode_bits,&new_rtph_update->ts_sdvl_encode_bits,6);
					uor2->ts0 = (new_ts >> (new_bits + 1)) & 0x1f;
					break;

			}
		}else{
			uor2->ts0 = (new_ts >> 1) & 0x1f;
			new_bits = 0;
		}
		encode_len = 1;
	}

	if(!build_full && build_first)
		goto out;
	uor2->ts1 = (new_ts >> new_bits) & 0x1;
	uor2->m = rtph->m;
	switch(ext_type){
		case EXT_TYPE_NONE:
			uor2->sn = msn & 0x3f;
			break;
		case EXT_TYPE_0:
		case EXT_TYPE_1:
		case EXT_TYPE_2:
			uor2->sn = (msn >> 3) & 0x3f;
		case EXT_TYPE_3:
			if(msn_encode_bits_set_test(msn_k_bits,6))
				uor2->sn = msn & 0x3f;
			else
				uor2->sn = (msn >> 8) & 0x3f;

	}

	uor2->crc = 0;
	encode_len += sizeof(struct profile_rtp_uor2) - 1;
	if(x){
		skb_put(comp_skb,encode_len);
		pkt_info->comp_hdr_len += encode_len;
		encode_len = 0;
		retval = v1_context->prof_v1_ops->bulid_extension(context,pkt_info);
		if(retval)
			rohc_pr(ROHC_DRTP,"profile rtp build extension-%d failed\n",ext_type);
	}
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
}

int comp_rtp_build_uor2_id(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct rtphdr *rtph;
	struct sk_buff *comp_skb;
	struct comp_profile_v1_context *v1_context;
	struct comp_rtp_context *c_rtp_context;
	struct rtp_context *rtp_context;
	struct rtph_update *new_rtph_update;
	struct rohc_bits_encode_set *ts_encode_bits;
	struct profile_rtp_uor2_id *uor2_id;
	struct  msn_encode_bits *msn_k_bits;

	enum rohc_ext_type ext_type;
	enum rohc_cid_type cid_type;

	bool build_full,x,is_inner_iph;

	u16 msn,ipid_off;

	int encode_len = 0;
	int retval = 0;
	v1_context = (struct comp_profile_v1_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_context *)v1_context->prof_context;
	rtp_context = &c_rtp_context->rtp_context;

	msn_k_bits = &v1_context->msn_k_bits;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	msn = context->co_fields.msn;

	ext_type = v1_context->packet_info.ext_type;
	cid_type = context->compresser->cid_type;
	if(ext_type != EXT_TYPE_NONE)
		x = true;
	else
		x= false;
	if(cid_type == CID_TYPE_SMALL){
		uor2_id = (struct profile_rtp_uor2_id *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			uor2_id = (struct profile_rtp_uor2_id *)comp_hdr;
		else
			uor2_id = (struct profile_rtp_uor2_id *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		rohc_comp_pick_non_rnd_const_ipid(v1_context,pkt_info,&ipid_off,&is_inner_iph);
		uor2_id->dsc = ROHC_PACKET_URO_2 >> 5;
		if(x){
			switch(ext_type){
				case EXT_TYPE_2:
					uor2_id->ipid_off = ipid_off >> 11;
					break;
				case EXT_TYPE_0:
				case EXT_TYPE_1:
					uor2_id->ipid_off = ipid_off >> 3;
					break;
				case EXT_TYPE_3:
					if(!specfied_iph_ipid_off_need_full_transmit(&v1_context->ip_context,is_inner_iph) && \
					    specified_iph_ipid_off_encode_bits_test(&v1_context->ip_context,is_inner_iph,5))
						uor2_id->ipid_off = ipid_off & 0x1f;
					else{
						/*ipid full transmit by extension 3 IP-ID field*/
						uor2_id->ipid_off = 0;
					}
					break;
			}
		}else
			uor2_id->ipid_off = ipid_off & 0x1f;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	uor2_id->t = 0;
	uor2_id->m = rtph->m;
	
	switch(ext_type){
		case EXT_TYPE_NONE;
			uor2_id->msn = msn & 0x3f;
			break;
		case EXT_TYPE_0:
		case EXT_TYPE_1:
		case EXT_TYPE_2:
			uor2_id->msn = (msn >> 3) & 0x3f;
			break;
		case EXT_TYPE_3:
			if(msn_encode_bits_set_test(msn_k_bits,6))
				uor2_id->msn = msn & 0x3f;
			else
				uor2_id->msn = (msn >> 8) & 0x3f;
			break;
	}
	uor2_id->x = x;
	uor2_id->crc = 0;
	encode_len += sizeof(struct profile_rtp_uor2_id) - 1;
	if(x){
		skb_put(comp_skb,encode_len);
		pkt_info->comp_hdr_len += encode_len;
		v1_context->prof_v1_ops->bulid_extension(context,pkt_info);
	}
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int comp_rtp_build_uor2_ts(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct rtphdr *rtph;
	struct sk_buff *comp_skb;
	struct comp_profile_v1_context *v1_context;
	struct comp_rtp_context *c_rtp_context;
	struct rtp_context *rtp_context;
	struct rtph_update *new_rtph_update;
	struct rohc_bits_encode_set *ts_encode_bits;
	struct profile_rtp_uor2_ts *uor2_ts;
	struct  msn_encode_bits *msn_k_bits;

	enum rohc_ext_type ext_type;
	enum rohc_cid_type cid_type;

	bool build_full,x;
	int new_bits;
	u32 new_ts;
	u16 msn;

	int encode_len = 0;
	int retval = 0;
	v1_context = (struct comp_profile_v1_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_context *)v1_context->prof_context;
	rtp_context = &c_rtp_context->rtp_context;

	new_rtph_update = &rtp_context->update_by_packet;
	msn_k_bits = &v1_context->msn_k_bits;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	msn = context->co_fields.msn;

	ext_type = v1_context->packet_info.ext_type;
	cid_type = context->compresser->cid_type;
	if(ext_type != EXT_TYPE_NONE)
		x = true;
	else
		x= false;
	if(cid_type == CID_TYPE_SMALL){
		uor2_ts = (struct profile_rtp_uor2_ts *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			uor2_ts = (struct profile_rtp_uor2_ts *)comp_hdr;
		else
			uor2_ts = (struct profile_rtp_uor2_ts *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		uor2_ts->dsc = ROHC_PACKET_URO_2 >> 5;
		if(new_rtph_update->tsc){
			new_ts = new_rtph_update->ts_scaled;
		}else{
			new_ts = rtph->ts;
		}

		if(x){
			if(new_rtph_update->tsc)
				ts_encode_bits = &new_rtph_update->ts_scaled_encode_bits;
			else
				ts_encode_bits = &new_rtph_update->ts_encode_bits;
			switch(ext_type){
				case EXT_TYPE_0:
				case EXT_TYPE_1:
					uor2_ts->ts = (new_ts >> 3) & 0x1f;
					break;
				case EXT_TYPE_2:
					uor2_ts->ts = (new_ts >> 11) & 0x1f;
					break;
				case EXT_TYPE_3:
					new_bits = rtp_ts_encode_len_align_up_to_sdvl(ts_encode_bits,&new_rtph_update->ts_sdvl_encode_bits,5);
					uor2_ts->ts = (new_ts >> new_bits) & 0x1f;
					break;
			}
		}else
			uor2_ts->ts = new_ts & 0x1f;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	uor2_ts->t = 1;
	uor2_ts->m = rtph->m;
	switch(ext_type){
		case EXT_TYPE_NONE:
			uor2_ts->sn = msn & 0x3f;
			break;
		case EXT_TYPE_0:
		case EXT_TYPE_1:
		case EXT_TYPE_2:
			uor2_ts->sn = (msn >> 3) & 0x3f;
			break;
		case EXT_TYPE_3:
			if(msn_encode_bits_set_test(msn_k_bits,6))
				uor2_ts->sn = msn & 0x3f;
			else
				uor2_ts->sn = (msn >> 8) & 0x3f;
			break;
	}
	uor2_ts->x = x;
	uor2_ts->crc = 0;
	encode_len += sizeof(struct profile_rtp_uor2_ts) - 1;
	if(x){
		skb_put(comp_skb,encode_len);
		pkt_info->comp_hdr_len += encode_len;
		encode_len = 0;
		retval = v1_context->prof_v1_ops->bulid_extension(context,pkt_info);
	}
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;

}

int comp_rtp_build_ext0(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct comp_profile_v1_context *v1_context;
	struct comp_rtp_context *c_rtp_context;
	struct rtp_context *rtp_context;
	struct rtph_update *new_rtph_update;
	struct sk_buff *comp_skb;
	struct rtphdr *rtph;
	enum rohc_packet_type packet_type;
	u16 msn,ipid_off;

	int encode_len = 0;
	int retval = 0;

	v1_context = (struct comp_profile_v1_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_context *)v1_context->prof_context;
	rtp_context = &c_rtp_context->rtp_context;

	new_rtph_update = &rtp_context->update_by_packet;
	comp_skb  = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	rtph = &pkt_info->rtph;

	msn = context->co_fields.msn;
	packet_type = pkt_info->packet_type;

	*comp_hdr = ROHC_EXT_0 | ((msn & 0x7) << 3);
	if(rohc_packet_carryed_rtp_ts(packet_type)){
		if(new_rtph_update->tsc)
			(*comp_hdr) |= new_rtph_update->ts_scaled & 0x7;
		else
			(*comp_hdr) |= rtph->ts & 0x7;
	}else{
		rohc_comp_pick_non_rnd_const_ipid(v1_context,pkt_info,&ipid_off,NULL);
		(*comp_hdr) |= ipid_off & 0x7;
	}
	skb_put(comp_skb,1);
	pkt_info->comp_hdr_len += 1;
	return retval;

}

int comp_rtp_build_ext1(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct rtphdr *rtph;
	struct comp_profile_v1_context *v1_context;
	struct comp_rtp_context *c_rtp_context;
	struct rtp_context *rtp_context;
	struct rtph_update *new_rtph_update;
	struct sk_buff *comp_skb;

	enum rtp_ext_t positive_t;
	enum rohc_packet_type packet_type;
	u16 msn,ipid_off;
	
	u32 new_ts;
	int encode_len = 0;
	int retval = 0;

	v1_context = (struct comp_profile_v1_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_context *)v1_context->prof_context;
	rtp_context = &c_rtp_context->rtp_context;

	new_rtph_update = &rtp_context->update_by_packet;
	
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	rtph = &pkt_info->rtph;

	packet_type = pkt_info->packet_type;
	msn = context->co_fields.msn;

	if(rohc_packet_carryed_rtp_ts(packet_type))
		positive_t = RTP_EXT_T_TS;
	else
		positive_t = RTP_EXT_T_IPID;
	if(new_rtph_update->tsc)
		new_ts = new_rtph_update->ts_scaled;
	else
		new_ts = rtph->ts;
	rohc_comp_pick_non_rnd_const_ipid(v1_context,pkt_info,&ipid_off,NULL);
	/*field.1 : type,sn,+T*/
	*comp_hdr = ROHC_EXT_1 | ((msn & 0x7) << 3);
	if(positive_t == RTP_EXT_T_TS){
		(*comp_hdr) |= new_ts & 0x7;
		encode_len++;
		comp_hdr++;
	}else{
		(*comp_hdr) |= ipid_off & 0x7;
		comp_hdr++;
		encode_len++;
	}
	/*field.2 -T*/
	if(positive_t == RTP_EXT_T_TS){
		*comp_hdr = ipid_off & 0xff;
		encode_len++;
	}else{
		*comp_hdr = new_ts & 0xff;
		encode_len++;
	}
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int comp_rtp_build_ext2(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct rtphdr *rtph;
	struct comp_profile_v1_context *v1_context;
	struct comp_rtp_context *c_rtp_context;
	struct rtp_context *rtp_context;
	struct rtph_update *new_rtph_update;
	struct sk_buff *comp_skb;

	enum rtp_ext_t positive_t;
	enum rohc_packet_type packet_type;
	u16 msn,ipid_off;
	
	u32 new_ts;
	int encode_len = 0;
	int retval = 0;

	v1_context = (struct comp_profile_v1_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_context *)v1_context->prof_context;
	rtp_context = &c_rtp_context->rtp_context;

	new_rtph_update = &rtp_context->update_by_packet;
	
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	rtph = &pkt_info->rtph;

	packet_type = pkt_info->packet_type;
	msn = context->co_fields.msn;
	if(rohc_packet_carryed_rtp_ts(packet_type))
		positive_t = RTP_EXT_T_TS;
	else
		positive_t = RTP_EXT_T_IPID;
	if(new_rtph_update->tsc)
		new_ts = new_rtph_update->ts_scaled;
	else
		new_ts = rtph->ts;
	rohc_comp_pick_non_rnd_const_ipid(v1_context,pkt_info,&ipid_off,NULL);
	/*field.1 :type,sn,+T */
	*comp_hdr = ROHC_EXT_2 | ((msn & 0x7) << 3);
	if(positive_t == RTP_EXT_T_TS){
		(*comp_hdr) |= (new_ts >> 8) & 0x7;
		/*field.2 +T*/
		comp_hdr++;
		encode_len++;
		*comp_hdr = new_ts & 0xff;
	}else{
		(*comp_hdr) |= (ipid_off >> 8) & 0x7;
		/*field.2 +T*/
		comp_hdr++;
		encode_len++;
		*comp_hdr = ipid_off & 0xff;
	}
	comp_hdr++;
	encode_len++;
	/*field.3 -T*/
	if(positive_t == RTP_EXT_T_TS){
		*comp_hdr = ipid_off & 0xff;
	}else
		*comp_hdr = new_ts & 0xff;
	encode_len++;
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

static int rtp_build_ext3_iph_flags(u8 *to,struct iph_update_info *iph_update,struct iph_behavior_info *iph_bh,struct iphdr *iph,bool i)
{
	u8 flags = 0;
	if(iph_update->tos_tc_update)
		flags = 1 << 7;
	if(iph_update->ttl_hl_update)
		flags |= 1 << 6;
	if(rohc_iph_is_v4(iph->version)){
		if(iph_bh->df)
			flags |= 1 << 5;
		if(iph_bh->nbo)
			flags |= 1 << 2;
		if(iph_bh->rnd)
			flags |= 1 << 1;
	}
	if(i)
		flags |= 1;
	*to = flags;
	return 1;
}

static int rtp_build_ext3_iph_fields(u8 *to,struct iphdr *iph,struct iph_update_info *iph_update)
{
	struct ipv6hdr *ipv6h;
	int encode_len = 0;
	if(rohc_iph_is_v4(iph->version)){
		if(iph_update->tos_tc_update){
			*to = iph->tos;
			to++;
			encode_len++;
		}
		if(iph_update->ttl_hl_update){
			*to = iph->ttl;
			to++;
			encode_len++;
		}
	}else{
		//ipv6 todo.
	}
	return encode_len;
}

static int rtp_build_ext3_rtph_flags(u8 *to,struct rtph_update *rtp_update,struct rtp_csrc_update *csrc_update, struct rtphdr *rtph,int context_mode)
{
	u8 flags = 0;
	flags = context_mode << 6;
	if(rtp_update->p_update || rtp_update->pt_update)
		flags |= 1 << 5;
	if(rtph->m)
		flags |= 1 << 4;
	if(rtph->x)
		flags |= 1 << 3;
	if(rtp_update->ts_stride_update)
		flags |= 1 << 1;
	if(csrc_update->csrc_list_update)
		flags |= 1 << 2;
	/*compressed csrc list and time_stride is not support for now
	 */
	*to = flags;
	return 1;

}

static int rtp_build_ext3_rtph_fileds(u8 *to,struct rtph_update *rtp_update,struct rtphdr *rtph)
{
	enum rohc_sd_vl_type vl_type;
	int encode_len = 0;
	int sdvl_len;
	/*filed.1 R-P and RTP PT*/
	if(rtp_update->p_update || rtp_update->pt_update){
		*to = (rtph->p << 7) | rtph->pt;
		encode_len++;
		to++;
	}
	/*compressed csrc list and time_stride is not support for now
	 */
	if(rtp_update->ts_stride_update){
		if(rohc_sd_vl_value_to_type(rtp_update->ts_stride_use,&vl_type)){
			rohc_pr(ROHC_DRTP,"%s ,ts stride use is too large:%lu\n",__func__,rtp_update->ts_stride_use);
		}
		rohc_sd_vl_encode(to,&sdvl_len,rtp_update->ts_stride_use,vl_type);
		encode_len += sdvl_len;
	}
	return encode_len;
}
static inline int rtp_ts_encode_bits_set_to_sdvl_type(struct rohc_bits_encode_set *bits_set,enum rohc_sd_vl_type *vl_type)
{
	int retval = 0;
	if(ROHC_ENCODE_BITS_TEST(bits_set,ROHC_ENCODE_BY_BITS(7)))
		*vl_type = ROHC_SD_VL_TYPE_0;
	else if(ROHC_ENCODE_BITS_TEST(bits_set,ROHC_ENCODE_BY_BITS(14)))
		*vl_typ = ROHC_SD_VL_TYPE_10;
	else if(ROHC_ENCODE_BITS_TEST(bits_set,ROHC_ENCODE_BY_BITS(21)))
		*vl_typ = ROHC_SD_VL_TYPE_110;
	else if(ROHC_ENCODE_BITS_TEST(bits_set,ROHC_ENCODE_BY_BITS(29)))
		*vl_type = ROHC_SD_VL_TYPE_111;
	else{
		rohc_pr(ROHC_DRTP,"extension 3 not support sdvl encode\n");
		retval = -EFAULT;
	}
	return retval;
}
int comp_rtp_build_ext3(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct rthdr *rtph;
	struct iphdr *iph,*inner_iph;
	struct comp_profile_v1_context *v1_context;
	struct comp_rtp_context *c_rtp_context;
	struct rtp_context *rtp_context;
	struct rtph_update *new_rtph_update;
	struct rtp_csrc_update *csrc_update;
	struct sk_buff *comp_skb;
	struct rohc_bits_encode_set *ts_encode_bits,*ts_sdvl_encode_bits;
	struct msn_encode_bits *msn_encode_bits;

	struct ip_context *ip_context;
	struct iph_update_info *outer_iph_update,*inner_iph_update;
	struct iph_behavior_info *outer_iph_bh,*inner_iph_bh;
	struct iph_oa_send_info *outer_oa_send_info,*inner_oa_send_info;
	enum rohc_packet_type packet_type;
	enum rohc_sd_vl_type vl_type;

	u32 new_ts;
	u16 msn,outer_ipid_off,inner_ipid_off;

	bool s,r_ts,tsc,i1,i2,ip1,ip2,rtp;
	int call_len;
	int encode_len = 0;
	int retval = 0;

	v1_context = (struct comp_profile_v1_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_context *)v1_context->prof_context;
	rtp_context = &c_rtp_context->rtp_context;
	ip_context = &v1_context->ip_context;
	new_rtph_update = &rtp_context->update_by_packet;
	csrc_update = &c_rtp_context->csrc_context.update_by_packet;
	outer_iph_update = &ip_context->update_by_packet.iph_updates[ROHC_OUTER_IPH];
	outer_iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_OUTER_IPH];
	outer_oa_send_info = &ip_context->oa_send_pkts[ROHC_OUTER_IPH];
	outer_ipid_off = outer_iph_update->ip_id_offset;
	
	iph = &pkt_info->iph;
	rtph = &pkt_info->rtph;
	msn_encode_bits = &v1_context->msn_k_bits;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);

	packet_type = pkt_info->packet_type;
	msn = context->co_fields.msn;
	if(rohc_packet_carryed_msn_4bits(packet_type)){
		if(msn_encode_bits_set_test(msn_encode_bits,4))
			s = false;
		else
			s = true;
	}else{
		if(msn_encode_bits_set_test(msn_encode_bits,6))
			s = false;
		else
			s = true;
	}
	if(pkt_info->has_inner_iph){

		inner_iph = &pkt_info->inner_iph;
		inner_iph_update = &ip_context->update_by_packet.iph_updates[ROHC_INNER_IPH];
		inner_iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_INNER_IPH];
		inner_oa_send_info = &ip_context->oa_send_pkts[ROHC_INNER_IPH];
		inner_ipid_off = inner_iph_update->ip_id_offset;

		if(rohc_iph_is_v4(inner_iph->version) && !ip_id_is_random_or_constant(inner_iph_bh->ip_id_bh)){
			if(specfied_iph_ipid_off_need_full_transmit(ip_context,true))
				i1 = true;
			else if(rohc_packet_carryed_ipid(packet_type)){
				if(specified_iph_ipid_off_encode_bits_test(ip_context,true,5)){
					i1 = false;
				}else
					i1 = true;
			}else if(inner_iph_update->ip_id_offset_update)
				i1 = true;
			else
				i1 = false;
			if(rohc_iph_is_v4(iph->version) && !ip_id_is_random_or_constant(outer_iph_bh->ip_id_bh)){
				if(outer_iph_update->df_update || outer_iph_update->ip_id_offset_update)
					i2 = true;
				else
					i2 = false;	
			}else 
				i2 = false;
		}else if(rohc_iph_is_v4(iph->version) && !ip_id_is_random_or_constant(outer_iph_update->ip_id_bh)){
			if(specfied_iph_ipid_off_need_full_transmit(ip_context,false))
				i1 = true;
			else if(rohc_packet_carryed_ipid(packet_type)){
				if(specified_iph_ipid_off_encode_bits_test(ip_context,false,5))
					i1 = false;
				else
					i1 = true;
			}else if(outer_iph_update->ip_id_offset_update)
				i1 = true;
			else
				i1 = false;
			i2 = false;
		}else{
			i1 = false;
			i2 = false;
		}
		if(iph_dynamic_fields_update(outer_iph_update) || i2)
			ip2 = true;
		else
			ip2 = false;
		if(iph_dynamic_fields_update(inner_iph_update) || ip2)
			ip1 = true;
		else
			ip1 = false;
	}else{
		if(rohc_iph_is_v4(iph->version) && !ip_id_is_random_or_constant(outer_iph_update->ip_id_bh)){
			if(specfied_iph_ipid_off_need_full_transmit(ip_context,false))
				i1 = true;
			else if(rohc_packet_carryed_ipid(packet_type)){
				if(specified_iph_ipid_off_encode_bits_test(ip_context,false,5))
					i1 = false;
				else 
					i1 = true;
			}else if(outer_iph_update->ip_id_offset_update)
				i1 = true;
			else
				i1 = false;
			i2 = false;

		}
		if(iph_dynamic_fields_update(outer_iph_update))
			ip1 = true;
		else
			ip1 = false;
		ip2 = false;
	}
	if(new_rtph_update->tsc){
		tsc = true;
		ts_encode_bits = &new_rtph_update->ts_scaled_encode_bits;
		new_ts = new_rtph_update->ts_scaled;
	}else{
		tsc = false;
		new_ts = rtph->ts;
		ts_encode_bits = &new_rtph_update->ts_encode_bits;
	}
	ts_sdvl_encode_bits = &new_rtph_update->ts_sdvl_encode_bits;
	if(rtp_dynamic_fields_update_without_m(new_rtph_update,csrc_update))
		rtp = true;
	else
		rtp = false;
	if(rohc_packet_carryed_rtp_ts(packet_type)){
		if(!ts_sdvl_encode_bits->k_set)
			r_ts = false;
		else
			r_ts = true;
	}else if(new_rtph_update->ts_update || new_rtph_update->ts_stride_update || new_rtph_update->ts_residue_update)
		r_ts = true;
	else
		r_ts = false;

	/*filed.1 FLAGS */
	*comp_hdr = ROHC_EXT_3 | (s << 5) | (r_ts << 4) | (tsc << 3) | (i1 << 2) | (ip1 << 1) | rtp;
	comp_hdr++;
	encode_len++;
	/*filed.2 inner ip header flags*/
	if(ip1){
		if(pkt_info->has_inner_iph){
			call_len = rtp_build_ext3_iph_flags(comp_hdr,inner_iph_update,inner_iph_bh,inner_iph,inner_iph,ip2);
			update_iph_oa_send_info_condition(inner_iph,inner_oa_send_info,inner_iph_update);
		}else{
			call_len = rtp_build_ext3_iph_flags(comp_hdr,outer_iph_update,outer_iph_bh,iph,ip2);
			update_iph_oa_send_info_condition(iph,outer_oa_send_info,outer_iph_update);
		}
		comp_hdr += call_len;
		encode_len += call_len;
	}
	/*filed.3 outer ip header flags*/
	if(ip2){
		call_len = rtp_build_ext3_iph_flags(comp_hdr,outer_iph_update,outer_iph_bh,iph,i2);
		update_iph_oa_send_info_condition(iph,outer_oa_send_info,outer_iph_update);
		comp_hdr += call_len;
		encode_len += call_len;
	}
	/*filed.4 sn*/
	if(s){
		*comp_hdr = msn & 0xff;
		comp_hdr++;
		encode_len++;
	}
	/*field.5 TS*/
	if(r_ts){
		if(rohc_packet_carryed_rtp_ts(packet_type)){
			retval = rtp_ts_encode_bits_set_to_sdvl_type(ts_sdvl_encode_bits,&vl_type);
			if(retval)
				goto out;
			rohc_sd_vl_encode(comp_hdr,&call_len,new_ts,vl_type);
		}else{
			retval = rtp_ts_encode_bits_set_to_sdvl_type(ts_encode_bits,&vl_type);
			if(retval)
				goto out;
			rohc_sd_vl_encode(comp_hdr,&call_len,new_ts,vl_type);
		}
		comp_hdr += call_len;
		encode_len += call_len;
	}
	/*filed.6 inner ip header fields*/
	if(ip1){
		if(pkt_info->has_inner_iph){
			call_len = rtp_build_ext3_iph_fields(comp_hdr,inner_iph,inner_iph_update);
		}else
			call_len = rtp_build_ext3_iph_fields(comp_hdr,iph,outer_iph_update);
		comp_hdr += call_len;
		encode_len += call_len;
	}
	/*filed.7 IP-ID(inner ip header ipid has high priority)*/
	if(i1){
		if(pkt_info->has_inner_iph){
			if(rohc_iph_is_v4(inner_iph->version) && !ip_id_is_random_or_constant(inner_iph_bh->ip_id_bh)){
				/*change to network byte order*/
				inner_ipid_off = htons(inner_ipid_off);
				memcpy(comp_hdr,&inner_ipid_off,2);
			}else{
				outer_ipid_off = htons(outer_ipid_off);
				memcpy(comp_hdr,&outer_ipid_off,2);
			}
		}else{
			outer_ipid_off = htons(outer_ipid_off);
			memcpy(comp_hdr,&outer_ipid_off,2);
		}
		comp_hdr += 2;
		encode_len += 2;
	}
	/*filed.8 outer ip header fields*/
	if(ip2){
		call_len = rtp_build_ext3_iph_fields(comp_hdr,iph,outer_iph_update);
		comp_hdr += call_len;
		encode_len += call_len;
		if(i2){
			outer_ipid_off = htons(outer_ipid_off);
			memcpy(comp_hdr,&outer_ipid_off,2);
			comp_hdr += 2;
			encode_len += 2;
		}

	}
	/*filed.9 rtp header fileds and flags*/
	if(rtp){
		call_len = rtp_build_ext3_rtph_flags(comp_hdr,new_rtph_update,csrc_update,rtph,context->mode);
		comp_hdr += call_len;
		encode_len += call_len;
		//call_len = rtp_build_ext3_rtph_fileds(comp_hdr,new_rtph_update,rtph);
		//encode_len += call_len;
		if(new_rtph_update->p_update || new_rtph_update->pt_update){
			*comp_hdr = (rtph->p << 7) | rtph->pt;
			encode_len++;
			comp_hdr++;
		}
		/*compressed csrc list*/
		if(csrc_update->csrc_list_update){
			skb_put(comp_skb,encode_len);
			pkt_info->comp_hdr_len += encode_len;
			encode_len = 0;
			retval = rtp_csrc_build_clist(&c_rtp_context->csrc_context,comp_skb,pkt_info);
			if(retval){
				rohc_pr(ROHC_DRTP,"profile rtp cid-%d build csrc compressed list failed when build extension3\n",context->cid);
				goto out;
			}
			comp_hdr = skb_tail_pointer(comp_skb);
		}
		if(new_rtph_update->ts_stride_update){
			if(rohc_sd_vl_value_to_type(rtp_update->ts_stride_use,&vl_type)){
				rohc_pr(ROHC_DRTP,"%s ,ts stride use is too large:%lu\n",__func__,rtp_update->ts_stride_use);
				retval = -EFAULT;
				goto out;
			}
			rohc_sd_vl_encode(comp_hdr,&call_len,rtp_update->ts_stride_use,vl_type);
			encode_len += call_len;
			comp_hdr += call_len;
		}
	}
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

static int rtp_adjust_extension_type(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct comp_profile_v1_context *v1_context;
	struct packet_type_info *packet_info;
	struct comp_rtp_context *c_rtp_context;
}
static enum rohc_packet_type rtp_adjust_packet_type_so(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct iphdr *iph,*inner_iph;
	struct ip_context *ip_context;
	struct comp_profile_v1_context *v1_context;
	struct ip_context *ip_context;
	struct comp_rtp_context *c_rtp_context;

	struct rtp_csrc_update *csrc_update;
	struct rtph_update *new_rtph_update;
	struct iph_update_info *outer_iph_update,*inner_iph_update;
	struct iph_behavior_info *outer_iph_bh,*inner_iph_bh;
	struct  msn_encode_bits *msn_k_bits;
	struct rohc_bits_encode_set *ts_encode_bits;

	enum rohc_packet_type packet_type;
	bool need_ext3;

	v1_context = (struct comp_profile_v1_context *)context->prof_context;
	c_rtp_context = (struct comp_rtp_context *)v1_context->prof_context;
	rtp_context = &c_rtp_context->rtp_context;
	csrc_update = &c_rtp_context->csrc_context.update_by_packet;

	ip_context = &v1_context->ip_context;
	outer_iph_update = &ip_context->update_by_packet.iph_updates[ROHC_OUTER_IPH];
	inner_iph_update = &ip_context->update_by_packet.iph_updates[ROHC_INNER_IPH];
	outer_iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_OUTER_IPH];
	new_rtph_update = &rtp_context->update_by_packet;
	msn_k_bits = &v1_context->msn_k_bits;
	iph = &pkt_info->iph;

	if(new_rtph_update->tsc)
		ts_encode_bits = &new_rtph_update->ts_scaled_encode_bits;
	else
		ts_encode_bits = &new_rtph_update->ts_encode_bits;

	if(new_rtph_update->udp_check_bh_update || \
	   outer_iph_update->constant_update || \
	   inner_iph_update->constant_update || \
	   outer_iph_update->rnd_update ||
	   inner_iph_update->rnd_update){
		/*Distinguish between UO1 and UO1-ID/TS or URO2 and URO2_ID/TS
		 * ,the premise is to know context whether it contains sequential
		 * ipid in ipv4 header
		 */
		packet_type = ROHC_PACKET_TYPE_IR_DYN;
	}
	else if(!msn_encode_bits_set_test(msn_k_bits,4) && !msn_encode_bits_set_test(msn_k_bits,6) && \
		!msn_encode_bits_set_test(msn_k_bits,7) && !msn_encode_bits_set_test(msn_k_bits,9) && \
		!msn_encode_bits_set_test(msn_k_bits,12) && !msn_encode_bits_set_test(msn_k_bits,14))
		packet_type = ROHC_PACKET_TYPE_IR_DYN;
	else{
		if(iph_dynamic_fields_update(outer_iph_update) || \
		   iph_dynamic_fields_update(inner_iph_update) || \
		   rtp_dynamic_fields_update_without_m(new_rtph_update,csrc_update))
			need_ext3 = true;
		else
			need_ext3 = false;

		if(!need_ext3 && \
		   !new_rtph_update->m_update && \
		   iph_has_no_ipid_offset_need_trans(ip_context,pkt_info) && \
		   msn_encode_bits_set_test(msn_k_bits,4) && \
	           !new_rtph_update->ts_update && \
		   !new_rtph_update->ts_stride_update && \
		   !new_rtph_update->ts_residue_update)
			packet_type = ROHC_PACKET_TYPE_UO_0;
		else if(!iph_has_sequence_ipid(ip_context,pkt_info)){
			/*This branch is for non-sequential ip-id
			* only for the context does not contains any ipv4 header with sequential ipid
			*/
			if(!need_ext3 && \
			   iph_has_no_ipid_offset_need_trans(ip_context,pkt_info) && \
			   msn_encode_bits_set_test(msn_k_bits,4) && \
			   ROHC_ENCODE_BITS_TEST(ts_encode_bits,ROHC_ENCODE_BY_BITS(6)))
				packet_type = ROHC_PACKET_TYPE_UO_1;
			  else
				packet_type = ROHC_PACKET_TYPE_URO_2;
		}else{
			/*this branch is for context contains  sequential ipid
			 */
			if(!need_ext3 && \
			    iph_has_no_ipid_offset_need_trans(ip_context,pkt_info) && \
			    msn_encode_bits_set_test(msn_k_bits,4) && \
			    ROHC_ENCODE_BITS_TEST(ts_encode_bits,ROHC_ENCODE_BY_BITS(5)))
				packet_type = ROHC_PACKET_TYPE_UO_1_TS;
			else if(!new_rtph_update->m_update && \
				ROHC_ENCODE_BITS_TEST(ts_encode_bits,ROHC_ENCODE_BY_BITS(29)) && \
				msn_encode_bits_set_test(msn_k_bits,12)){

				/*uo1-id can carried ext0,ext1,ext2,or ext3,but ext3,no field carried RTP
				 * M bit,SO,in order to universally apply any extension,so add the restriction
				 * of whether M is updated
				 */
				packet_type = ROHC_PACKET_TYPE_UO_1_ID;
			}else if(ROHC_ENCODE_BITS_TEST(ts_encode_bits,ROHC_ENCODE_BY_BITS(29))){
				/*On the premise of not distinguishng the extension type,the packet
				*of URO_2_ID and URO_2_TS can only be distinguished by the number
				*of codeable bits of timestamp or timestamp scaled
				*/
				packet_type = ROHC_PACKET_TYPE_URO_2_ID;
			}else
				packet_type = ROHC_PACKET_TYPE_URO_2_TS;

		}
	}

}
enum rohc_packet_type comp_rtp_adjust_packet_type(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{

}
