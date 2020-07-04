/*
 *	rohc
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	Date   :	2020-05-22
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
#include "../rohc_packet.h"
#include "../rohc_cid.h"
#include "../rohc_bits_encode.h"
#include "../rohc_feedback.h"
#include "../rohc_ipid.h"
#include "../lsb.h"

#include "../profile/rohc_v2_profile.h"
#include "../profile/rohc_v2_packet.h"

#include "rohc_comp.h"
#include "rohc_comp_wlsb.h"
#include "rohc_comp_v2_common.h"
u8 rohc_v2_field_static_or_irreg_indicator(bool update)
{
	u8 ind;
	if(update)
		ind = 1;
	else
		ind = 0;
	return ind;
}

int innermost_seq_ipid_variable_build(u8 *to,struct rohc_comp_packet_hdr_info *pkt_info,struct rohc_v2_iph_context *iph_context,int ind)
{
	struct iphdr *iph;
	enum ip_id_behavior ipid_bh;
	u16 ipid_off;
	int encode_len = 0;
	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		ipid_bh = iph_context->inner_update_by_packet.new_ipid_bh;
		ipid_off = iph_context->inner_update_by_packet.new_ipid_offset;
	}else{
		iph = &pkt_info->iph;
		ipid_bh = iph_context->update_by_packet.new_ipid_bh;
		ipid_off = iph_context->update_by_packet.new_ipid_offset;
	}
	if(!rohc_iph_is_v4(iph->version) || ip_id_is_random_or_zero(ipid_bh))
		return encode_len;
	/*transfer to network byte order*/
	if(!ind){
		*to = ipid_off & 0xff;
		encode_len = 1;
	}else{
		/*keep network byte order and transfer the original ip-id of ipv4 header*/
		memcpy(to,&iph->id,2);
		encode_len = 2;
	}
	return encode_len;
}
static inline int rohc_v2_profile_234_flags_build(u8 *to,struct rohc_comp_packet_hdr_info *pkt_info,struct rohc_v2_iph_context *iph_context,int flag)
{
	struct iphdr *innermost_iph;
	enum ip_id_behavior ipid_bh;
	u8 outer_ind = 0;
	if(!flag)
		return 0;
	if(pkt_info->has_inner_iph){
		innermost_iph = &pkt_info->inner_iph;
		ipid_bh = iph_context->inner_update_by_packet.new_ipid_bh;
		if(iph_context->update_by_packet.ttl_hl_update || iph_context->update_by_packet.tos_tc_update)
			outer_ind = 1;

	}else{
		innermost_iph = &pkt_info->iph;
		ipid_bh = iph_context->update_by_packet.new_ipid_bh;
	}
	*to = (outer_ind << 7);
	if(rohc_iph_is_v4(innermost_iph->version))
		(*to) |= (!!(ntohs(innermost_iph->frag_off) & IP_DF) << 6) | ((ipid_bh & 0x3) << 4);
	inc_spec_iph_dynamic_field_trans_times(iph_context,IPH_FIELD_DF,true,pkt_info->has_inner_iph);
	inc_spec_iph_dynamic_field_trans_times(iph_context,IPH_FIELD_IPID_BH,true,pkt_info->has_inner_iph);

	if(outer_ind){
		inc_spec_iph_dynamic_field_trans_times(iph_context,IPH_FIELD_TOS_TC,false,pkt_info->has_inner_iph);
		inc_spec_iph_dynamic_field_trans_times(iph_context,IPH_FIELD_TTL_HL,false,pkt_info->has_inner_iph);
	}
	return 1;
}

static inline u8 rohc_v2_profile_234_flags_indicator(struct rohc_v2_iph_context *iph_context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct iphdr *iph;
	struct iph_field_update *iph_update;

	bool outer_flag = false;
	u8 ind = 0;

	if(pkt_info->has_inner_iph){
		iph_update = &iph_context->update_by_packet;
		if(iph_update->tos_tc_update || iph_update->ttl_hl_update)
			outer_flag = true;
		iph_update = &iph_context->inner_update_by_packet;
		iph = &pkt_info->inner_iph;
	}else{
		iph_update = &iph_context->update_by_packet;
		iph = &pkt_info->iph;
	}
	/*detect the innermost ipv4 header df update or ipid bh update
	 */
	if(rohc_iph_is_v4(iph->version)){
		if(outer_flag || iph_update->df_update || iph_update->ipid_bh_update)
			ind = 1;
	}else{
		if(outer_flag)
			ind = 1;
	}
	return ind;
}
static inline u8 innermost_iph_field_static_or_irreg_indicator(bool has_inner_iph,bool outer_update,bool inner_update)
{
	u8 ind;
	if(has_inner_iph){
		if(inner_update)
			ind = 1;
		else
			ind = 0;
	}else{
		/*only one ip header*/
		if(outer_update)
			ind = 1;
		else
			ind = 0;
	}
	return ind;
}
int innermost_iph_field_static_or_irreg_build(u8 *to,struct rohc_comp_packet_hdr_info *pkt_info,int ind,int field_type)
{
	struct iphdr *iph;
	int encode_len = 0;
	if(!ind)
		return encode_len;
	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
	}else
		iph = &pkt_info->iph;
	switch(field_type){
		case IPH_FIELD_TTL_HL:
			if(rohc_iph_is_v4(iph->version))
				*to = iph->ttl;
			else{
				//IPV6
			}
			encode_len = 1;
			break;
		case IPH_FIELD_TOS_TC:
			if(rohc_iph_is_v4(iph->version))
				*to = iph->tos;
			else{
				//ipv6
			}
			encode_len = 1;
			break;
		default:
			break;
	}
	return encode_len;
}
void rohc_v2_ip_id_behavior_probe(struct rohc_v2_iph_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info)
{

	struct iphdr *iph,*inner_iph,*old_iph,*old_inner_iph;
	struct last_comped_iph *iph_ref;
	struct iph_field_update *iph_update,*inner_iph_update;;
	int i;
	int retval;
	u16 new_ipid;
	u16 old_ipid;
	iph_ref = &ip_context->iph_ref;
	iph_update= &ip_context->update_by_packet;
	inner_iph_update = &ip_context->inner_update_by_packet;
	iph = &pkt_info->iph;
	old_iph = &iph_ref->iph;

	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		old_inner_iph = &iph_ref->inner_iph;
		if(ip_context->is_first_packet){
			inner_iph_update->new_ipid_bh = IP_ID_BEHAVIOR_SEQ_NBO;
			iph_update->new_ipid_bh = IP_ID_BEHAVIOR_RANDOM;
			return;
		}
		if(rohc_iph_is_v4(inner_iph->version)){
			new_ipid = ntohs(inner_iph->id);
			old_ipid = ntohs(old_inner_iph->id);
			/*rohc_v2 profiles must not assign a sequential behavior to any IP-ID but
			 * the one in the innermost  IP header when compressing more than one level
			 * of IP headers
			 */
			__ip_id_behavior_probe(new_ipid,old_ipid,&inner_iph_update->new_ipid_bh,true);

		}
		if(rohc_iph_is_v4(iph->version)){
			new_ipid = ntohs(iph->id);
			old_ipid = ntohs(old_iph->id);
			__ip_id_behavior_probe(new_ipid,old_ipid,&iph_update->new_ipid_bh,false);
		}
	}else if(rohc_iph_is_v4(iph->version)){
		if(ip_context->is_first_packet)
			iph_update->new_ipid_bh = IP_ID_BEHAVIOR_SEQ_NBO;
		else{
			new_ipid = ntohs(iph->id);
			old_ipid = ntohs(old_iph->id);
			__ip_id_behavior_probe(new_ipid,old_ipid,&iph_update->new_ipid_bh,true);
		}
	}
}

bool innermost_ipid_bh_is_seq(struct rohc_v2_iph_context *iph_context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct iphdr *iph;
	struct iph_field_update *iph_update;
	bool retval = false;

	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		iph_update = &iph_context->inner_update_by_packet;
		if(rohc_iph_is_v4(iph->version) && !ip_id_is_random_or_zero(iph_update->new_ipid_bh))
			retval = true;
	}else{
		iph = &pkt_info->iph;
		iph_update = &iph_context->update_by_packet;
		if(rohc_iph_is_v4(iph->version) && !ip_id_is_random_or_zero(iph_update->new_ipid_bh))
			retval = true;
	}
	return retval;
}

bool innermost_iph_dynamic_field_update(struct rohc_v2_iph_context *iph_context,bool has_inner_iph,int type)
{
	struct iph_field_update *iph_update;

	int retval;
	if(has_inner_iph)
		iph_update = &iph_context->inner_update_by_packet;
	else
		iph_update = &iph_context->update_by_packet;
	switch(type){
		case IPH_FIELD_TTL_HL:
			retval = iph_update->ttl_hl_update;
			break;
		case IPH_FIELD_TOS_TC:
			retval = iph_update->tos_tc_update;
			break;
		case IPH_FIELD_DF:
			retval = iph_update->df_update;
			break;
		case IPH_FIELD_IPID_BH:
			retval = iph_update->ipid_bh_update;
			break;
		case IPH_FIELD_IPID_OFF:
			retval = iph_update->ipid_off_update;
			break;
	}
	return retval;

}

bool outer_iph_dynamic_field_update(struct rohc_v2_iph_context *iph_context,bool has_inner_iph,int type)
{
	struct iph_field_update *iph_update;
	bool retval = false;
	if(!has_inner_iph)
		return retval;
	iph_update = &iph_context->update_by_packet;
	switch(type){
		case IPH_FIELD_TTL_HL:
			retval = iph_update->ttl_hl_update;
			break;
		case IPH_FIELD_TOS_TC:
			retval = iph_update->tos_tc_update;
			break;
		case IPH_FIELD_DF:
			retval = iph_update->df_update;
			break;
		case IPH_FIELD_IPID_BH:
			retval = iph_update->ipid_bh_update;
			break;
	}
	return retval;
}

void pick_innermost_seq_ipid_offset(struct rohc_v2_iph_context *iph_context,bool has_inner_iph,u16 *ipid_off)
{
	struct iph_field_update *iph_update;
	if(has_inner_iph)
		iph_update = &iph_context->inner_update_by_packet;
	else
		iph_update = &iph_context->update_by_packet;
	if(ip_id_is_random_or_zero(iph_update->new_ipid_bh))
		rohc_pr(ROHC_DEBUG,"can't fine the sequential ipid,has_inner_iph is %s\n",has_inner_iph ? "true" : "false");
	*ipid_off = iph_update->new_ipid_offset;
}

bool innermost_ipid_encode_set_test(struct rohc_v2_iph_context *iph_context,bool has_inner_iph,int bits)
{
	bool retval = false;
	struct iph_field_update *iph_update;
	if(has_inner_iph)
		iph_update = &iph_context->inner_update_by_packet;
	else
		iph_update = &iph_context->update_by_packet;
	if(ROHC_ENCODE_BITS_TEST(&iph_update->ipid_off_encode_bits,bits))
		retval = true;
	return retval;
}

void ipv4_header_update_probe(struct iphdr *new_iph,struct iphdr *old_iph,struct iph_field_update *iph_update,struct iph_field_trans_times *update_trans_times, enum ip_id_behavior old_ipid_bh,int oa_max)
{
	/*tos update probe*/
	net_header_field_update_probe(new_iph->tos,old_iph->tos,&iph_update->tos_tc_update,&update_trans_times->tos_tc_trans_time,oa_max);

	net_header_field_update_probe(new_iph->ttl,old_iph->ttl,&iph_update->ttl_hl_update,&update_trans_times->ttl_hl_trans_time,oa_max);

	net_header_field_update_probe(ntohs(new_iph->frag_off) & IP_DF,ntohs(old_iph->frag_off) & IP_DF,&iph_update->df_update,&update_trans_times->df_trans_time,oa_max);

	net_header_field_update_probe(iph_update->new_ipid_bh,old_ipid_bh,&iph_update->ipid_bh_update,&update_trans_times->ipid_bh_trans_time,oa_max);

}

void ipv6_header_update_probe(void)
{

}

void ipv4_cal_innermost_ipid_encode_bts_set(struct iphdr *iph,struct iph_field_update *iph_update,struct comp_win_lsb *wlsb,u32 msn)
{
	struct rohc_bits_encode_set *ipid_set;
	u16 new_ipid,ipid_off;
	u32 last_ipid_off;

	new_ipid = ntohs(iph->id);
	if(ip_id_is_nbo(iph_update->new_ipid_bh))
		ipid_off = new_ipid - msn;
	else
		ipid_off = __swab16(new_ipid) - msn;
	iph_update->new_ipid_offset = ipid_off;

	if(ip_id_is_random_or_zero(iph_update->new_ipid_bh))
		return;
	if(rohc_comp_wlsb_peek_last_val(wlsb,&last_ipid_off))
		iph_update->ipid_off_update = true;
	else{
		if(ipid_off != last_ipid_off)
			iph_update->ipid_off_update = true;
		else
			iph_update->ipid_off_update = false;
	}

	ipid_set = &iph_update->ipid_off_encode_bits;
	if(comp_wlsb_can_encode_type_ushort(wlsb,8,ROHC_LSB_V2_IPID_P(8),ipid_off))
		ROHC_ENCODE_BITS_SET(ipid_set,ROHC_ENCODE_BY_BITS(8));
	if(comp_wlsb_can_encode_type_ushort(wlsb,4,ROHC_LSB_V2_IPID_P(4),ipid_off))
		ROHC_ENCODE_BITS_SET(ipid_set,ROHC_ENCODE_BY_BITS(4));
	if(comp_wlsb_can_encode_type_ushort(wlsb,5,ROHC_LSB_V2_IPID_P(5),ipid_off))
		ROHC_ENCODE_BITS_SET(ipid_set,ROHC_ENCODE_BY_BITS(5));
	if(comp_wlsb_can_encode_type_ushort(wlsb,6,ROHC_ENCODE_BY_BITS(6),ipid_off))
		ROHC_ENCODE_BITS_SET(ipid_set,ROHC_ENCODE_BY_BITS(6));

}

void rohc_v2_iph_update_probe(struct rohc_v2_iph_context *iph_context,struct rohc_comp_packet_hdr_info *pkt_info,int oa_max,u32 msn)
{
	struct iphdr *iph,*iph_ref;
	struct iph_field_update *iph_update;
	struct iph_field_trans_times *update_trans_times;
	enum ip_id_behavior ipid_bh_ref;
	iph = &pkt_info->iph;
	iph_ref = &iph_context->iph_ref.iph;
	iph_update = &iph_context->update_by_packet;
	update_trans_times = &iph_context->update_trans_times;

	ipid_bh_ref = iph_context->iph_ref.ipid_bh;

	/*clear update by packet*/
	memset(&iph_context->update_by_packet,0,sizeof(struct iph_field_update));
	memset(&iph_context->inner_update_by_packet,0,sizeof(struct iph_field_update));

	/*ipv4 header ip-id behavior probe*/
	rohc_v2_ip_id_behavior_probe(iph_context,pkt_info);

	if(rohc_iph_is_v4(iph->version)){
		ipv4_header_update_probe(iph,iph_ref,iph_update,update_trans_times,ipid_bh_ref,oa_max);
		/*ipid off encode bits cal*/
		if(!pkt_info->has_inner_iph)
			ipv4_cal_innermost_ipid_encode_bts_set(iph,iph_update,iph_context->outer_ipid_wlsb,msn);
	}else{
		ipv6_header_update_probe();
	}

	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		iph_ref = &iph_context->iph_ref.inner_iph;
		iph_update = &iph_context->inner_update_by_packet;
		update_trans_times = &iph_context->inner_update_trans_times;
		ipid_bh_ref = iph_context->iph_ref.inner_ipid_bh;
		if(rohc_iph_is_v4(iph->version)){
			ipv4_header_update_probe(iph,iph_ref,iph_update,update_trans_times,ipid_bh_ref,oa_max);
			ipv4_cal_innermost_ipid_encode_bts_set(iph,iph_update,iph_context->innermost_ipid_wlsb,msn);
		}
	}else{
		ipv6_header_update_probe();
	}
}


void rohc_v2_cal_msn_encode_bits_set(struct rohc_bits_encode_set *msn_set,struct comp_win_lsb *msn_wlsb,enum rohc_v2_reordering_ratio r_ratio,u32 msn,int msn_type)
{

	if(msn_type == TYPE_USHORT){
		if(comp_wlsb_can_encode_type_ushort(msn_wlsb,4,rohc_v2_msn_k_to_p_under_rr(r_ratio,4),msn))
			ROHC_ENCODE_BITS_SET(msn_set,ROHC_ENCODE_BY_BITS(4));
		if(comp_wlsb_can_encode_type_ushort(msn_wlsb,5,rohc_v2_msn_k_to_p_under_rr(r_ratio,5),msn))
			ROHC_ENCODE_BITS_SET(msn_set,ROHC_ENCODE_BY_BITS(5));
		if(comp_wlsb_can_encode_type_ushort(msn_wlsb,6,rohc_v2_msn_k_to_p_under_rr(r_ratio,6),msn))
			ROHC_ENCODE_BITS_SET(msn_set,ROHC_ENCODE_BY_BITS(6));
		if(comp_wlsb_can_encode_type_ushort(msn_wlsb,7,rohc_v2_msn_k_to_p_under_rr(r_ratio,7),msn))
			ROHC_ENCODE_BITS_SET(msn_set,ROHC_ENCODE_BY_BITS(7));
		if(comp_wlsb_can_encode_type_ushort(msn_wlsb,8,rohc_v2_msn_k_to_p_under_rr(r_ratio,8),msn))
			ROHC_ENCODE_BITS_SET(msn_set,ROHC_ENCODE_BY_BITS(8));
		/*self-describng variable length encoding with reordering offset: 7bits, 14bits,
		 * 21bits,28 bits,32 bits,because sn type is unsigned short ,so here < 21bits */
		if(comp_wlsb_can_encode_type_ushort(msn_wlsb,14,rohc_v2_msn_k_to_p_under_rr(r_ratio,14),msn))
			ROHC_ENCODE_BITS_SET(msn_set,ROHC_ENCODE_BY_BITS(14));


	}else{
		//UINT
		if(comp_wlsb_can_encode_type_ushort(msn_wlsb,4,rohc_v2_msn_k_to_p_under_rr(r_ratio,4),msn))
			ROHC_ENCODE_BITS_SET(msn_set,ROHC_ENCODE_BY_BITS(4));
		if(comp_wlsb_can_encode_type_ushort(msn_wlsb,5,rohc_v2_msn_k_to_p_under_rr(r_ratio,5),msn))
			ROHC_ENCODE_BITS_SET(msn_set,ROHC_ENCODE_BY_BITS(5));
		if(comp_wlsb_can_encode_type_ushort(msn_wlsb,6,rohc_v2_msn_k_to_p_under_rr(r_ratio,6),msn))
			ROHC_ENCODE_BITS_SET(msn_set,ROHC_ENCODE_BY_BITS(6));
		if(comp_wlsb_can_encode_type_ushort(msn_wlsb,7,rohc_v2_msn_k_to_p_under_rr(r_ratio,7),msn))
			ROHC_ENCODE_BITS_SET(msn_set,ROHC_ENCODE_BY_BITS(7));
		if(comp_wlsb_can_encode_type_ushort(msn_wlsb,8,rohc_v2_msn_k_to_p_under_rr(r_ratio,8),msn))
			ROHC_ENCODE_BITS_SET(msn_set,ROHC_ENCODE_BY_BITS(8));
		/*self-describng variable length encoding with reordering offset: 7bits, 14bits,
		 * 21bits,28 bits,32 bits*/
		if(comp_wlsb_can_encode_type_ushort(msn_wlsb,14,rohc_v2_msn_k_to_p_under_rr(r_ratio,14),msn))
			ROHC_ENCODE_BITS_SET(msn_set,ROHC_ENCODE_BY_BITS(14));
		if(comp_wlsb_can_encode_type_ushort(msn_wlsb,21,rohc_v2_msn_k_to_p_under_rr(r_ratio,21),msn))
			ROHC_ENCODE_BITS_SET(msn_set,ROHC_ENCODE_BY_BITS(21));
		if(comp_wlsb_can_encode_type_ushort(msn_wlsb,28,rohc_v2_msn_k_to_p_under_rr(r_ratio,28),msn))
			ROHC_ENCODE_BITS_SET(msn_set,ROHC_ENCODE_BY_BITS(28));

	}
}

void rohc_v2_cal_ts_encode_bits_set(struct comp_win_lsb *ts_wlsb,struct rohc_bits_encode_set *ts_set,u32 ts)
{

	if(comp_wlsb_can_encode_type_uint(ts_wlsb,5,ROHC_LSB_RTP_TS_K_TO_P(5),ts))
		ROHC_ENCODE_BITS_SET(ts_set,ROHC_ENCODE_BY_BITS(5));
	if(comp_wlsb_can_encode_type_uint(ts_wlsb,6,ROHC_LSB_RTP_TS_K_TO_P(6),ts))
		ROHC_ENCODE_BITS_SET(ts_set,ROHC_ENCODE_BY_BITS(6));
	/*Self describing variable length encoding :
	 * 7,14,21,28,32*/

	if(comp_wlsb_can_encode_type_uint(ts_wlsb,7,ROHC_LSB_RTP_TS_K_TO_P(7),ts))
		ROHC_ENCODE_BITS_SET(ts_set,ROHC_ENCODE_BY_BITS(7));
	if(comp_wlsb_can_encode_type_uint(ts_wlsb,14,ROHC_LSB_RTP_TS_K_TO_P(14),ts))
		ROHC_ENCODE_BITS_SET(ts_set,ROHC_ENCODE_BY_BITS(14));
	if(comp_wlsb_can_encode_type_uint(ts_wlsb,21,ROHC_LSB_RTP_TS_K_TO_P(21),ts))
		ROHC_ENCODE_BITS_SET(ts_set,ROHC_ENCODE_BY_BITS(21));
	if(comp_wlsb_can_encode_type_uint(ts_wlsb,28,ROHC_LSB_RTP_TS_K_TO_P(28),ts))
		ROHC_ENCODE_BITS_SET(ts_set,ROHC_ENCODE_BY_BITS(28));

}


int rohc_comp_v2_build_generic_co_common(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct iphdr *iph;
	struct sk_buff *comp_skb;
	struct rohc_v2_common_context *co_context;
	struct rohc_v2_iph_context *iph_context;
	struct iph_field_update *iph_update,*inner_iph_update;
	struct co_common_generic *co_common;
	struct rohc_crc_info	*crc_info;
	enum rohc_cid_type cid_type;
	u16 msn,ipid_off;

	bool build_full;
	int call_len;
	int encode_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_common_context *)context->prof_context;
	iph_context = &co_context->iph_context;

	iph_update = &iph_context->update_by_packet;
	inner_iph_update = &iph_context->inner_update_by_packet;

	crc_info = &pkt_info->crc_info;
	cid_type = context->compresser->cid_type;
	msn = context->co_fields.msn;

	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);

	if(cid_type == CID_TYPE_SMALL){
		co_common = (struct co_common_generic *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			co_common = (struct co_common_generic *)comp_hdr;
		else
			co_common = (struct co_common_generic *)(comp_hdr - 1);
		build_full = false;
	}

	if(build_first){
		co_common->disc = ROHC_PACKET_GENERIC_CO_COMMON;
		encode_len = 1;
	};

	if(!build_full && build_first)
		goto out;
	if(innermost_ipid_bh_is_seq(iph_context,pkt_info)){
		if(innermost_ipid_encode_set_test(iph_context,pkt_info->has_inner_iph,ROHC_ENCODE_BY_BITS(8)))
			co_common->ipid_ind = 0;
		else
			co_common->ipid_ind = 1;
	}else
		co_common->ipid_ind = 0;
	if(context->comp_profile->pro_ops->crc_cal){
		crc_info->start_off = ETH_HLEN;
		crc_info->len = pkt_info->to_comp_pkt_hdr_len - ETH_HLEN;
		crc_info->crc_type = CRC_TYPE_7;
		co_common->crc = context->comp_profile->pro_ops->crc_cal(skb,crc_info);
	}else
		co_common->crc = 0;
	co_common->flag = rohc_v2_profile_234_flags_indicator(iph_context,pkt_info);
	co_common->ttl_hl_ind = innermost_iph_field_static_or_irreg_indicator(pkt_info->has_inner_iph,iph_update->ttl_hl_update,inner_iph_update->ttl_hl_update);
	co_common->tos_tc_ind = innermost_iph_field_static_or_irreg_indicator(pkt_info->has_inner_iph,iph_update->tos_tc_update,inner_iph_update->tos_tc_update);

	co_common->reorder_ratio = REORDER_R_NONE;
	co_common->ctrl_crc = 0;

	encode_len += sizeof(struct co_common_generic) - 1;
	comp_hdr += encode_len;
	/*next fields is variable lenght fields */
	/*field.1 2_3_4_flags*/

	call_len = rohc_v2_profile_234_flags_build(comp_hdr,pkt_info,iph_context,co_common->flag);
	comp_hdr += call_len;
	encode_len += call_len;

	/*filed.2 tos_tc*/
	call_len = innermost_iph_field_static_or_irreg_build(comp_hdr,pkt_info,co_common->tos_tc_ind,IPH_FIELD_TOS_TC);
	comp_hdr += call_len;
	encode_len += call_len;
	if(co_common->tos_tc_ind)
		inc_spec_iph_dynamic_field_trans_times(iph_context,IPH_FIELD_TOS_TC,true,pkt_info->has_inner_iph);

	/*field.3 ttl_hl */
	call_len = innermost_iph_field_static_or_irreg_build(comp_hdr,pkt_info,co_common->ttl_hl_ind,IPH_FIELD_TTL_HL);
	comp_hdr += call_len;
	encode_len += call_len;

	if(co_common->ttl_hl_ind)
		inc_spec_iph_dynamic_field_trans_times(iph_context,IPH_FIELD_TTL_HL,true,pkt_info->has_inner_iph);
	/*field.4 msn*/
	*comp_hdr = msn & 0xff;
	comp_hdr++;
	encode_len++;
	/*filed.5 innermost ipv4 header ipid*/
	call_len = innermost_seq_ipid_variable_build(comp_hdr,pkt_info,iph_context,co_common->ipid_ind);
	comp_hdr += call_len;
	encode_len += call_len;

out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rohc_comp_v2_build_pt_0_crc3(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct pt_0_crc3 *pt_0_crc;
	struct rohc_crc_info *crc_info;
	enum rohc_cid_type cid_type;

	bool build_full;
	u16 msn;
	int encode_len = 0;
	int retval = 0;

	crc_info = &pkt_info->crc_info;

	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);

	cid_type = context->compresser->cid_type;
	msn = context->co_fields.msn;

	if(cid_type == CID_TYPE_SMALL){
		pt_0_crc = (struct pt_0_crc3 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			pt_0_crc = (struct pt_0_crc3 *)comp_hdr;
		else
			pt_0_crc = (struct pt_0_crc3 *)(comp_hdr - 1);
	}
	if(build_first){
		pt_0_crc->disc = ROHC_PACKET_PT_0_CRC3 >> 7;
		pt_0_crc->msn = msn & 0xf;
		if(context->capability & ROHC_COMP_CAP_CRC_VERIFY){
			crc_info->crc_type = CRC_TYPE_3;
			crc_info->start_off = ETH_HLEN;
			crc_info->len = pkt_info->to_comp_pkt_hdr_len - ETH_HLEN;
			pt_0_crc->crc = context->comp_profile->pro_ops->crc_cal(skb,crc_info);
		}else
			pt_0_crc->crc = 0;
		encode_len = 1;

	}else
		goto out;

	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
out:
	return retval;
}

int rohc_comp_v2_build_pt_0_crc7(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct pt_0_crc7 *pt_0_crc;
	enum rohc_cid_type cid_type;

	bool build_full;

	u32 msn;
	int encode_len = 0;
	int retval = 0;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);

	msn = context->co_fields.msn;

	if(COMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		pt_0_crc = (struct pt_0_crc7 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			pt_0_crc = (struct pt_0_crc7 *)comp_hdr;
		else
			pt_0_crc = (struct pt_0_crc7 *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		pt_0_crc->disc = ROHC_PACKET_PT_0_CRC7 >> 5;
		pt_0_crc->msn0 = msn >> 1;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	pt_0_crc->msn1 = msn & 0x1;
	pt_0_crc->crc = 0;
	encode_len += sizeof(struct pt_0_crc7) - 1;
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rohc_comp_v2_build_pt_1_seq_id(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct rohc_v2_common_context *co_context;
	struct rohc_v2_iph_context *iph_context;
	struct pt_1_seq_id *seq_id;

	bool build_full;
	u16 msn,ipid_off;

	int encode_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_common_context *)context->prof_context;

	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);

	msn = context->co_fields.msn;
	if(COMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		seq_id = (struct pt_1_seq_id *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			seq_id = (struct pt_1_seq_id *)comp_hdr;
		else
			seq_id = (struct pt_1_seq_id *)(comp_hdr - 1);
		build_full = false;

	}
	if(build_first){
		seq_id->disc = ROHC_PACKET_PT_1_SEQ_ID >> 5;
		seq_id->crc = 0;
		seq_id->msn0 = (msn >> 4) & 0x3;

		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	seq_id->msn1 = msn & 0xf;
	iph_context = &co_context->iph_context;
	pick_innermost_seq_ipid_offset(iph_context,pkt_info->has_inner_iph,&ipid_off);
	seq_id->ipid_off = ipid_off & 0xf;
	encode_len += sizeof(struct pt_1_seq_id) - 1;
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rohc_comp_v2_build_pt_2_seq_id(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct rohc_v2_common_context *co_context;
	struct rohc_v2_iph_context *iph_context;
	struct pt_2_seq_id *seq_id;

	bool build_full;
	u16 msn,ipid_off;

	int encode_len = 0;
	int retval = 0;

	co_context = (struct rohc_v2_common_context *)context->prof_context;
	iph_context = &co_context->iph_context;

	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);

	msn = context->co_fields.msn;
	if(COMP_CONTEXT_CID_TYPE(context) == CID_TYPE_SMALL){
		seq_id = (struct pt_2_seq_id *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			seq_id = (struct pt_2_seq_id *)comp_hdr;
		else
			seq_id = (struct pt_2_seq_id *)(comp_hdr - 1);
		build_full = false;
	}
	pick_innermost_seq_ipid_offset(iph_context,pkt_info->has_inner_iph,&ipid_off);

	if(build_first){
		seq_id->disc = ROHC_PACKET_PT_2_SEQ_ID >> 5;
		seq_id->ipid_off0 = (ipid_off >> 1) & 0x1f;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	seq_id->ipid_off1 = ipid_off & 0x1;
	seq_id->crc = 0;

	seq_id->msn = msn & 0xff;
	encode_len += sizeof(struct pt_2_seq_id) - 1;
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

static inline int rohc_v2_iph_build_static_field(u8 *to,struct iphdr *iph,bool is_inner)
{
	struct profile_ipv4_static *ipv4_static;
	int encode_len = 0;
	if(rohc_iph_is_v4(iph->version)){
		ipv4_static = (struct profile_ipv4_static *)to;
		ipv4_static->innermost = is_inner;
		ipv4_static->version = 0;
		ipv4_static->protocol = iph->protocol;
		/*keep network byte order*/
		ipv4_static->saddr = iph->saddr;
		ipv4_static->daddr = iph->daddr;
		encode_len = sizeof(struct profile_ipv4_static);
	}else{
		//ipv6
		//return 0;
	}
	return encode_len;
}
int rohc_comp_v2_build_ip_static_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct iphdr *iph;
	struct sk_buff *comp_skb;
	int call_len;
	int encode_len = 0;
	int retval = 0;

	iph = &pkt_info->iph;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	call_len = rohc_v2_iph_build_static_field(comp_hdr,iph,false);
	encode_len += call_len;
	comp_hdr += call_len;
	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		call_len = rohc_v2_iph_build_static_field(comp_hdr,iph,true);
		encode_len += call_len;
	}
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

static inline int rohc_v2_iph_build_dynamic_field(u8 *to,struct iphdr *iph,enum ip_id_behavior ipid_bh)
{
	struct profile_ipv4_dynamic *ipv4_dynamic;
	int encode_len = 0;
	if(rohc_iph_is_v4(iph->version)){
		ipv4_dynamic = (struct profile_ipv4_dynamic *)to;
		ipv4_dynamic->ipid_bh = ipid_bh;
		ipv4_dynamic->df = !!(ntohs(iph->frag_off) & IP_DF);
		ipv4_dynamic->tos = iph->tos;
		ipv4_dynamic->ttl = iph->ttl;
		encode_len = sizeof(struct profile_ipv4_dynamic);
		if(!ip_id_is_zero(ipid_bh)){
			to += encode_len;
			/*keep network byte order*/
			memcpy(to,&iph->id,2);
			encode_len += 2;
		}

	}else{
		//IPV6;
	}
	return encode_len;
}
int rohc_comp_v2_build_ip_dynamic_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct iphdr *iph;
	struct sk_buff *comp_skb;
	struct rohc_v2_common_context *co_context;
	struct iph_field_update *iph_update;

	int call_len;
	int encode_len = 0;
	int retval = 0;
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	iph_update = &co_context->iph_context.update_by_packet;

	iph = &pkt_info->iph;

	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	call_len = rohc_v2_iph_build_dynamic_field(comp_hdr,iph,iph_update->new_ipid_bh);
	encode_len += call_len;
	comp_hdr += call_len;
	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		iph_update = &co_context->iph_context.inner_update_by_packet;
		call_len = rohc_v2_iph_build_dynamic_field(comp_hdr,iph,iph_update->new_ipid_bh);
		encode_len += call_len;
	}
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rohc_comp_v2_build_ip_irr_chain(struct rohc_v2_iph_context *iph_context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct iphdr *iph;

	struct iph_field_update *iph_update;

	int encode_len = 0;
	int retval = 0;

	iph_update = &iph_context->update_by_packet;
	iph = &pkt_info->iph;
	comp_hdr = skb_tail_pointer(comp_skb);
	/*first outer ip header irrreguar chain*/
	/*field.1 ipid*/
	if(rohc_iph_is_v4(iph->version) && ip_id_is_random(iph_update->new_ipid_bh)){
		/*keep network byte order*/
		memcpy(comp_hdr,&iph->id,2);
		comp_hdr += 2;
		encode_len += 2;
	}
	if(pkt_info->has_inner_iph){
		if(iph_update->tos_tc_update || iph_update->ttl_hl_update){
			/*field.2 tos_tc*/
			if(rohc_iph_is_v4(iph->version)){
				*comp_hdr = iph->tos;
				comp_hdr++;
				encode_len++;
				*comp_hdr = iph->ttl;
				comp_hdr++;
				encode_len++;
			}else{
				//ipv6
			}
		}
	}
	/*innermost ip header irrreguar chain*/
	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		iph_update = &iph_context->inner_update_by_packet;
		if(rohc_iph_is_v4(iph->version) && ip_id_is_random(iph_update->new_ipid_bh)){
			/*keep network byte order */
			memcpy(comp_hdr,&iph->id,2);
			encode_len += 2;
		}
	}
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;

}

void rohc_v2_update_ip_context(struct rohc_v2_iph_context *iph_context,struct rohc_comp_packet_hdr_info *pkt_info,u32 msn)
{
	struct iphdr *new_iph,*to_iph;
	struct ipv6hdr *new_ipv6h,*to_ipv6h;
	struct iph_field_update *iph_update;
	struct last_comped_iph *iph_ref;
	u16 new_ipid_offset;
	new_iph = &pkt_info->iph;
	iph_update = &iph_context->update_by_packet;
	iph_ref = &iph_context->iph_ref;
	if(rohc_iph_is_v4(new_iph->version)){
		to_iph = &iph_ref->iph;
		memcpy(to_iph,new_iph,sizeof(struct iphdr));
		iph_ref->ipid_bh = iph_update->new_ipid_bh;
		comp_wlsb_add(iph_context->outer_ipid_wlsb,NULL,msn,iph_update->new_ipid_offset);
	}else{
		//IPV6
	}
	if(pkt_info->has_inner_iph){
		iph_update = &iph_context->inner_update_by_packet;
		new_iph = &pkt_info->inner_iph;
		to_iph = &iph_ref->inner_iph;
		memcpy(to_iph,new_iph,sizeof(struct iphdr));
		iph_ref->inner_ipid_bh = iph_update->new_ipid_bh;
		comp_wlsb_add(iph_context->innermost_ipid_wlsb,NULL,msn,iph_update->new_ipid_offset);
	}
	iph_context->is_first_packet = false;
}
int rohc_v2_comp_init_ip_context(struct rohc_v2_iph_context *ip_context,int oa_max)
{
	int retval,i;

	for(i = 0 ; i < ROHC_V2_MAX_IP_HDR; i++){
		ip_context->ip_id_wlsb[i] = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_USHORT,GFP_ATOMIC);
		if(IS_ERR(ip_context->ip_id_wlsb[i])){
			if(i == ROHC_INNER_IPH)
				comp_wlsb_destroy(ip_context->ip_id_wlsb[i - 1]);
			retval = -ENOMEM;
			goto err0;
		}
	}
	ip_context->is_first_packet = true;
	return 0;

err0:
	return retval;
}
void rohc_v2_destroy_ip_context(struct rohc_v2_iph_context *ip_context)
{

	comp_wlsb_destroy(ip_context->outer_ipid_wlsb);
	comp_wlsb_destroy(ip_context->innermost_ipid_wlsb);
}

int rohc_comp_v2_feedack_ack(struct rohc_comp_context *context ,u32 msn,int sn_bit_width,bool sn_valid)
{
	struct iphdr *iph;
	struct rohc_v2_common_context *co_context;
	struct rohc_v2_iph_context *iph_context;
	struct rohc_v2_prof_ops *prof_ops;
	int ack_num;
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	iph_context = &co_context->iph_context;
	prof_ops = co_context->prof_ops;
	if(sn_valid)
		ack_num = comp_wlsb_ack(co_context->msn_wlsb,sn_bit_width,msn);
	if(context->context_state != COMP_STATE_SO){
		rohc_comp_context_change_state(context,COMP_STATE_SO);
	}
	if(sn_valid){
		confident_iph_field_trans_times(&iph_context->update_trans_times,co_context->oa_upward_pkts);
		confident_iph_field_trans_times(&iph_context->inner_update_trans_times,co_context->oa_upward_pkts);
	}
	if(prof_ops && prof_ops->feedback_input)
		prof_ops->feedback_input(co_context,ROHC_FEEDBACK_ACK,msn,sn_bit_width,sn_valid);
	return 0;
}

int rohc_comp_v2_feedack_ack1(struct rohc_comp_context *context,struct sk_buff *skb,int feedback_size)
{
	u8 *data;
	u32 msn;
	int msn_mask_bit;
	data = skb->data;
	msn = (*data) & 0xff;
	msn_mask_bit = 8;
	if(context->mode != ROHC_MODE_O)
		rohc_comp_context_change_mode(context,ROHC_MODE_O);
	rohc_comp_v2_feedack_ack(context,msn,msn_mask_bit,true);
	skb_pull(skb,feedback_size);
	return 0;
}
int rohc_comp_v2_feedack_ack2(struct rohc_comp_context *context,struct sk_buff *skb,int feedback_size)
{
	u8 *data;
	struct rohc_v2_common_context *co_context;
	struct rohc_v2_iph_context *iph_context;
	struct rohc_v2_prof_ops *prof_ops;
	enum rohc_profile prof;
	int mode;
	int ack_type;
	u32 msn;
	u32 sn_mask_bits;
	u8 crc;
	struct rohc_feedback_option_compile option_compile;
	int retval = 0;
	int decode_size = 0;
	bool sn_valid = true;
	co_context = (struct rohc_v2_common_context *)context->prof_context;
	prof_ops = co_context->prof_ops;
	iph_context = &co_context->iph_context;

	memset(&option_compile,0,sizeof(struct rohc_feedback_option_compile));
	data = skb->data;
	prof = context->comp_profile->profile;
	if(rohc_profile_is_v2(prof) || prof == ROHC_V1_PROFILE_TCP){
		sn_mask_bits = 14;
		ack_type = ((*data) >> 6) & 0x3;
		msn = (*data) &0x3f;
		data++;
		msn = (msn << 8) | (*data);
		decode_size = 2;
		data++;
		/*the fllowing is crc byte.
		 */
		crc = *data;
		decode_size++;
		rohc_comp_context_change_mode(context,ROHC_MODE_O);
	}else{
		sn_mask_bits = 12;
		ack_type = ((*data) >> 6) & 0x3;
		mode = ((*data) >> 4) & 0x3;
		msn = (*data) & 0xf;
		data++;
		msn = (msn << 8) | (*data);
		decode_size = 2;
		rohc_comp_context_change_mode(context,mode);
	}
	option_compile.sn = msn;
	skb_pull(skb,decode_size);
	feedback_size -= decode_size;

	rohc_feeback_parse_options(skb,&option_compile,prof,feedback_size);
	sn_mask_bits += option_compile.sn_opt_bits;
	msn = option_compile.sn;
	if(option_compile.option_apprear[FEEDBACK_OPTION_TYPE_UNVALID_SN] > 0)
		sn_valid = false;
	switch(ack_type){
		case ROHC_FEEDBACK_ACK:
			rohc_comp_v2_feedack_ack(context,msn,sn_mask_bits,sn_valid);
			break;
		case ROHC_FEEDBACK_NACK:
			if(context->context_state == COMP_STATE_SO){
				memset(&iph_context->update_trans_times,0,sizeof(struct iph_field_trans_times));
				memset(&iph_context->inner_update_trans_times,0,sizeof(struct iph_field_trans_times));
				rohc_comp_context_change_state(context,COMP_STATE_FO);
				if(prof_ops && prof_ops->feedback_input)
					prof_ops->feedback_input(co_context,ack_type,msn,sn_mask_bits,sn_valid);
			}
			break;
		case ROHC_FEEDBACK_STATIC_NACK:
			rohc_comp_context_change_state(context,COMP_STATE_IR);
			memset(&iph_context->update_trans_times,0,sizeof(struct iph_field_trans_times));
			memset(&iph_context->inner_update_trans_times,0,sizeof(struct iph_field_trans_times));
			if(prof_ops && prof_ops->feedback_input)
				prof_ops->feedback_input(co_context,ack_type,msn,sn_mask_bits,sn_valid);
			break;
	}
	return 0;
}
int rohc_comp_v2_feedback_input(struct rohc_comp_context *context,struct sk_buff *skb,int cid_len,int feeback_size)
{
	enum rohc_profile prof;
	int retval;
	struct rohc_comp_profile *comp_profile;
	u8 *data_start;
	retval = 0;
	comp_profile = context->comp_profile;
	prof = comp_profile->profile;
	if(!rohc_feeback_crc_is_ok(skb,prof,cid_len)){
		pr_err("%s : the cid-%d context feeback's crc is error\n",__func__,context->cid);
		retval = -EFAULT;
		goto out;
	}
	skb_pull(skb,cid_len);
	feeback_size -= cid_len;
	if(feeback_size  == 1)
		rohc_comp_v2_feedack_ack1(context,skb,feeback_size);
	else if(feeback_size > 1)
		rohc_comp_v2_feedack_ack2(context,skb,feeback_size);
	else{
		pr_err("context-%d,profile-%x recieved the size zero feedback\n",context->cid,prof);
		retval = -EFAULT;
	}

out:
	return retval;
}
