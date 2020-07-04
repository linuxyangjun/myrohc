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
#include "../profile/tcp_packet.h"
#include "../profile/tcp_profile.h"

#include "rohc_comp.h"
#include "rohc_comp_wlsb.h"
#include "rohc_comp_packet.h"

#include "comp_tcp.h"
#include "comp_tcp_clist.h"

/*profile tcp encoding method
 */

static inline u8 tcp_rsf_encode(u8 rsf)
{
	u8 rsf_idx;
	switch(rsf){
		case 0:
			rsf_idx = 0;
			break;
		case 1:
			rsf_idx = 3;
			break;
		case 2:
			rsf_idx = 2;
			break;
		case 4:
			rsf_idx = 1;
			break;
		default:
			rohc_pr(rohc_err,"not only one bit rsf:%x\n",rsf);
			break;
	}
	return rsf_idx;
}

static inline u8 tcp_ip_field_static_or_irreg_indicator(bool update)
{
	u8 ind;
	if(update)
		ind = 1;
	else
		ind = 0;
	return ind;
}

static inline u8 tcp_ip_field_vari_length_32(bool update,struct rohc_bits_encode_set *bits_set)
{
	u8 ind;
	if(!update)
		ind = 0;
	else if(ROHC_ENCODE_BITS_TEST(bits_set,ROHC_ENCODE_BY_BITS(8)))
		ind = 1;
	else if(ROHC_ENCODE_BITS_TEST(bits_set,ROHC_ENCODE_BY_BITS(16) && ROHC_ENCODE_P_BITS_TEST(bits_set,ROHC_TCP_WLSB_K_R_2_TO_P)))
		ind = 2;
	else
		ind = 3;

	return ind;
}

static inline u8 inner_iph_field_static_or_irreg_indicator(struct rohc_comp_packet_hdr_info *pkt_info,bool outer_update,bool inner_update)
{
	u8 ind;
	if(pkt_info->has_inner_iph){
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


static inline int tcp_ip_field_vari_length_32_build(u8 *to,u32 encode_v,u8 ind)
{
	int len = 0;
	switch(ind){
		case 1:
			*to = encode_v & 0xff;
			len = 1;
			break;
		case 2: 
			/*big endian*/
			*to = (encode_v >> 8) & 0xff;
			to++;
			*to = encode_v;
			len = 2;
			break;
		case 3:
			/*big endian*/
			encode_v = htonl(encode_v);
			memcpy(to,&encode_v,4);
			len = 4;
			break;
	}
	return len;
}

static inline int tcp_ip_field_static_or_irreg16(u8 *to,u16 encode_v,u8 ind)
{
	int len;
	if(!ind)
		len = 0;
	else{
		encode_v = htons(encode_v);
		memcpy(to,&encode_v,2);
		len = 2;
	}
	return len;
}

static inline int tcp_ip_field_static_or_irreg8(u8 *to,u8 encode_v,int ind)
{
	int len;
	if(!ind)
		len = 0;
	else{
		*to = encode_v;
		len = 1;
	}
	return len;
}


static inline int tcp_ip_field_static_or_irreg32(u8 *to,u32 encode_v,int ind)
{
	int len;
	if(!ind)
		len = 0;
	else{
		encode_v = htonl(encode_v);
		memcpy(to,&encode_v,4);
		len = 4;
	}
	return len;
}

/*If more than one level of IP headers is present,ROHC-TCP can assian
 * a sequential behavior(NBO or SWAP) only to the IP-ID of the innermost
 * ipv4 header.This is because only this IP-ID can possibly have a sufficicently
 * close correlation with MSN()to compress it as a sequential changing field.Therefore
 * ,a compresser MUST not assian ethier the seq-NBO or seq-SWAP behavior to tunneling headers.
 * But I think if innermost ip header is ipv6 or ip id behavior is random or zero,the ip-id of seq packet
 * can occupied by the outer ipv4 header.
 */


static inline enum ip_id_behavior __ip_id_behavior_true(u16 new_ipid,u16 old_ipid)
{
	enum ip_id_behavior true_ipid_bh;
	if(new_ipid == 0 && new_ipid == old_ipid)
		true_ipid_bh = IP_ID_BEHAVIOR_ZERO;
	if(ip_id_mon_increasing(new_ipid,old_ipid,20))
		true_ipid_bh = IP_ID_BEHAVIOR_SEQ_SWAP;
	else{
		new_ipid = __swab16(new_ipid);
		old_ipid = __swab16(old_ipid);
		if(ip_id_mon_increasing(new_ipid,old_ipid,20))
			true_ipid_bh = IP_ID_BEHAVIOR_SEQ_SWAP;
		else
			true_ipid_bh = IP_ID_BEHAVIOR_RANDOM;
	}
	return true_ipid_bh;

}
void tcp_ip_id_behavior_probe(struct tcp_iph_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info)
{

	struct iphdr *iph,*inner_iph,*old_iph,*old_inner_iph;
	struct last_comped_iph_ref *iph_ref;
	struct iph_update *iph_update,*inner_iph_update;;
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
			__ip_id_behavior_probe(new_ipid,old_ipid,&inner_iph_update->new_ipid_bh,true);
			if(rohc_iph_is_v4(iph->version)){
				new_ipid = ntohs(iph->id);
				old_ipid = ntohs(old_iph->id);
				__ip_id_behavior_probe(new_ipid,old_ipid,&iph_update->new_ipid_bh,false);
			}
		}else if(rohc_iph_is_v4(iph->version)){
			new_ipid = ntohs(iph->id);
			old_ipid = ntohs(old_iph->id);
			__ip_id_behavior_probe(new_ipid,old_ipid,&iph_update->new_ipid_bh,true);
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

static bool ip_id_only_one_seq(struct tcp_iph_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct iphdr *outer_iph,*inner_iph;
	struct iph_update *outer_iph_update,*inner_iph_update;
	bool retval = false;
	outer_iph = &pkt_info->iph;
	outer_iph_update = &ip_context->update_by_packet;
	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		inner_iph_update = &ip_context->inner_update_by_packet;
		/*only inner ip header is ipv6,the outer ip header ip-id can preemt the location if is outer ipv4*/
		if(rohc_iph_is_v4(inner_iph->version)){
			if(!ip_id_is_random_or_zero(inner_iph_update->new_ipid_bh))
				retval = true;
		}else{
			if(rohc_iph_is_v4(outer_iph->version) && !ip_id_is_random_or_zero(outer_iph_update->new_ipid_bh))
				retval = true;
		}
	}else{
		if(rohc_iph_is_v4(outer_iph->version) && !ip_id_is_random_or_zero(outer_iph_update->new_ipid_bh))
				retval = true;
	}
	return retval;
}

static bool ip_has_inner_iph_dynamic_field_full_update(struct tcp_iph_context *ip_context,bool has_inner_iph,int type)
{
	struct iph_update *iph_new_update;
	bool retval = false;
	if(has_inner_iph)
		iph_new_update = &ip_context->inner_update_by_packet;
	else
		iph_new_update = &ip_context->update_by_packet;
	switch(type){
		case IP_FIELD_DF:
			retval = iph_new_update->df_update;
			break;
		case IP_FIELD_DSCP:
			retval = iph_new_update->dscp_update;
			break;
		case IP_FIELD_TTL_HL:
			if(iph_new_update->ttl_hl_update && !ROHC_ENCODE_BITS_TEST(&iph_new_update->inner_ttl_hl_encode_bits,ROHC_ENCODE_BY_BITS(3)))
				retval = true;
			break;
		case IP_FIELD_IPID_BH:
			retval = iph_new_update->ipid_bh_update;
			break;
	}
	return retval;
}

static bool ip_inner_iph_ttl_field_update_can_encode(struct tcp_iph_context *ip_context,bool has_inner_iph)
{
	struct iph_update *iph_new_update;
	bool retval = false;
	if(has_inner_iph)
		iph_new_update = &ip_context->update_by_packet;
	else
		iph_new_update = &ip_context->inner_update_by_packet;
	if(iph_new_update->ttl_hl_update && ROHC_ENCODE_BITS_TEST(&iph_new_update->inner_ttl_hl_encode_bits,ROHC_ENCODE_BY_BITS(3)))
		retval = true;
	return retval;
}
static bool ip_has_outer_iph_dynamic_field_full_update(struct tcp_iph_context *ip_context,bool has_inner_iph,int type)
{
	struct iph_update *iph_new_update;
	bool retval = false;
	if(!has_inner_iph)
		return retval;
	iph_new_update = &ip_context->update_by_packet;
	switch(type){
		case IP_FIELD_DF:
			retval = iph_new_update->df_update;
			break;
		case IP_FIELD_DSCP:
			retval = iph_new_update->dscp_update;
			break;
		case IP_FIELD_TTL_HL:
			retval = iph_new_update->ttl_hl_update;
			break;
		case IP_FIELD_IPID_BH:
			retval = iph_new_update->ipid_bh_update;
			break;	
	}
	return retval;
}
static void ip_pick_non_rand_zero_ipid_off(struct tcp_iph_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info,u16 *ipid_off)
{
	struct iphdr *outer_iph,*inner_iph;
	struct iph_update *outer_iph_update,*inner_iph_update;
	outer_iph_update = &ip_context->update_by_packet;
	outer_iph = &pkt_info->iph;
	if(pkt_info->has_inner_iph){
		inner_iph_update = &ip_context->inner_update_by_packet;
		inner_iph = &pkt_info->inner_iph;
		if(rohc_iph_is_v4(inner_iph->version)){
			BUG_ON(ip_id_is_random_or_zero(inner_iph_update->new_ipid_bh));
			*ipid_off = inner_iph_update->new_ip_id_offset;
		}else if(rohc_iph_is_v4(outer_iph->version)){
			BUG_ON(ip_id_is_random_or_zero(outer_iph_update->new_ipid_bh));
			*ipid_off = outer_iph_update->new_ip_id_offset;
		}else
			pr_err("%s : error can't find the non random and non constant ip id,has_inner_iph=%s\n",__func__,pkt_info->has_inner_iph ? "true":"false");
	}else{
		if(rohc_iph_is_v4(outer_iph->version)){
			BUG_ON(ip_id_is_random_or_zero(outer_iph_update->new_ipid_bh));
			*ipid_off = outer_iph_update->new_ip_id_offset;
		}else
			pr_err("%s : error can't find the non random and non constant ip id,has_inner_iph=%s\n",__func__,pkt_info->has_inner_iph ? "true":"false");
	}
}

static inline bool ip_seq_ip_id_encode_sets_test(struct tcp_iph_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info,int bits)
{
	struct iphdr *iph,*inner_iph;
	struct iph_update *iph_new_update,*inner_iph_new_update;
	bool retval = false;
	iph = &pkt_info->iph;
	iph_new_update = &ip_context->update_by_packet;
	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		inner_iph_new_update = &ip_context->inner_update_by_packet;
		if(rohc_iph_is_v4(inner_iph->version)){
			if(ROHC_ENCODE_BITS_TEST(&inner_iph_new_update->new_ipid_off_encode_bits,bits))
				retval = true;
		}else{
			if(ROHC_ENCODE_BITS_TEST(&iph_new_update->new_ipid_off_encode_bits,bits))
				retval = true;
		}
	}else{
		if(ROHC_ENCODE_BITS_TEST(&iph_new_update->new_ipid_off_encode_bits,bits))
				retval = true;
	}
	return retval;
}
void ipid_cal_bits_encode_set(struct iph_update *new_update,struct iphdr *iph,struct comp_win_lsb *wlsb,u32 msn)
{
	u16 ipid,ipid_off;
	ipid = ntohs(iph->id);
	if(!ip_id_is_nbo(new_update->new_ipid_bh)){
		ipid = __swab16(ipid);
		ipid_off = ipid - msn;
	}else
		ipid_off = ipid - msn;
	new_update->new_ip_id_offset = ipid_off;
	/*dectect the encode bits for packet common
	 */

	if(ip_id_is_random_or_zero(new_update->new_ipid_bh))
		return;
	if(comp_wlsb_can_encode_type_ushort(wlsb,8,ROHC_LSBC_TCP_IPID_K_TO_P(8),ipid_off))
		ROHC_ENCODE_BITS_SET(&new_update->new_ipid_off_encode_bits,ROHC_ENCODE_BY_BITS(8));
	/*dectect the encode bits for sequential packet.
	 */
	if(comp_wlsb_can_encode_type_ushort(wlsb,4,ROHC_LSBC_TCP_IPID_K_TO_P(4),ipid_off))
		ROHC_ENCODE_BITS_SET(&new_update->new_ipid_off_encode_bits,ROHC_ENCODE_BY_BITS(4));
	if(comp_wlsb_can_encode_type_ushort(wlsb,3,ROHC_LSBC_TCP_IPID_K_TO_P(3),ipid_off))
		ROHC_ENCODE_BITS_SET(&new_update->new_ipid_off_encode_bits,ROHC_ENCODE_BY_BITS(3));
	if(comp_wlsb_can_encode_type_ushort(wlsb,7,ROHC_LSBC_TCP_IPID_K_TO_P(7),ipid_off))
		ROHC_ENCODE_BITS_SET(&new_update->new_ipid_off_encode_bits,ROHC_ENCODE_BY_BITS(7));
	if(comp_wlsb_can_encode_type_ushort(wlsb,5,ROHC_LSBC_TCP_IPID_K_TO_P(5),ipid_off))
		ROHC_ENCODE_BITS_SET(&new_update->new_ipid_off_encode_bits,ROHC_ENCODE_BY_BITS(5));
}
void ttl_cal_bits_encode_set(struct iph_update *new_update,struct comp_win_lsb *wlsb,u8 ttl_hl)
{
	if(comp_wlsb_can_encode_type_uchar(wlsb,3,ROHC_LSB_TCP_TTL_HL,ttl_hl))
		ROHC_ENCODE_BITS_SET(&new_update->inner_ttl_hl_encode_bits,ROHC_ENCODE_BY_BITS(3));
}
void ipv4h_update_probe(struct iphdr *new_iph,struct iphdr *old_iph,struct iph_update *new_update,struct iph_update_trans_times *trans_times,enum ip_id_behavior new_ipid_bh,enum ip_id_behavior old_ipid_bh,int oa_max)
{
	/*ip header ttl update probe
	 */
	net_header_field_update_probe(new_iph->ttl,old_iph->ttl,&new_update->ttl_hl_update,&trans_times->ttl_hl_trans_time,oa_max);
	/*iph header dsp update pobe
	  */
	net_header_field_update_probe(new_iph->tos >> 2,old_iph->tos >> 2,&new_update->dscp_update,&trans_times->dscp_trans_time,oa_max);
	if(new_iph->tos & 0x3)
		new_update->ecn_carryed = true;
	/*ip header df update probe
	 */
	net_header_field_update_probe(ntohs(new_iph->frag_off) & IP_DF,ntohs(old_iph->frag_off) & IP_DF,&new_update->df_update,&trans_times->df_trans_time,oa_max);
	/*ip id behavior update probe
	 */
	net_header_field_update_probe(new_ipid_bh,old_ipid_bh,&new_update->ipid_bh_update,&trans_times->ipid_bh_trans_time,oa_max);

}
void ipv6h_update_probe(void)
{

}
int tcp_iph_update_probe(struct tcp_iph_context *iph_context,struct rohc_comp_packet_hdr_info *pkt_info,int oa_max,u32 msn)
{
	struct iphdr *new_iph,*new_inner_iph;
	struct iphdr *old_iph,*old_inner_iph;
	struct iph_update *new_iph_update,*new_inner_iph_update;
	new_iph = &pkt_info->iph;
	old_iph = &iph_context->iph_ref.iph;
	new_iph_update = &iph_context->update_by_packet;
	new_inner_iph_update = &iph_context->inner_update_by_packet;
	memset(new_iph_update,0,sizeof(struct iph_update));
	memset(new_inner_iph_update,0,sizeof(struct iph_update));
	tcp_ip_id_behavior_probe(iph_context,pkt_info);
	if(rohc_iph_is_v4(new_iph->version))
		ipv4h_update_probe(new_iph,old_iph,new_iph_update,&iph_context->update_trans_times,new_iph_update->new_ipid_bh,iph_context->iph_ref.ipid_bh,oa_max);
	else
		ipv6h_update_probe();
	if(pkt_info->has_inner_iph){
		new_inner_iph = &pkt_info->inner_iph;
		old_inner_iph = &iph_context->iph_ref.inner_iph;
		if(rohc_iph_is_v4(new_inner_iph->version)){
			ipid_cal_bits_encode_set(new_inner_iph_update,new_inner_iph,iph_context->inner_ipid_wlsb,msn);
		}else if(rohc_iph_is_v4(new_iph->version))
			ipid_cal_bits_encode_set(new_iph_update,new_iph,iph_context->ipid_wlsb,msn);
		if(rohc_iph_is_v4(new_inner_iph->version)){
			ipv4h_update_probe(new_inner_iph,old_inner_iph,new_inner_iph_update,&iph_context->inner_update_trans_times,new_inner_iph_update->new_ipid_bh,iph_context->iph_ref.inner_ipid_bh,oa_max);
			ttl_cal_bits_encode_set(new_inner_iph_update,iph_context->ttl_hl_wlsb,new_inner_iph->ttl);
		}else{
			ipv6h_update_probe();
			//ttl_cal_bits_encode_set(new_inner_iph_update,iph_context->ttl_hl_wlsb,);
		}
	}else{
		if(rohc_iph_is_v4(new_iph->version)){
			ipid_cal_bits_encode_set(new_iph_update,new_iph,iph_context->ipid_wlsb,msn);
			ttl_cal_bits_encode_set(new_iph_update,iph_context->ttl_hl_wlsb,new_iph->ttl);
		}else{
			//ipv6 hopl cal.
		}
	}
}
static inline void tcp_seq_scaled_cal_bits_encode_set(struct comp_win_lsb *wlsb,struct tcph_update *new_update,u32 seq_scaled)
{
	if(comp_wlsb_can_encode_type_uint(wlsb,4,ROHC_LSB_TCP_SEQ_SCALED_P,seq_scaled))
		ROHC_ENCODE_BITS_SET(&new_update->seq_scaled_encode_bits,ROHC_ENCODE_BY_BITS(4));
}

static inline void tcp_ack_seq_scaled_cal_bits_encode_set(struct comp_win_lsb *wlsb,struct tcph_update *new_update,u32 ack_seq_scaled)
{
	if(comp_wlsb_can_encode_type_uint(wlsb,4,ROHC_LSB_TCP_ACK_SEQ_SCALED_P,ack_seq_scaled))
		ROHC_ENCODE_BITS_SET(&new_update->ack_seq_scaled_encode_bits,ROHC_ENCODE_BY_BITS(4));
}


static inline void tcp_ack_seq_cal_bits_encode_set(struct comp_win_lsb *wlsb,struct tcph_update *new_update,u32 ack_seq)
{
	u32 last_ack_seq;
	rohc_comp_wlsb_peek_last_val(wlsb,&last_ack_seq);
	rohc_pr(ROHC_DTCP,"new_ack = %lu,last_ack_seq=%lu\n",ack_seq,last_ack_seq);
	if(comp_wlsb_can_encode_type_uint(wlsb,8,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(8),ack_seq))
		ROHC_ENCODE_BITS_SET(&new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(8));
	if(comp_wlsb_can_encode_type_uint(wlsb,15,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(15),ack_seq))
		ROHC_ENCODE_BITS_SET(&new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(14));
	if(comp_wlsb_can_encode_type_uint(wlsb,16,ROHC_LSB_TCP_K_RSHIFT_1_TO_P(16),ack_seq)){
		ROHC_ENCODE_BITS_SET(&new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(16));
		ROHC_ENCODE_BITS_P_SET(&new_update->ack_seq_encode_bits,ROHC_TCP_WLSB_K_R_1_TO_P);
	}
	if(comp_wlsb_can_encode_type_uint(wlsb,16,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(16),ack_seq)){
		ROHC_ENCODE_BITS_SET(&new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(16));
		ROHC_ENCODE_BITS_P_SET(&new_update->ack_seq_encode_bits,ROHC_TCP_WLSB_K_R_2_TO_P);
	}

	if(comp_wlsb_can_encode_type_uint(wlsb,18,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(18),ack_seq)){
		ROHC_ENCODE_BITS_SET(&new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(18));
	}

}

static inline void tcp_window_cal_bits_encode_set(struct comp_win_lsb *wlsb,struct tcph_update *new_update,u16 window)
{
	if(comp_wlsb_can_encode_type_uint(wlsb,15,ROHC_LSB_TCP_K_RSHIFT_1_TO_P(15),window))
		ROHC_ENCODE_BITS_SET(&new_update->window_encode_bits,ROHC_ENCODE_BY_BITS(15));
}
static inline void tcp_seq_cal_bits_encode_set(struct comp_win_lsb *wlsb,struct tcph_update *new_update,u32 seq)
{
	u32 last_seq;
	rohc_comp_wlsb_peek_last_val(wlsb,&last_seq);
	rohc_pr(ROHC_DTCP,"new_seq = %lu,last_seq=%lu\n",seq,last_seq);
	if(comp_wlsb_can_encode_type_uint(wlsb,8,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(8),seq))
		ROHC_ENCODE_BITS_SET(&new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(8));
	if(comp_wlsb_can_encode_type_uint(wlsb,14,ROHC_LSB_TCP_K_RSHIFT_1_TO_P(14),seq))
		ROHC_ENCODE_BITS_SET(&new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(14));
	if(comp_wlsb_can_encode_type_uint(wlsb,16,ROHC_LSB_TCP_K_RSHIFT_1_TO_P(16),seq)){
		ROHC_ENCODE_BITS_SET(&new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(16));
		ROHC_ENCODE_BITS_P_SET(&new_update->seq_encode_bits,ROHC_TCP_WLSB_K_R_1_TO_P);
	}
	if(comp_wlsb_can_encode_type_uint(wlsb,16,ROHC_LSB_TCP_K_RSHIFT_0_TO_P(16),seq)){
		ROHC_ENCODE_BITS_SET(&new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(16));
		ROHC_ENCODE_BITS_P_SET(&new_update->seq_encode_bits,ROHC_TCP_WLSB_K_R_0_TO_P);
	}
	if(comp_wlsb_can_encode_type_uint(wlsb,18,ROHC_LSB_TCP_K_RSHIFT_2_TO_P(18),seq)){
		ROHC_ENCODE_BITS_SET(&new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(18));
	}
}
void tcph_update_probe(struct tcph_context *tcp_context,struct rohc_comp_packet_hdr_info *pkt_info,int oa_max)
{
	struct tcphdr *new_tcph,*old_tcph;
	struct tcph_update *new_update;
	struct last_comped_tcph_ref *tcph_ref;
	struct tcph_update_trans_times *trans_times;
	struct sk_buff *skb;

	u32 new_ack_seq,old_ack_seq;
	u32 new_seq,old_seq;
	u32 ack_stride,ack_seq_scaled,ack_seq_residue;

	u32 seq_scaled,seq_residue;
	u16 new_window,old_window;
	u8  new_rsf,old_rsf;
	int tcp_payload_len;
	new_update = &tcp_context->tcph_update_by_packet;
	tcph_ref = &tcp_context->tcph_ref;
	trans_times = &tcp_context->update_trans_times;
	skb = pkt_info->skb;
	new_tcph = &pkt_info->tcph;
	old_tcph = &tcph_ref->tcph;
	new_seq = ntohl(new_tcph->seq);
	old_seq = ntohl(old_tcph->seq);
	new_ack_seq = ntohl(new_tcph->ack_seq);
	old_ack_seq = ntohl(old_tcph->ack_seq);
	new_window = ntohs(new_tcph->window);
	old_window = ntohs(old_tcph->window);
	new_rsf = (new_tcph->rst << 2 ) | (new_tcph->syn << 1) | new_tcph->fin;
	old_rsf = (old_tcph->rst << 2) | (old_tcph->syn << 1) | old_tcph->fin;
	memset(new_update,0,sizeof(struct tcph_update));
	/*detect tcp window update*/
	net_header_field_update_probe(new_window,old_window,&new_update->window_update,&trans_times->window_trans_time,oa_max);
	/*dectect sequential update
	  */
	net_header_field_update_probe(new_seq,old_seq,&new_update->seq_update,&trans_times->seq_trans_time,oa_max);
	/*detect ack sequential update
	  */
	net_header_field_update_probe(new_ack_seq,old_ack_seq,&new_update->ack_seq_update,&trans_times->ack_seq_trans_time,oa_max);
	/*detect ack flag update
	  */
	net_header_field_update_probe(new_tcph->ack,old_tcph->ack,&new_update->ack_flag_update,NULL,oa_max);
	/*detect urg flag update */

	net_header_field_update_probe(new_tcph->urg,old_tcph->urg,&new_update->urg_flag_update,NULL,oa_max);
	/*detect urg prt update*/
	net_header_field_update_probe(new_tcph->urg_ptr,old_tcph->urg_ptr,&new_update->urg_ptr_update,NULL,oa_max);
	/*detect resved bits update*/
	net_header_field_update_probe(new_tcph->res1,old_tcph->res1,&new_update->res1_flags_update,NULL,oa_max);
	/*detect urg pointer is present*/
	if(new_tcph->urg)
		new_update->urg_carryed = true;

	/*detect tcp ecn flags is zero or not*/
	if(new_tcph->ece || new_tcph->cwr)
		new_update->ecn_carryed = true;
	/*detect rst,syn,fin flags probe */
	net_header_field_update_probe(new_rsf,old_rsf,&new_update->rsf_flags_update,NULL,oa_max);
	if(hweight8(new_rsf) <= 1)
		new_update->rsf_carray_one_or_zero_bit = true;
	/*detect tcp sequential factor or residue update*/
	tcp_payload_len = skb->len - pkt_info->to_comp_pkt_hdr_len;
	tcp_field_scaling(tcp_payload_len,&seq_scaled,new_seq,&seq_residue);
	if(!tcp_payload_len || tcp_payload_len != tcph_ref->seq_factor || seq_residue != tcph_ref->seq_residue){
		new_update->seq_scale_factor_or_residue_update = true;
		trans_times->new_seq_scaled_encode_trans_time = 0;
		rohc_pr(ROHC_DTCP,"%s:%d\n",__func__,__LINE__);
	}else if(trans_times->new_seq_scaled_encode_trans_time < oa_max){
		new_update->seq_scale_factor_or_residue_update = true;
		rohc_pr(ROHC_DTCP,"%s:%d\n",__func__,__LINE__);

	}
	else
		new_update->seq_scale_factor_or_residue_update = false;
	rohc_pr(ROHC_DTCP,"tcp_payload_len=%d,last_seq_factor=%d,new_seq_residue=%d,last_seq_residue=%d,seq_scacled_trans:%d\n",tcp_payload_len,tcph_ref->seq_factor,seq_residue,tcph_ref->seq_residue,trans_times->new_seq_scaled_encode_trans_time);
	/*detect tcp ack factor or residue update;*/
	ack_stride = (new_ack_seq - old_ack_seq) & 0xffff;
	if(ack_stride && (comp_wlsb_cal_appear_rate(tcp_context->ack_stride_wlsb,ack_stride) < RATE_PERCENT_50))
		ack_stride = tcph_ref->ack_stride;

	if(!ack_stride)
		ack_stride = tcph_ref->ack_stride;
	/*if ack_stride is zero,we can transmit it to decompresser,and decompresser
	  *can use the residue to revoery the ack seq [ack_seq = 0 * 0 + ack_seq_residue]
	  */
	if(ack_stride){
		tcp_field_scaling(ack_stride,&ack_seq_scaled,new_ack_seq,&ack_seq_residue);
		net_header_field_update_probe(ack_stride,tcph_ref->ack_stride,&new_update->ack_stride_update,&trans_times->ack_stride_trans_time,oa_max);
		net_header_field_update_probe(ack_seq_residue,tcph_ref->ack_seq_residue,&new_update->ack_seq_residue_update,&trans_times->new_ack_seq_residue_trans_time,oa_max);
	}else{
#if 1
		/*if the ack stride is zero,compresser can't transmit the scaled of ack seq,only
		 * transmit the original ack seq
		 */
		if(new_update->ack_seq_update){
			new_update->ack_seq_residue_update = true;
			trans_times->new_ack_seq_residue_trans_time = 0;
		}
#endif
	}
	rohc_pr(ROHC_DTCP,"new_ack_stride:%d,last_ack_stride:%d,ack_stride_use:%d\n",new_ack_seq-old_ack_seq,tcph_ref->ack_stride,ack_stride);

	new_update->seq_factor = tcp_payload_len;
	new_update->seq_residue = seq_residue;
	new_update->seq_scaled = seq_scaled;
	new_update->ack_stride_true = (new_ack_seq - old_ack_seq) & 0xffff;
	if(ack_stride){
		new_update->ack_stride_use = ack_stride;
		new_update->ack_seq_scaled = ack_seq_scaled;
		new_update->ack_seq_residue = ack_seq_residue;
	}

	if(!new_update->seq_scale_factor_or_residue_update)
		tcp_seq_scaled_cal_bits_encode_set(tcp_context->seq_scaled_wlsb,new_update,seq_scaled);
	if(!new_update->ack_stride_update && !new_update->ack_seq_residue_update)
		tcp_ack_seq_scaled_cal_bits_encode_set(tcp_context->ack_seq_scaled_wlsb,new_update,ack_seq_scaled);
	tcp_ack_seq_cal_bits_encode_set(tcp_context->ack_seq_wlsb,new_update,new_ack_seq);
	tcp_seq_cal_bits_encode_set(tcp_context->seq_wlsb,new_update,new_seq);
	tcp_window_cal_bits_encode_set(tcp_context->window_wlsb,new_update,new_window);

}
void tcp_ecn_use_update(struct comp_tcp_context *c_tcp_context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct tcp_iph_context *ip_context;
	struct tcph_context *tcp_context;
	bool new_ecn_used;
	bool outer_dscp_update;
	bool ecn_is_carryed;
	c_tcp_context->ecn_used_update = false;
	ip_context = &c_tcp_context->ip_context;
	tcp_context = &c_tcp_context->tcp_context;
	ecn_is_carryed = ip_context->update_by_packet.ecn_carryed;
	if(pkt_info->has_inner_iph){
		outer_dscp_update = ip_context->update_by_packet.dscp_update;
		ecn_is_carryed = !!(ip_context->inner_update_by_packet.ecn_carryed || ecn_is_carryed);
	}else
		outer_dscp_update = false;
	if(outer_dscp_update || ecn_is_carryed || tcp_context->tcph_update_by_packet.res1_flags_update || tcp_context->tcph_update_by_packet.ecn_carryed)
		new_ecn_used = true;
	else
		new_ecn_used = false;
	c_tcp_context->ecn_used = new_ecn_used;
	net_header_field_update_probe(new_ecn_used,c_tcp_context->last_ecn_used,&c_tcp_context->ecn_used_update,&c_tcp_context->ecn_used_trans_time,c_tcp_context->oa_upward_pkts);

}
void comp_tcp_update_probe(struct comp_tcp_context *c_tcp_context,struct rohc_comp_packet_hdr_info *pkt_info,u32 msn)
{
	struct tcp_iph_context *ip_context;
	struct tcph_context *tcp_context;
	int oa_max;
	oa_max = c_tcp_context->oa_upward_pkts;
	ip_context = &c_tcp_context->ip_context;
	tcp_context = &c_tcp_context->tcp_context;
	tcp_iph_update_probe(ip_context,pkt_info,oa_max,msn);
	tcph_update_probe(tcp_context,pkt_info,oa_max);
	tcp_ecn_use_update(c_tcp_context,pkt_info);
	tcp_options_update_probe(&c_tcp_context->tcp_opt_context,pkt_info,c_tcp_context->oa_upward_pkts,tcp_context->tcph_update_by_packet.ack_seq_update);
	if(comp_wlsb_can_encode_type_ushort(tcp_context->msn_wlsb,4,ROHC_LSB_TCP_MSN_P,msn)){
		ROHC_ENCODE_BITS_SET(&tcp_context->tcph_update_by_packet.msn_encode_bits,ROHC_ENCODE_BY_BITS(4));
	}else{
		rohc_pr(ROHC_DTCP,"msn can't encode by 4 bit,msn = %d\n",msn);
	}
}



int comp_tcp_build_common(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool bulid_first)
{
	u8 *comp_hdr;
	struct iphdr *iph,*inner_iph;
	struct tcphdr *tcph;
	struct sk_buff *comp_skb;
	struct rohc_compresser *rohc_comp;
	struct comp_tcp_context *c_tcp_context;
	struct tcp_iph_context *iph_context;
	struct tcph_context	*tcp_context;
	struct tcph_option_context *opt_context;
	struct iph_update *outer_iph_update;
	struct iph_update *inner_iph_update;
	struct tcph_update *tcph_update;
	struct tcph_update_trans_times *tcph_trans_times;
	struct iph_update_trans_times *iph_trans_times;
	struct iph_update_trans_times *inner_iph_trans_times;
	struct profile_tcp_co_common *common;
	u32 msn;
	u8 crc;
	u8 ind;
	bool build_full;
	int call_len;
	int encode_len = 0;
	int retval = 0;
	comp_skb = context->comp_skb;
	rohc_comp = context->compresser;
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	iph_context = &c_tcp_context->ip_context;
	tcp_context = &c_tcp_context->tcp_context;
	opt_context = &c_tcp_context->tcp_opt_context;
	outer_iph_update = &iph_context->update_by_packet;
	inner_iph_update = &iph_context->inner_update_by_packet;
	iph_trans_times = &iph_context->update_trans_times;
	inner_iph_trans_times = &iph_context->inner_update_trans_times;
	tcph_update = &tcp_context->tcph_update_by_packet;
	tcph_trans_times = &tcp_context->update_trans_times;
	comp_hdr = skb_tail_pointer(comp_skb);
	iph = &pkt_info->iph;
	tcph = &pkt_info->tcph;
	msn = context->co_fields.msn;
	if(rohc_comp->cid_type == CID_TYPE_SMALL){
		common = (struct profile_tcp_co_common *)comp_hdr;
		build_full = true;
	}else{
		if(bulid_first){
			common = (struct profile_tcp_co_common *)comp_hdr;

		}else{
			common = (struct profile_tcp_co_common *)(comp_hdr - 1);
		}
		build_full = false;
	}
	if(bulid_first){
		common->disc = ROHC_PACKET_CO_COMMON >> 1;
		if(pkt_info->has_inner_iph && outer_iph_update->ttl_hl_update)
			common->ttl_hl = 1;
		else
			common->ttl_hl = 0;
		encode_len = 1;

	}
	if(bulid_first && !build_full)
		goto out;
	/*bulid the remainder of base header
	 */
	common->msn = msn & 0xf;
	common->ack = tcph->ack;
	common->push = tcph->psh;
	common->rsf = tcp_rsf_encode((tcph->rst << 2 ) | (tcph->syn << 1) | tcph->fin);
	if(tcph_update->urg_ptr_update)
		common->urg_ind = 1;
	else 
		common->urg_ind = 0;
	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		if(rohc_iph_is_v4(inner_iph->version)){
			common->ipid_bh = inner_iph_update->new_ipid_bh;
			increase_iph_dynamic_field_trans_times(inner_iph_trans_times,IP_FIELD_IPID_BH);
			if(!ip_id_is_random_or_zero(inner_iph_update->new_ipid_bh)){
				if(ROHC_ENCODE_BITS_TEST(&inner_iph_update->new_ipid_off_encode_bits,ROHC_ENCODE_BY_BITS(8)))
					common->ip_id_ind = 0;
				else
					common->ip_id_ind = 1;
			}else
				common->ip_id_ind = 0;
		}else if(rohc_iph_is_v4(iph->version) && !ip_id_is_random_or_zero(outer_iph_update->new_ipid_bh)){
			if(ROHC_ENCODE_BITS_TEST(&outer_iph_update->new_ipid_off_encode_bits,ROHC_ENCODE_BY_BITS(8)))
				common->ip_id_ind = 0;
			else
				common->ip_id_ind = 1;
		}else
			common->ip_id_ind = 0;
	}else if(rohc_iph_is_v4(iph->version)){
		/*only one ipv4 header*/
		common->ipid_bh = outer_iph_update->new_ipid_bh;
		increase_iph_dynamic_field_trans_times(iph_trans_times,IP_FIELD_IPID_BH);
		if(!ip_id_is_random_or_zero(outer_iph_update->new_ipid_bh)){
			if(ROHC_ENCODE_BITS_TEST(&outer_iph_update->new_ipid_off_encode_bits,ROHC_ENCODE_BY_BITS(8)))
				common->ip_id_ind = 0;
			else
				common->ip_id_ind = 1;
		}else
			common->ip_id_ind = 0;
	}else
		common->ip_id_ind = 0;
	common->win_ind = tcp_ip_field_static_or_irreg_indicator(tcph_update->window_update);
	common->ack_stride_ind = tcp_ip_field_static_or_irreg_indicator(tcph_update->ack_stride_update && tcph_update->ack_stride_use);
	common->ack_seq_ind = tcp_ip_field_vari_length_32((tcph_update->ack_seq_update | tcph_update->ack_stride_update | tcph_update->ack_seq_residue_update),&tcph_update->ack_seq_encode_bits);
	common->seq_ind = tcp_ip_field_vari_length_32((tcph_update->seq_update | tcph_update->seq_scale_factor_or_residue_update),&tcph_update->seq_encode_bits);
	common->urg = tcph->urg;
	common->inner_ttl_hl = inner_iph_field_static_or_irreg_indicator(pkt_info,outer_iph_update->ttl_hl_update,inner_iph_update->ttl_hl_update);
	common->dscp_ind = inner_iph_field_static_or_irreg_indicator(pkt_info,outer_iph_update->dscp_update,inner_iph_update->dscp_update);

	common->list_ind = tcp_ip_field_static_or_irreg_indicator(opt_context->opts_update_by_packet.list_structure_update | opt_context->opts_update_by_packet.content_update_not_defined_in_irr);
	common->ecn_used = c_tcp_context->ecn_used;
	c_tcp_context->ecn_used_trans_time++;
	/*now not support crc,so set it zero
	 */
	common->crc = 0;
	if(pkt_info->has_inner_iph){
		common->df = !!(ntohs(inner_iph->frag_off) & IP_DF);
		increase_iph_dynamic_field_trans_times(inner_iph_trans_times,IP_FIELD_DF);
	}else{
		increase_iph_dynamic_field_trans_times(iph_trans_times,IP_FIELD_DF);
		common->df = !!(ntohs(iph->frag_off) & IP_DF);
	}

	encode_len += sizeof(struct profile_tcp_co_common) - 1;
	comp_hdr += encode_len;
	rohc_pr(ROHC_DTCP,"%s : comp_hdr_len=%d\n",__func__,pkt_info->comp_hdr_len + encode_len);
	/*next build the dynamic exist field*/
	/*field.1 ,tcp seq*/
	call_len = tcp_ip_field_vari_length_32_build(comp_hdr,ntohl(tcph->seq),common->seq_ind);
	comp_hdr += call_len;
	encode_len += call_len;
	if(common->seq_ind){
		increase_tcph_dynamic_field_trans_times(tcph_trans_times,TCP_FIELD_SEQ);
		increase_tcph_dynamic_field_trans_times(tcph_trans_times,TCP_FIELD_SEQ_SCALED);
	}
	/*filed.2 ,ack seq*/
	call_len = tcp_ip_field_vari_length_32_build(comp_hdr,ntohl(tcph->ack_seq),common->ack_seq_ind);
	comp_hdr += call_len;
	encode_len += call_len;
	if(common->ack_seq_ind){
		increase_tcph_dynamic_field_trans_times(tcph_trans_times,TCP_FIELD_ACK_SEQ);
		increase_tcph_dynamic_field_trans_times(tcph_trans_times,TCP_FIELD_ACK_SEQ_RESIDUE);
	}
	/*filed.3 ack stride*/
	call_len = tcp_ip_field_static_or_irreg16(comp_hdr,tcph_update->ack_stride_use,common->ack_stride_ind);
	comp_hdr += call_len;
	encode_len += call_len;
	if(common->ack_stride_ind)
		increase_tcph_dynamic_field_trans_times(tcph_trans_times,TCP_FIELD_ACK_STRIDE);
	/*filed.4 tcp window*/
	call_len = tcp_ip_field_static_or_irreg16(comp_hdr,ntohs(tcph->window),common->win_ind);
	comp_hdr += call_len;
	encode_len += call_len;
	if(common->win_ind)
		increase_tcph_dynamic_field_trans_times(tcph_trans_times,TCP_FIELD_WIN);
	/*filed.5 ipid*/
	if(pkt_info->has_inner_iph){
		if(rohc_iph_is_v4(inner_iph->version)){
			if(!ip_id_is_random_or_zero(inner_iph_update->new_ipid_bh)){
				if(common->ip_id_ind){
					/*big endian*/
					memcpy(comp_hdr,&inner_iph->id,2);
					comp_hdr += 2;
					encode_len += 2;
				}else{
					/*fill the ipid =:= ip_id_lsb()
					 */
					*comp_hdr = inner_iph_update->new_ip_id_offset & 0xff;
					comp_hdr++;
					encode_len++;
				}
			}
		}else{
			if(rohc_iph_is_v4(iph->version) && !ip_id_is_random_or_zero(outer_iph_update->new_ipid_bh)){
				if(common->ip_id_ind){
					/*big endian*/
					memcpy(comp_hdr,&iph->id,2);
					comp_hdr += 2;
					encode_len += 2;
				}else{
					/*fill the ipid =:= ip_id_lsb()
					 */
					*comp_hdr = outer_iph_update->new_ip_id_offset & 0xff;
					comp_hdr++;
					encode_len++;
				}
			}
		}
	}else{
		if(rohc_iph_is_v4(iph->version) && !ip_id_is_random_or_zero(outer_iph_update->new_ipid_bh)){
				if(common->ip_id_ind){
					/*big endian*/
					memcpy(comp_hdr,&iph->id,2);
					comp_hdr += 2;
					encode_len += 2;
				}else{
					/*fill the ipid =:= ip_id_lsb()
					 */
					*comp_hdr = outer_iph_update->new_ip_id_offset & 0xff;
					comp_hdr++;
					encode_len++;
				}
		}
	}
	/*filed 6,urg_ptr*/
	call_len = tcp_ip_field_static_or_irreg16(comp_hdr,ntohs(tcph->urg_ptr),common->urg_ind);
	comp_hdr += call_len;
	encode_len += call_len;
	
	/*filed.7 dscp*/
	if(common->dscp_ind){
		if(pkt_info->has_inner_iph){
			if(rohc_iph_is_v4(inner_iph->version)){
				*comp_hdr = inner_iph->tos & ~0x3;
				increase_iph_dynamic_field_trans_times(inner_iph_trans_times,IP_FIELD_DSCP);
			}else{
				//IPV6
			}
		}else{
			if(rohc_iph_is_v4(iph->version)){
				*comp_hdr = iph->tos & ~0x3;
				increase_iph_dynamic_field_trans_times(iph_trans_times,IP_FIELD_DSCP);
			}else{
				//IPV6
			}
		}
		comp_hdr++;
		encode_len++;
	}
	/*filed 8,ttl_hopl only ipv4*/
	if(common->inner_ttl_hl){
		if(pkt_info->has_inner_iph){
			if(rohc_iph_is_v4(inner_iph->version)){
				*comp_hdr = inner_iph->ttl;
				increase_iph_dynamic_field_trans_times(inner_iph_trans_times,IP_FIELD_TTL_HL);
			}else{
				//IPV6
			}
		}else{
			if(rohc_iph_is_v4(iph->version)){
				*comp_hdr = iph->ttl;
				increase_iph_dynamic_field_trans_times(iph_trans_times,IP_FIELD_TTL_HL);
			}else{
				//IPV6
			}
		}
		comp_hdr++;
		encode_len++;
	}
	if(common->list_ind){
		skb_put(comp_skb,encode_len);
		pkt_info->comp_hdr_len += encode_len;
		encode_len = 0;
		retval = tcp_options_build_clist(opt_context,comp_skb,pkt_info);
	}

out:
	pkt_info->comp_hdr_len += encode_len;
	skb_put(comp_skb,encode_len);
	return retval;
}


int comp_tcp_build_rnd1(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool bulid_first)
{
	u8 *comp_hdr;
	struct iphdr *iph,*inner_iph;
	struct tcphdr *tcph;
	struct sk_buff *comp_skb;
	struct rohc_compresser *rohc_comp;
	struct comp_tcp_context *c_tcp_context;
	struct tcp_iph_context *iph_context;
	struct tcph_context	*tcp_context;
	struct profile_tcp_rnd1 *rnd1;
	u32 msn,seq;

	bool build_full;
	int encode_len = 0;
	int retval = 0;
	comp_skb = context->comp_skb;
	rohc_comp = context->compresser;
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	tcp_context = &c_tcp_context->tcp_context;
	comp_hdr = skb_tail_pointer(comp_skb);
	iph = &pkt_info->iph;
	tcph = &pkt_info->tcph;
	msn = context->co_fields.msn;
	seq = ntohl(tcph->seq);
	if(rohc_comp->cid_type == CID_TYPE_SMALL){
		rnd1 = (struct profile_tcp_rnd1 *)comp_hdr;
		build_full = true;
	}else{
		if(bulid_first){
			rnd1 = (struct profile_tcp_rnd1 *)comp_hdr;

		}else{
			rnd1 = (struct profile_tcp_rnd1 *)(comp_hdr - 1);
		}
		build_full = false;
	}
	if(bulid_first){
		rnd1->disc = ROHC_PACKET_RND1 >> 2;
		rnd1->seq0 = (seq >> 16) & 0x3;
		encode_len = 1;
	}
	if(bulid_first && !build_full)
		goto out;
	rnd1->seq1 = (seq >> 8) & 0xff;
	rnd1->seq2 = seq & 0xff;
	rnd1->msn = msn & 0xf;
	rnd1->push = tcph->psh;
	rnd1->crc = 0;
	encode_len += sizeof(struct profile_tcp_rnd1) - 1;

	increase_tcph_dynamic_field_trans_times(&tcp_context->update_trans_times,TCP_FIELD_SEQ);
	increase_tcph_dynamic_field_trans_times(&tcp_context->update_trans_times,TCP_FIELD_SEQ_SCALED);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}
int comp_tcp_build_rnd2(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool bulid_first)
{
	u8 *comp_hdr;
	struct iphdr *iph,*inner_iph;
	struct tcphdr *tcph;
	struct sk_buff *comp_skb;
	struct rohc_compresser *rohc_comp;
	struct comp_tcp_context *c_tcp_context;
	struct tcp_iph_context *iph_context;
	struct tcph_context	*tcp_context;
	struct tcph_update	*new_tcph_update;
	struct profile_tcp_rnd2 *rnd2;
	u32 msn,seq_scaled;

	bool build_full;
	int encode_len = 0;
	int retval = 0;
	comp_skb = context->comp_skb;
	rohc_comp = context->compresser;
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	new_tcph_update = &c_tcp_context->tcp_context.tcph_update_by_packet;
	comp_hdr = skb_tail_pointer(comp_skb);
	iph = &pkt_info->iph;
	tcph = &pkt_info->tcph;
	msn = context->co_fields.msn;
	seq_scaled = new_tcph_update->seq_scaled;
	if(rohc_comp->cid_type == CID_TYPE_SMALL){
		rnd2 = (struct profile_tcp_rnd2 *)comp_hdr;
		build_full = true;
	}else{
		if(bulid_first){
			rnd2 = (struct profile_tcp_rnd2 *)comp_hdr;

		}else{
			rnd2 = (struct profile_tcp_rnd2 *)(comp_hdr - 1);
		}
		build_full = false;
	}
	if(bulid_first){
		rnd2->disc = ROHC_PACKET_RND2 >> 4;
		rnd2->seq_scaled = seq_scaled & 0xf;
		encode_len = 1;
	}
	if(bulid_first && !build_full)
		goto out;
	rnd2->msn = msn & 0xf;
	rnd2->push = tcph->psh;
	rnd2->crc = 0;
	encode_len += sizeof(struct profile_tcp_rnd2) - 1;
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_SEQ);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}
int comp_tcp_build_rnd3(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct tcphdr *tcph;
	struct comp_tcp_context *c_tcp_context;
	struct profile_tcp_rnd3 *rnd3;
	enum rohc_cid_type cid_type;
	u32 msn,ack_seq;
	bool build_full;
	int encode_len = 0;
	int retval = 0;
	cid_type = context->compresser->cid_type;
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	comp_skb = context->comp_skb;
	tcph = &pkt_info->tcph;
	comp_hdr = skb_tail_pointer(comp_skb);
	msn = context->co_fields.msn;
	ack_seq = ntohl(tcph->ack_seq);
	if(cid_type == CID_TYPE_SMALL){
		rnd3 = (struct profile_tcp_rnd3 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			rnd3 = (struct profile_tcp_rnd3 *)comp_hdr;
		else
			rnd3 = (struct profile_tcp_rnd3 *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		rnd3->disc = ROHC_PACKET_RND3 >> 7;
		rnd3->ack_seq0 = (ack_seq >> 8) & 0x7f;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	rnd3->ack_seq1 = ack_seq & 0xff;
	rnd3->msn = msn & 0xf;
	rnd3->push = tcph->psh;
	rnd3->crc = 0;
	encode_len += sizeof(struct profile_tcp_rnd3) - 1;
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ_RESIDUE);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return 0;
}

int comp_tcp_build_rnd4(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct tcphdr *tcph;
	struct comp_tcp_context *c_tcp_context;
	struct tcph_update *new_tcph_update;
	struct profile_tcp_rnd4 *rnd4;
	enum rohc_cid_type cid_type;
	u32 msn,ack_seq_scaled;
	bool build_full;
	int encode_len = 0;
	int retval = 0;
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	new_tcph_update = &c_tcp_context->tcp_context.tcph_update_by_packet;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	tcph = &pkt_info->tcph;
	cid_type = context->compresser->cid_type;
	msn = context->co_fields.msn;
	if(cid_type == CID_TYPE_SMALL){
		rnd4 = (struct profile_tcp_rnd4 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			rnd4 = (struct profile_tcp_rnd4 *)comp_hdr;
		else
			rnd4 = (struct profile_tcp_rnd4 *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		rnd4->disc = ROHC_PACKET_RND4 >> 4;
		rnd4->ack_seq_scaled = new_tcph_update->ack_seq_scaled & 0xf;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	rnd4->msn = msn & 0xf;
	rnd4->push = tcph->psh;
	rnd4->crc = 0;
	encode_len += sizeof(struct profile_tcp_rnd4) - 1;
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int comp_tcp_build_rnd5(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct tcphdr *tcph;
	struct comp_tcp_context *c_tcp_context;
	struct profile_tcp_rnd5 *rnd5;
	enum rohc_cid_type cid_type;
	bool build_full;
	u32 msn,ack_seq,seq;
	int encode_len = 0;
	int retval = 0;

	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	comp_skb = context->comp_skb;
	tcph = &pkt_info->tcph;
	comp_hdr = skb_tail_pointer(comp_skb);
	cid_type = context->compresser->cid_type;
	msn = context->co_fields.msn;
	seq = ntohl(tcph->seq);
	ack_seq = ntohl(tcph->ack_seq);
	if(cid_type == CID_TYPE_SMALL){
		rnd5 = (struct profile_tcp_rnd5 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			rnd5 = (struct profile_tcp_rnd5 *)comp_hdr;
		else
			rnd5 = (struct profile_tcp_rnd5 *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		rnd5->disc = ROHC_PACKET_RND5 >> 5;
		rnd5->push = tcph->psh;
		rnd5->msn = msn & 0xf;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	rnd5->seq0 = (seq >> 9) & 0x1f;
	rnd5->crc = 0;
	rnd5->seq1 = (seq >> 1) & 0xff;
	rnd5->seq2 = seq & 0x1;
	rnd5->ack_seq0 = (ack_seq >> 8) & 0x7f;
	rnd5->ack_seq1 = ack_seq & 0xff;
	encode_len += sizeof(struct profile_tcp_rnd5) - 1;
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ_RESIDUE);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_SEQ);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_SEQ_SCALED);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}
int comp_tcp_build_rnd6(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct tcphdr *tcph;
	struct comp_tcp_context *c_tcp_context;
	struct tcph_update *new_tcph_update;
	struct profile_tcp_rnd6 *rnd6;
	enum rohc_cid_type cid_type;
	u32 msn;
	u16 ack_seq_low;
	bool build_full;
	int encode_len = 0;
	int retval = 0;
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	new_tcph_update = &c_tcp_context->tcp_context.tcph_update_by_packet;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	tcph = &pkt_info->tcph;
	msn = context->co_fields.msn;
	cid_type = context->compresser->cid_type;
	
	if(cid_type == CID_TYPE_SMALL){
		rnd6 = (struct profile_tcp_rnd6 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			rnd6 = (struct profile_tcp_rnd6 *)comp_hdr;
		else
			rnd6 = (struct profile_tcp_rnd6 *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		rnd6->disc = ROHC_PACKET_RND6 >> 4;
		rnd6->crc = 0;
		rnd6->push = tcph->psh;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	ack_seq_low = ntohl(tcph->ack_seq) & 0xffff;
	/*bigendian net byte order */
	rnd6->ack_seq = htons(ack_seq_low);
	rnd6->msn = msn & 0xf;
	rnd6->seq_scaled = new_tcph_update->seq_scaled & 0xf;

	encode_len += sizeof(struct profile_tcp_rnd6) - 1;
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ_RESIDUE);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_SEQ);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int comp_tcp_build_rnd7(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct tcphdr *tcph;
	struct comp_tcp_context *c_tcp_context;
	struct profile_tcp_rnd7 *rnd7;
	enum rohc_cid_type cid_type;
	bool build_full;
	u32 msn,ack_seq;
	int encode_len = 0;
	int retval = 0;
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	comp_skb = context->comp_skb;
	msn = context->co_fields.msn;
	cid_type = context->compresser->cid_type;
	comp_hdr = skb_tail_pointer(comp_skb);
	tcph = &pkt_info->tcph;
	ack_seq = ntohl(tcph->ack_seq);
	if(cid_type == CID_TYPE_SMALL){
		rnd7 = (struct profile_tcp_rnd7 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			rnd7 = (struct profile_tcp_rnd7 *)comp_hdr;
		else
			rnd7 = (struct profile_tcp_rnd7 *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		rnd7->disc = ROHC_PACKET_RND7 >> 2;
		rnd7->ack_seq0 = (ack_seq >> 16) & 0x3;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	rnd7->ack_seq1 = (ack_seq >> 8) & 0xff;
	rnd7->ack_seq2 = ack_seq & 0xff;
	/*original network byte order,no need to change
	 */
	rnd7->window = tcph->window;
	rnd7->crc = 0;
	rnd7->push = tcph->psh;
	rnd7->msn = msn & 0xf;
	encode_len += sizeof(struct profile_tcp_rnd7) - 1;
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ_RESIDUE);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_WIN);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
	
}

int comp_tcp_build_rnd8(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info ,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct tcphdr *tcph;
	struct comp_tcp_context *c_tcp_context;
	struct profile_tcp_rnd8 *rnd8;
	struct tcph_option_context *opt_context;
	enum rohc_cid_type cid_type;
	bool build_full;
	u32 msn;
	u16 seq_low,ack_seq_low;
	u8 ttl,new_rsf;
	int encode_len = 0;
	int retval = 0;
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	opt_context = &c_tcp_context->tcp_opt_context;
	tcph = &pkt_info->tcph;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	cid_type = context->compresser->cid_type;
	new_rsf = (tcph->rst << 2 ) | (tcph->syn << 1) | tcph->fin;
	if(cid_type == CID_TYPE_SMALL){
		rnd8 = (struct profile_tcp_rnd8 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			rnd8 = (struct profile_tcp_rnd8 *)comp_hdr;
		else
			rnd8 = (struct profile_tcp_rnd8 *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		rnd8->disc = ROHC_PACKET_RND8 >> 3;
		rnd8->rsf = tcp_rsf_encode(new_rsf);
		rnd8->list_ind = tcp_ip_field_static_or_irreg_indicator(opt_context->opts_update_by_packet.list_structure_update | opt_context->opts_update_by_packet.content_update_not_defined_in_irr);
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	rnd8->crc = 0;
	rnd8->msn0 = (msn >> 3) & 0x1;
	rnd8->ecn_used = c_tcp_context->ecn_used;
	rnd8->push = tcph->psh;
	rnd8->msn1 = msn & 0x7;
	c_tcp_context->ecn_used_trans_time++;
	if(pkt_info->has_inner_iph){
		if(rohc_iph_is_v4(pkt_info->inner_iph.version)){
			ttl = pkt_info->inner_iph.ttl;
			increase_iph_dynamic_field_trans_times(&c_tcp_context->ip_context.inner_update_trans_times,IP_FIELD_TTL_HL);
		}else{
			//ipv6
		}
	}else{
		if(rohc_iph_is_v4(pkt_info->iph.version)){
			ttl = pkt_info->iph.ttl;
			increase_iph_dynamic_field_trans_times(&c_tcp_context->ip_context.update_trans_times,IP_FIELD_TTL_HL);
		}else{
			//IPV6
		}
	}
	rnd8->ttl_hl = ttl & 0x7;
	seq_low = ntohl(tcph->seq) & 0xffff;
	ack_seq_low = ntohl(tcph->ack_seq) & 0xffff;
	rnd8->seq  = htons(seq_low);
	rnd8->ack_seq = htons(ack_seq_low);
	encode_len += sizeof(struct profile_tcp_rnd8) - 1;
	/*next dynamic tcp list option
	 * */
	if(rnd8->list_ind){
		skb_put(comp_skb,encode_len);
		pkt_info->comp_hdr_len += encode_len;
		encode_len = 0;
		retval = tcp_options_build_clist(opt_context,comp_skb,pkt_info);
	}
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ_RESIDUE);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_SEQ);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_SEQ_SCALED);

out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}
int comp_tcp_build_seq1(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct tcphdr *tcph;
	struct sk_buff *comp_skb;
	struct tcp_iph_context *ip_context;
	struct comp_tcp_context *c_tcp_context;
	struct profile_tcp_seq1 *seq1;
	enum rohc_cid_type cid_type;
	bool build_full;
	u32 msn;
	u16 ipid_off,seq_low;
	int encode_len = 0;
	int retval = 0;
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	ip_context = &c_tcp_context->ip_context;
	comp_skb = context->comp_skb;
	tcph = &pkt_info->tcph;
	comp_hdr = skb_tail_pointer(comp_skb);
	cid_type = context->compresser->cid_type;
	msn = context->co_fields.msn;
	ip_pick_non_rand_zero_ipid_off(ip_context,pkt_info,&ipid_off);
	if(cid_type == CID_TYPE_SMALL){
		seq1 = (struct profile_tcp_seq1 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			seq1 = (struct profile_tcp_seq1 *)comp_hdr;
		else
			seq1 = (struct profile_tcp_seq1 *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		seq1->disc = ROHC_PACKET_SEQ1 >> 4;
		seq1->ipid_off = ipid_off & 0xf;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	seq_low = ntohl(tcph->seq) & 0xffff;
	seq1->seq = htons(seq_low);
	seq1->msn = msn & 0xf;
	seq1->push = tcph->psh;
	seq1->crc = 0;
	encode_len += sizeof(struct profile_tcp_seq1) - 1;
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_SEQ);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_SEQ_SCALED);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int comp_tcp_build_seq2(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct tcphdr *tcph;
	struct sk_buff *comp_skb;
	struct comp_tcp_context *c_tcp_context;
	struct tcp_iph_context *ip_context;
	struct tcph_context	*tcp_context;
	struct tcph_update	*new_tcph_update;
	struct profile_tcp_seq2 *seq2;
	enum rohc_cid_type cid_type;
	u32 msn;
	u16 ipid_off;
	bool build_full;
	int encode_len = 0;
	int retval = 0;
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	ip_context = &c_tcp_context->ip_context;
	new_tcph_update = &c_tcp_context->tcp_context.tcph_update_by_packet;
	comp_skb = context->comp_skb;
	tcph = &pkt_info->tcph;
	comp_hdr = skb_tail_pointer(comp_skb);
	cid_type = context->compresser->cid_type;
	msn = context->co_fields.msn;
	ip_pick_non_rand_zero_ipid_off(ip_context,pkt_info,&ipid_off);
	if(cid_type == CID_TYPE_SMALL){
		seq2 = (struct profile_tcp_seq2 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			seq2 = (struct profile_tcp_seq2 *)comp_hdr;
		else
			seq2 = (struct profile_tcp_seq2 *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		seq2->disc = ROHC_PACKET_SEQ2 >> 3;
		seq2->ipid_off0 = (ipid_off >> 4) & 0x7;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	seq2->seq_scaled = new_tcph_update->seq_scaled & 0xf;
	seq2->ipid_off1 = ipid_off & 0xf;
	seq2->msn = msn & 0xf;
	seq2->push = tcph->psh;
	seq2->crc = 0;
	encode_len += sizeof(struct profile_tcp_seq2) - 1;
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_SEQ);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;

}

int comp_tcp_build_seq3(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct tcphdr *tcph;
	struct sk_buff *comp_skb;
	struct comp_tcp_context *c_tcp_context;
	struct tcp_iph_context *ip_context;
	struct profile_tcp_seq3 *seq3;
	enum rohc_cid_type cid_type;
	bool build_full;
	u16 ack_seq_low,ipid_off;
	u32 msn;
	int encode_len = 0;
	int retval = 0;

	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	ip_context = &c_tcp_context->ip_context;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);

	tcph = &pkt_info->tcph;
	cid_type = context->compresser->cid_type;
	msn = context->co_fields.msn;
	ip_pick_non_rand_zero_ipid_off(ip_context,pkt_info,&ipid_off);

	if(cid_type == CID_TYPE_SMALL){
		seq3 = (struct profile_tcp_seq3 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			seq3 = (struct profile_tcp_seq3 *)comp_hdr;
		else
			seq3 = (struct profile_tcp_seq3 *)(comp_hdr - 1);
		build_full = false;
	}

	if(build_first){
		seq3->disc = ROHC_PACKET_SEQ3 >> 4;
		seq3->ipid_off = ipid_off & 0xf;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;

	ack_seq_low = ntohl(tcph->ack_seq) & 0xffff;
	seq3->ack_seq = htons(ack_seq_low);

	seq3->msn = msn & 0xf;
	seq3->push = tcph->psh;
	seq3->crc = 0;

	encode_len += sizeof(struct profile_tcp_seq3) - 1;
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ_RESIDUE);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}


int comp_tcp_build_seq4(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct tcphdr *tcph;
	struct tcp_iph_context *ip_context;
	struct comp_tcp_context *c_tcp_context;
	struct tcph_update *new_tcph_update;
	struct profile_tcp_seq4 *seq4;

	enum rohc_cid_type cid_type;
	bool build_full;
	u32 msn;
	u16 ipid_off;
	int encode_len = 0;
	int retval = 0;
	
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	ip_context = &c_tcp_context->ip_context;
	new_tcph_update = &c_tcp_context->tcp_context.tcph_update_by_packet;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	tcph = &pkt_info->tcph;

	cid_type = context->compresser->cid_type;
	msn = context->co_fields.msn;
	ip_pick_non_rand_zero_ipid_off(ip_context,pkt_info,&ipid_off);

	if(cid_type == CID_TYPE_SMALL){
		seq4 = (struct profile_tcp_seq4 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			seq4 = (struct profile_tcp_seq4 *)comp_hdr;
		else
			seq4 = (struct profile_tcp_seq4 *)(comp_hdr - 1);
		build_full = false;
	}

	if(build_first){
		seq4->disc = ROHC_PACKET_SEQ4 >> 7;
		seq4->ack_seq_scaled = new_tcph_update->ack_seq_scaled & 0xf;
		seq4->ipid_off = ipid_off & 0x7;
		encode_len = 1;
	}

	if(!build_full && build_first)
		goto out;

	seq4->msn = msn & 0xf;
	seq4->push = tcph->psh;
	seq4->crc = 0;

	encode_len += sizeof(struct profile_tcp_seq4) - 1;
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int comp_tcp_build_seq5(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct tcphdr *tcph;
	struct sk_buff *comp_skb;
	struct comp_tcp_context *c_tcp_context;
	struct tcp_iph_context *ip_context;
	struct profile_tcp_seq5 *seq5;

	enum rohc_cid_type cid_type;
	bool build_full;
	u32 msn;
	u16 ack_seq_low,seq_low;
	u16 ipid_off;
	int encode_len = 0;
	int retval = 0;
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	ip_context = &c_tcp_context->ip_context;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	tcph = &pkt_info->tcph;

	cid_type = context->compresser->cid_type;
	msn = context->co_fields.msn;
	ip_pick_non_rand_zero_ipid_off(ip_context,pkt_info,&ipid_off);

	if(cid_type == CID_TYPE_SMALL){
		seq5 = (struct profile_tcp_seq5 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			seq5 = (struct profile_tcp_seq5 *)comp_hdr;
		else
			seq5 = (struct profile_tcp_seq5 *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		seq5->disc = ROHC_PACKET_SEQ5 >> 4;
		seq5->ipid_off = ipid_off & 0xf;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;

	seq_low = ntohl(tcph->seq) & 0xffff;
	ack_seq_low = ntohl(tcph->ack_seq) & 0xffff;

	seq5->seq = htons(seq_low);
	seq5->ack_seq = htons(ack_seq_low);

	seq5->msn = msn & 0xf;
	seq5->push = tcph->psh;
	seq5->crc = 0;

	encode_len += sizeof(struct profile_tcp_seq5) - 1;
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ_RESIDUE);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_SEQ);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_SEQ_SCALED);

out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}


int comp_tcp_build_seq6(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct tcphdr *tcph;
	struct sk_buff *comp_skb;
	struct comp_tcp_context *c_tcp_context;
	struct tcp_iph_context *ip_context;
	struct tcph_update *new_tcph_update;
	struct profile_tcp_seq6 *seq6;

	enum rohc_cid_type cid_type;
	u16 ipid_off,ack_seq_low;
	u32 msn;
	bool build_full;

	int encode_len = 0;
	int retval = 0;

	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	ip_context = &c_tcp_context->ip_context;
	new_tcph_update = &c_tcp_context->tcp_context.tcph_update_by_packet;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	tcph = &pkt_info->tcph;

	msn = context->co_fields.msn;
	cid_type = context->compresser->cid_type;

	if(cid_type == CID_TYPE_SMALL){
		seq6 = (struct profile_tcp_seq6 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			seq6 = (struct profile_tcp_seq6 *)comp_hdr;
		else
			seq6 = (struct profile_tcp_seq6 *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		seq6->disc = ROHC_PACKET_SEQ6 >> 3;
		seq6->seq_scaled0 = (new_tcph_update->seq_scaled >> 1) & 0x7;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;

	ip_pick_non_rand_zero_ipid_off(ip_context,pkt_info,&ipid_off);
	seq6->ipid_off = ipid_off & 0x7f;
	seq6->seq_scaled1 = new_tcph_update->seq_scaled & 0x1;

	ack_seq_low = ntohl(tcph->ack_seq) & 0xffff;
	seq6->ack_seq = htons(ack_seq_low);

	seq6->msn = msn & 0xf;
	seq6->push = tcph->psh;
	seq6->crc = 0;
	encode_len += sizeof(struct profile_tcp_seq6) - 1;
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ_RESIDUE);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_SEQ);

out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}


int comp_tcp_build_seq7(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct tcphdr *tcph;
	struct sk_buff *comp_skb;
	struct comp_tcp_context *c_tcp_context;
	struct tcp_iph_context *ip_context;
	struct profile_tcp_seq7 *seq7;
	
	enum rohc_cid_type cid_type;
	bool build_full;
	u16 ipid_off,window,ack_seq_low;
	u32 msn;
	int encode_len = 0;
	int retval = 0;
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	ip_context = &c_tcp_context->ip_context;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	tcph = &pkt_info->tcph;

	msn = context->co_fields.msn;
	cid_type = context->compresser->cid_type;
	window = ntohs(tcph->window);

	if(cid_type == CID_TYPE_SMALL){
		seq7 = (struct profile_tcp_seq7 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			seq7 = (struct profile_tcp_seq7 *)comp_hdr;
		else
			seq7 = (struct profile_tcp_seq7 *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		seq7->disc = ROHC_PACKET_SEQ7 >> 4;
		seq7->win0 = window >> 11;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	ip_pick_non_rand_zero_ipid_off(ip_context,pkt_info,&ipid_off);
	seq7->win1 = (window >> 3) & 0xff;

	seq7->ipid_off = ipid_off & 0x1f;
	seq7->win2 = window & 0x7;

	ack_seq_low = ntohl(tcph->ack_seq) & 0xffff;
	seq7->ack_seq = htons(ack_seq_low);

	seq7->msn = msn & 0xf;
	seq7->push = tcph->psh;
	seq7->crc = 0;

	encode_len += sizeof(struct profile_tcp_seq7) - 1;
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ_RESIDUE);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_WIN);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int comp_tcp_build_seq8(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first)
{
	u8 *comp_hdr;
	struct iphdr *outer_iph,*inner_iph;
	struct tcphdr *tcph;
	struct sk_buff *comp_skb;
	struct comp_tcp_context *c_tcp_context;
	struct tcp_iph_context *ip_context;
	struct tcph_option_context *opt_context;
	struct profile_tcp_seq8 *seq8;
	enum rohc_cid_type cid_type;

	u32 ack_seq;
	u32 seq;
	u32 msn;
	u16 ipid_off;
	bool build_full;
	int encode_len = 0;
	int retval = 0;

	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	ip_context = &c_tcp_context->ip_context;
	opt_context = &c_tcp_context->tcp_opt_context;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	tcph = &pkt_info->tcph;

	cid_type = context->compresser->cid_type;
	ip_pick_non_rand_zero_ipid_off(ip_context,pkt_info,&ipid_off);

	if(cid_type == CID_TYPE_SMALL){
		seq8 = (struct profile_tcp_seq8 *)comp_hdr;
		build_full = true;
	}else{
		if(build_first)
			seq8 = (struct profile_tcp_seq8 *)comp_hdr;
		else
			seq8 = (struct profile_tcp_seq8 *)(comp_hdr - 1);
		build_full = false;
	}
	if(build_first){
		seq8->disc = ROHC_PACKET_SEQ8 >> 4;
		seq8->ipid_off = ipid_off & 0xf;
		encode_len = 1;
	}
	if(!build_full && build_first)
		goto out;
	seq8->list_ind = tcp_ip_field_static_or_irreg_indicator(opt_context->opts_update_by_packet.list_structure_update | opt_context->opts_update_by_packet.content_update_not_defined_in_irr);
	seq8->crc = 0;

	msn = context->co_fields.msn;
	seq8->msn = msn & 0xf;
	seq8->push = tcph->psh;

	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		if(rohc_iph_is_v4(inner_iph->version)){
			seq8->ttl_hl = inner_iph->ttl & 0x7;
			increase_iph_dynamic_field_trans_times(&ip_context->inner_update_trans_times,IP_FIELD_TTL_HL);
		}else{
			// ipv6
		}
	}else{
		outer_iph = &pkt_info->iph;
		if(rohc_iph_is_v4(outer_iph->version)){
			seq8->ttl_hl = outer_iph->ttl & 0x7;
			increase_iph_dynamic_field_trans_times(&ip_context->update_trans_times,IP_FIELD_TTL_HL);
		}else
			;//ipv6
	}
	seq8->ecn_used = c_tcp_context->ecn_used;
	c_tcp_context->ecn_used_trans_time++;
	ack_seq = ntohl(tcph->ack_seq);
	seq = ntohl(tcph->seq);
	seq8->ack_seq0 = (ack_seq >> 8) & 0x7f;
	seq8->ack_seq1 = ack_seq & 0xff;
	seq8->seq0 = (seq >> 8) & 0x3f;
	seq8->rsf = tcp_rsf_encode((tcph->rst << 2) | (tcph->syn << 1) | tcph->fin);
	seq8->seq1 = seq & 0xff;
	/*next build tcp option list
	 */
	if(seq8->list_ind){
		skb_put(comp_skb,encode_len);
		pkt_info->comp_hdr_len += encode_len;
		retval = tcp_options_build_clist(opt_context,comp_skb,pkt_info);
		encode_len = 0;
	}
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_ACK_SEQ_RESIDUE);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_SEQ);
	increase_tcph_dynamic_field_trans_times(&c_tcp_context->tcp_context.update_trans_times,TCP_FIELD_SEQ_SCALED);
out:
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}



static inline int ip_build_static_field(u8 *to,struct iphdr *new_iph)
{
	struct ipv6hdr *ipv6h;
	struct profile_tcp_ipv4_static *v4_static;
	if(rohc_iph_is_v4(new_iph->version)){
		v4_static = (struct profile_tcp_ipv4_static *)to;
		v4_static->version = 0;
		v4_static->rsv = 0;
		v4_static->protocol = new_iph->protocol;
		/*source addr and dest addr should network oder byte,no need to change
		 */
		v4_static->saddr = new_iph->saddr;
		v4_static->daddr = new_iph->daddr;
		return sizeof(struct profile_tcp_ipv4_static);
	}else{
		ipv6h = (struct ipv6hdr *)new_iph;
		/*ipv6 todo build*/
	}
}


int comp_tcp_build_ip_static_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct iphdr *iph;
	struct sk_buff *comp_skb;
	int call_len;
	int encode_len = 0;
	int retval = 0;
	comp_skb = context->comp_skb;
	iph = &pkt_info->iph;
	comp_hdr = skb_tail_pointer(comp_skb);
	call_len = ip_build_static_field(comp_hdr,iph);
	comp_hdr += call_len;
	encode_len += call_len;
	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		call_len = ip_build_static_field(comp_hdr,iph);
		encode_len += encode_len;
	}
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

static inline int ip_build_dynamic_field(u8 *to,struct iphdr *iph,enum ip_id_behavior ipid_bh)
{
	int encode_len = 0;
	struct ipv6h *ipv6h;
	struct profile_tcp_ipv4_dynamic *v4_dynamic;
	if(rohc_iph_is_v4(iph->version)){
		v4_dynamic = (struct profile_tcp_ipv4_dynamic *)to;
		v4_dynamic->rsv = 0;
		v4_dynamic->df = !!(ntohs(iph->frag_off) & IP_DF);
		v4_dynamic->ipid_bh = ipid_bh & 0x3;
		v4_dynamic->ecn_flags = iph->tos & 0x3;
		v4_dynamic->dscp = iph->tos >> 2;
		v4_dynamic->ttl_hl = iph->ttl;
		encode_len = sizeof(struct profile_tcp_ipv4_dynamic);
		/*the next filed ipid that is dynamic exisence */
		if(!ip_id_is_zero(ipid_bh)){
			to += sizeof(struct profile_tcp_ipv4_dynamic);
			memcpy(to,&iph->id,2);
			encode_len += 2;
		}
		return encode_len;
	}else{
		//IPV6
	}
}
int comp_tcp_build_ip_dynamic_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct iphdr *iph;
	struct sk_buff *comp_skb;
	struct comp_tcp_context *c_tcp_context;
	struct iph_update *new_iph_update;
	int call_len;
	int encode_len = 0;
	int retval = 0;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	new_iph_update = &c_tcp_context->ip_context.update_by_packet;
	iph = &pkt_info->iph;
	call_len = ip_build_dynamic_field(comp_hdr,iph,new_iph_update->new_ipid_bh);
	comp_hdr += call_len;
	encode_len += call_len;
	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		new_iph_update = &c_tcp_context->ip_context.inner_update_by_packet;
		call_len = ip_build_dynamic_field(comp_hdr,iph,new_iph_update->new_ipid_bh);
		encode_len += call_len;
	}

	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}


int comp_tcp_build_tcp_static_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct tcphdr *tcph;
	struct profile_tcp_static *tcp_static;

	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	tcph = &pkt_info->tcph;
	tcp_static = (struct profile_tcp_static *)comp_hdr;
	/*original network byte order,no need to change
	 */
	tcp_static->sport = tcph->source;
	tcp_static->dport = tcph->dest;
	skb_put(comp_skb,sizeof(struct profile_tcp_static));
	pkt_info->comp_hdr_len += sizeof(struct profile_tcp_static);
	return 0;
}


int comp_tcp_build_tcp_dynamic_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct tcphdr *tcph;
	struct comp_tcp_context *c_tcp_context;
	struct tcph_context *tcp_context;
	struct tcph_update *new_update;
	struct profile_tcp_dynamic *tcp_dynamic;
	u32 msn;
	int call_len;
	int encode_len = 0;
	int retval = 0;

	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	tcp_context = &c_tcp_context->tcp_context;
	new_update = &tcp_context->tcph_update_by_packet;
	tcph = &pkt_info->tcph;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);

	msn = context->co_fields.msn;
	tcp_dynamic = (struct profile_tcp_dynamic *)comp_hdr;
	tcp_dynamic->res = tcph->res1;
	tcp_dynamic->urg_zero = !!(tcph->urg == 0);
	tcp_dynamic->ack_zero = !!(tcph->ack_seq == 0);
	tcp_dynamic->ack_stride_ind = tcp_ip_field_static_or_irreg_indicator(new_update->ack_stride_update && new_update->ack_stride_use);
	tcp_dynamic->ecn_used = c_tcp_context->ecn_used;

	tcp_dynamic->rsf = (tcph->rst << 2) | (tcph->syn << 1) | tcph->fin;
	tcp_dynamic->push = tcph->psh;
	tcp_dynamic->ack = tcph->ack;
	tcp_dynamic->urg = tcph->urg;
	tcp_dynamic->ecn = (tcph->cwr << 1) | tcph->ece;
	tcp_dynamic->msn = htons(msn);
	rohc_pr(ROHC_DTCP,"build msn=%d\n",ntohs(tcp_dynamic->msn));
	tcp_dynamic->seq = tcph->seq;
	tcp_dynamic->window = tcph->window;
	tcp_dynamic->check = tcph->check;
	encode_len += sizeof(struct profile_tcp_dynamic);
	comp_hdr += encode_len;
	/*next filed is dynamic exist*/
	/*filed 1,is ack seq*/
	call_len = tcp_ip_field_static_or_irreg32(comp_hdr,ntohl(tcph->ack_seq),!tcp_dynamic->ack_zero);
	comp_hdr += call_len;
	encode_len += call_len;
	/*field .2 urg ptr*/
	call_len = tcp_ip_field_static_or_irreg16(comp_hdr,ntohs(tcph->urg_ptr),!tcp_dynamic->urg_zero);
	encode_len += call_len;
	comp_hdr += encode_len;
	/*field.3 is ack stride*/
	call_len = tcp_ip_field_static_or_irreg16(comp_hdr,new_update->ack_stride_use ,tcp_dynamic->ack_stride_ind);
	rohc_pr(ROHC_DTCP,"ack_stride_ind:%d,call_len:%d,ack_stride_use=%d\n",tcp_dynamic->ack_stride_ind,call_len,new_update->ack_stride_use);
	encode_len += call_len;
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	rohc_pr(ROHC_DTCP,"tcp cid-%d  comp tot len is %d excepet clist\n",context->cid,pkt_info->comp_hdr_len);
	/*field 4 is tcp options list*/
	retval = tcp_options_build_clist(&c_tcp_context->tcp_opt_context,comp_skb,pkt_info);
	return retval;
}

int comp_tcp_build_ip_irr_chain(struct tcp_iph_context *ip_context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info,bool ecn_used)
{
	u8 *comp_hdr;
	struct iphdr *iph;
	struct ipv6hdr *ipv6h;
	struct iph_update *new_update;
	u16 ipid_off;
	int encode_len = 0;
	int retval = 0;

	new_update = &ip_context->update_by_packet;
	iph = &pkt_info->iph;
	comp_hdr = skb_tail_pointer(comp_skb);
	/*fill outer ip header irr,if is ipv4*/
	if(rohc_iph_is_v4(iph->version) && ip_id_is_random(new_update->new_ipid_bh)){
		/*keep network byte order*/
		memcpy(comp_hdr,&iph->id,2);
		encode_len += 2;
		comp_hdr += 2;
	}
	/*fill ouer ip header dscp and ecn if two ip header*/
	if(ecn_used && pkt_info->has_inner_iph){
		if(rohc_iph_is_v4(iph->version)){
			*comp_hdr = iph->tos;
			comp_hdr++;
			encode_len++;
			increase_iph_dynamic_field_trans_times(&ip_context->update_trans_times,IP_FIELD_DSCP);
		}else{
			//ipv6
		}
	}
	/*fill outer header ttl_hopl,if has two ip header*/
	if(pkt_info->has_inner_iph && new_update->ttl_hl_update){
		if(rohc_iph_is_v4(iph->version)){
			*comp_hdr = iph->ttl;
			comp_hdr++;
			encode_len++;
			increase_iph_dynamic_field_trans_times(&ip_context->update_trans_times,IP_FIELD_TTL_HL);
		}else{
			//ipv6
		}
	}
	/*fill inner ip header irr*/
	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		new_update = &ip_context->inner_update_by_packet;
		if(rohc_iph_is_v4(iph->version) && ip_id_is_random(new_update->new_ipid_bh)){
			/*keep network byte order*/
			memcpy(comp_hdr,&iph->id,2);
			encode_len += 2;
			comp_hdr += 2;
		}
	}
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return 0;
}

int comp_tcp_build_tcp_irr_chain(struct tcph_context *tcp_context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info,bool ecn_used)
{
	u8 *comp_hdr;
	struct tcphdr *tcph;
	struct iphdr *iph;
	int encode_len = 0;
	comp_hdr = skb_tail_pointer(comp_skb);
	tcph = &pkt_info->tcph;


	if(ecn_used){
		if(pkt_info->has_inner_iph)
			iph = &pkt_info->inner_iph;
		else
			iph = &pkt_info->iph;
		*comp_hdr = ((iph->tos & 0x3) << 6) | (tcph->res1 << 2) | (tcph->cwr << 1) | tcph->ece;
		comp_hdr++;
		encode_len++;
	}


	/*fill tcp heaer checksum,because the original is network byte order,so no need to change*/
	memcpy(comp_hdr,&tcph->check,2);
	encode_len += 2;
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;

	return 0;
}

int comp_tcp_build_irr_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct tcp_iph_context *ip_context;
	struct tcph_context *tcp_context;
	struct tcph_option_context *opt_context;
	struct comp_tcp_context *c_tcp_context;
	struct sk_buff *comp_skb;
	int retval;

	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	ip_context = &c_tcp_context->ip_context;
	tcp_context = &c_tcp_context->tcp_context;
	opt_context = &c_tcp_context->tcp_opt_context;
	comp_skb = context->comp_skb;

	/*first ,build ip irregular chain*/
	comp_tcp_build_ip_irr_chain(ip_context,comp_skb,pkt_info,c_tcp_context->ecn_used);
	rohc_pr(ROHC_DTCP,"%s[%d] : comp_hdr_len=%d\n",__func__,__LINE__,pkt_info->comp_hdr_len);
	/*second,build tcp irregular chain*/

	comp_tcp_build_tcp_irr_chain(tcp_context,comp_skb,pkt_info,c_tcp_context->ecn_used);
	rohc_pr(ROHC_DTCP,"%s[%d] : comp_hdr_len=%d\n",__func__,__LINE__,pkt_info->comp_hdr_len);
	/*third ,build tcp options irregular chain*/
	retval = tcp_options_build_irr_chain(opt_context,comp_skb,pkt_info);
	rohc_pr(ROHC_DTCP,"%s[%d] : comp_hdr_len=%d\n",__func__,__LINE__,pkt_info->comp_hdr_len);
	return retval;
}

int comp_tcp_build_co_header(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
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
	rohc_pr(ROHC_DTCP,"cid-%d,len=%d,comp_eth_hdr=%d\n",context->cid,context->comp_skb->len,context->comp_eth_hdr);
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
			build_co_func = comp_tcp_build_common;
			break;
		case ROHC_PACKET_TYPE_RND1:
			build_co_func = comp_tcp_build_rnd1;
			break;
		case ROHC_PACKET_TYPE_RND2:
			build_co_func = comp_tcp_build_rnd2;
			break;
		case ROHC_PACKET_TYPE_RND3:
			build_co_func = comp_tcp_build_rnd3;
			break;
		case ROHC_PACKET_TYPE_RND4:
			build_co_func = comp_tcp_build_rnd4;
			break;
		case ROHC_PACKET_TYPE_RND5:
			build_co_func = comp_tcp_build_rnd5;
			break;
		case ROHC_PACKET_TYPE_RND6:
			build_co_func = comp_tcp_build_rnd6;
			break;
		case ROHC_PACKET_TYPE_RND7:
			build_co_func = comp_tcp_build_rnd7;
			break;
		case ROHC_PACKET_TYPE_RND8:
			build_co_func = comp_tcp_build_rnd8;
			break;
		case ROHC_PACKET_TYPE_SEQ1:
			build_co_func = comp_tcp_build_seq1;
			break;
		case ROHC_PACKET_TYPE_SEQ2:
			build_co_func = comp_tcp_build_seq2;
			break;
		case ROHC_PACKET_TYPE_SEQ3:
			build_co_func = comp_tcp_build_seq3;
			break;
		case ROHC_PACKET_TYPE_SEQ4:
			build_co_func = comp_tcp_build_seq4;
			break;
		case ROHC_PACKET_TYPE_SEQ5:
			build_co_func = comp_tcp_build_seq5;
			break;
		case ROHC_PACKET_TYPE_SEQ6:
			build_co_func = comp_tcp_build_seq6;
			break;
		case ROHC_PACKET_TYPE_SEQ7:
			build_co_func = comp_tcp_build_seq7;
			break;
		case ROHC_PACKET_TYPE_SEQ8:
			build_co_func = comp_tcp_build_seq8;
			break;
		default:
			pr_err("%s : can't support packet : %d\n",__func__,packet_type);
			break;
	}
	u8 *cid_byte,*type_byte;
	if(cid_type == CID_TYPE_SMALL){
		retval = rohc_cid_encode(cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		cid_byte = comp_skb->data + sizeof(struct ethhdr);
	type_byte = comp_skb->data + sizeof(struct ethhdr) + cid_encode_len;
	rohc_pr(ROHC_DTCP,"1 cid=%x[%p],type_byte=%x[%p],context-%d,cid_encode_len=%d,comhdr=%x,%p\n",*cid_byte,cid_byte,*type_byte,type_byte,cid,cid_encode_len,*comp_hdr,comp_hdr);
		pkt_info->comp_hdr_len += cid_encode_len;
		skb_put(comp_skb,pkt_info->comp_hdr_len);
		build_co_func(context,skb,pkt_info,true);
	}else{
		skb_put(comp_skb,pkt_info->comp_hdr_len);
		retval = build_co_func(context,skb,pkt_info,true);
		if(retval)
			goto out;
		comp_hdr = skb_tail_pointer(comp_skb);
		retval = rohc_cid_encode(cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		skb_put(comp_skb,cid_encode_len);
		pkt_info->comp_hdr_len += cid_encode_len;
		retval = build_co_func(context,skb,pkt_info,false);
		if(retval)
			goto out;
	}

	cid_byte = comp_skb->data + sizeof(struct ethhdr);
	type_byte = comp_skb->data + sizeof(struct ethhdr) + cid_encode_len;
	rohc_pr(ROHC_DTCP,"cid=%d,type_byte=%x,context-%d,comp_hdr_len=%d\n",*cid_byte,*type_byte,cid,pkt_info->comp_hdr_len);
	/*next field is irregular chain(including irregular chain items for tcp options)
	 */
	retval = comp_tcp_build_irr_chain(context,skb,pkt_info);
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

int comp_tcp_build_static_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	int retval;
	/*The static chain consists of one item for each header of the chain
	*of protocol headers to be compressed, starting from the outermost
	*IP header and ending with a TCP header
	*/
	comp_tcp_build_ip_static_chain(context,skb,pkt_info);
	comp_tcp_build_tcp_static_chain(context,skb,pkt_info);
	return 0;
}

int comp_tcp_build_dynamic_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct comp_tcp_context *c_tcp_context;
	struct tcp_iph_context *ip_context;
	struct tcph_context *tcp_context;
	int retval;

	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	ip_context = &c_tcp_context->ip_context;
	tcp_context = &c_tcp_context->tcp_context;
	/*
	*The dynamic chain consists of one item for each header of the
	*chain of protocol headers to be compressed, starting from the
	*outermost IP header and ending with a UDP header
	*/
	retval = comp_tcp_build_ip_dynamic_chain(context,skb,pkt_info);
	if(retval){
		pr_err("profile tcp build ip dynamic failed,cid-%d\n",context->cid);
		goto out;
	}
	retval = comp_tcp_build_tcp_dynamic_chain(context,skb,pkt_info);
	if(retval){
		pr_err("profile tcp build tcp dynamic failed,cid-%d\n",context->cid);
		goto out;
	}

	/*increase transmit time*/
	increase_tcph_all_trans_times(&tcp_context->update_trans_times);
	increase_iph_all_trans_times(&ip_context->update_trans_times);
	if(pkt_info->has_inner_iph)
		increase_iph_all_trans_times(&ip_context->inner_update_trans_times);
	c_tcp_context->ecn_used_trans_time++;

out:
	return retval;
}


static inline bool is_can_trans_by_rnd6(struct tcph_update *tcph_new_update)
{
	if(!tcph_new_update->seq_scale_factor_or_residue_update && \
	   ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_scaled_encode_bits,ROHC_ENCODE_BY_BITS(4)) &&\
	   ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(16)) && \
	   ROHC_ENCODE_P_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_TCP_WLSB_K_R_2_TO_P))
		return true;
	else
		return false;
}

static inline bool is_can_trans_by_rnd5(struct tcph_update *tcph_new_update)
{
	if(ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(14)) && \
	   ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(15)))
		return true;
	else
		return false;
}

static inline bool ack_and_seq_is_can_trans_by_rnd8(struct tcph_update *tcph_new_update)
{
	if(ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(16)) && \
	   ROHC_ENCODE_P_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_TCP_WLSB_K_R_2_TO_P) && \
	   ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(16)) && \
	   ROHC_ENCODE_P_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_TCP_WLSB_K_R_0_TO_P))
		return true;
	else
		return false;
}

static inline bool is_can_trans_by_seq6(struct tcph_update *tcph_new_update,struct tcp_iph_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info,int bits)
{

	rohc_pr(ROHC_DTCP,"%s:ipid:%d\n",__func__,ip_seq_ip_id_encode_sets_test(ip_context,pkt_info,ROHC_ENCODE_BY_BITS(bits)));
	rohc_pr(ROHC_DTCP,"%s: seq_scacled_4:%d\n",__func__,ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_scaled_encode_bits,ROHC_ENCODE_BY_BITS(4)));
	rohc_pr(ROHC_DTCP,"%s : ack_16_14:%d\n",__func__,ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(16)) && ROHC_ENCODE_P_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_TCP_WLSB_K_R_2_TO_P));
	if(!tcph_new_update->seq_scale_factor_or_residue_update && \
	   ip_seq_ip_id_encode_sets_test(ip_context,pkt_info,ROHC_ENCODE_BY_BITS(bits)) &&\
	   ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_scaled_encode_bits,ROHC_ENCODE_BY_BITS(4)) &&\
	   ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(16)) &&\
	   ROHC_ENCODE_P_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_TCP_WLSB_K_R_2_TO_P))
		return true;
	else
		return false;
}

static inline bool is_can_trans_by_seq5(struct tcph_update *tcph_new_update,struct tcp_iph_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info,int bits)
{
	rohc_pr(ROHC_DTCP,"%s: ipid:%d\n",__func__,ip_seq_ip_id_encode_sets_test(ip_context,pkt_info,ROHC_ENCODE_BY_BITS(bits)));
	rohc_pr(ROHC_DTCP,"%s: ack_seq_16_14:%d\n",__func__,ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(16)) && ROHC_ENCODE_P_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_TCP_WLSB_K_R_2_TO_P));
	rohc_pr(ROHC_DTCP,"%s : seq_16_15:%d\n",__func__,ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(16)) &&  ROHC_ENCODE_P_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_TCP_WLSB_K_R_1_TO_P));
	if(ip_seq_ip_id_encode_sets_test(ip_context,pkt_info,ROHC_ENCODE_BY_BITS(bits)) && \
					ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(16)) && \
					ROHC_ENCODE_P_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_TCP_WLSB_K_R_2_TO_P) && \
					ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(16)) && \
					ROHC_ENCODE_P_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_TCP_WLSB_K_R_1_TO_P))
		return true;
	else
		return false;
}
static enum rohc_packet_type comp_tcp_adjust_packet_type_so(struct comp_tcp_context *c_tcp_context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct tcp_iph_context *ip_context;
	struct tcph_context *tcp_context;
	struct tcph_option_context *opt_context;
	struct iph_update *iph_new_update,*inner_iph_new_update;
	struct tcph_update *tcph_new_update;
	struct tcph_options_update *opt_new_update;
	enum rohc_packet_type packet_type;
	ip_context = &c_tcp_context->ip_context;
	tcp_context = &c_tcp_context->tcp_context;
	opt_context = &c_tcp_context->tcp_opt_context;
	iph_new_update = &ip_context->update_by_packet;
	inner_iph_new_update = &ip_context->inner_update_by_packet;
	tcph_new_update = &tcp_context->tcph_update_by_packet;
	opt_new_update = &opt_context->opts_update_by_packet;
	if(ip_has_outer_iph_dynamic_field_full_update(ip_context,pkt_info->has_inner_iph,IP_FIELD_DF) || \
	   ip_has_outer_iph_dynamic_field_full_update(ip_context,pkt_info->has_inner_iph,IP_FIELD_IPID_BH) || \
	   !ROHC_ENCODE_BITS_TEST(&tcp_context->tcph_update_by_packet.msn_encode_bits,ROHC_ENCODE_BY_BITS(4)) || \
	   (tcph_new_update->rsf_flags_update && !tcph_new_update->rsf_carray_one_or_zero_bit))
		packet_type = ROHC_PACKET_TYPE_IR_DYN;
	else if(tcph_new_update->ack_stride_update || tcph_new_update->urg_flag_update || \
		tcph_new_update->urg_ptr_update || tcph_new_update->ack_flag_update || \
		ip_has_inner_iph_dynamic_field_full_update(ip_context,pkt_info->has_inner_iph,IP_FIELD_DSCP) || \
		ip_has_inner_iph_dynamic_field_full_update(ip_context,pkt_info->has_inner_iph,IP_FIELD_TTL_HL) || \
		ip_has_inner_iph_dynamic_field_full_update(ip_context,pkt_info->has_inner_iph,IP_FIELD_DF) || \
		ip_has_outer_iph_dynamic_field_full_update(ip_context,pkt_info->has_inner_iph,IP_FIELD_TTL_HL) || \
		ip_has_inner_iph_dynamic_field_full_update(ip_context,pkt_info->has_inner_iph,IP_FIELD_IPID_BH))
		packet_type = ROHC_PACKET_TYPE_CO_COMMON;
	else if(c_tcp_context->ecn_used_update || opt_new_update->list_structure_update || \
		opt_new_update->content_update_not_defined_in_irr || \
		ip_inner_iph_ttl_field_update_can_encode(ip_context,pkt_info->has_inner_iph) || \
		tcph_new_update->rsf_flags_update){
		if(ip_id_only_one_seq(ip_context,pkt_info)){
			if(ip_seq_ip_id_encode_sets_test(ip_context,pkt_info,ROHC_ENCODE_BY_BITS(4)) && ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(15)) && ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(14)) && !tcph_new_update->window_update)
				packet_type = ROHC_PACKET_TYPE_SEQ8;
			else{
				packet_type = ROHC_PACKET_TYPE_CO_COMMON;
				rohc_pr(ROHC_DTCP,"%s [%d]\n",__func__,__LINE__);
			}
		}else{
			if(ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(16) &&\
			   ROHC_ENCODE_P_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_TCP_WLSB_K_R_0_TO_P)) &&\
			   ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(16)) &&\
			   ROHC_ENCODE_P_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_TCP_WLSB_K_R_2_TO_P) && \
			   !tcph_new_update->window_update)
				packet_type = ROHC_PACKET_TYPE_RND8;
			else{
				packet_type = ROHC_PACKET_TYPE_CO_COMMON;
				rohc_pr(ROHC_DTCP,"%s [%d]\n",__func__,__LINE__);

			}
		}
	}else{
		if(ip_id_only_one_seq(ip_context,pkt_info)){
			/*If one ip id of ipv4 is sequential */
			if(tcph_new_update->window_update){
				if(ROHC_ENCODE_BITS_TEST(&tcph_new_update->window_encode_bits,ROHC_ENCODE_BY_BITS(15))\
				   && !tcph_new_update->seq_update \
				   && ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(16)) \
				   && ROHC_ENCODE_P_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_TCP_WLSB_K_R_1_TO_P) && ip_seq_ip_id_encode_sets_test(ip_context,pkt_info,5))
					packet_type = ROHC_PACKET_TYPE_SEQ7;
				else{
					packet_type = ROHC_PACKET_TYPE_CO_COMMON;

					rohc_pr(ROHC_DTCP,"%s [%d]\n",__func__,__LINE__);
				}
			}else if(!tcph_new_update->seq_update /*&& !tcph_new_update->seq_scale_factor_or_residue_update*/){/*for example pure ack*/
				if(!tcph_new_update->ack_seq_residue_update && \
				    ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_scaled_encode_bits,ROHC_ENCODE_BY_BITS(4)) && \
				    ip_seq_ip_id_encode_sets_test(ip_context,pkt_info,3))
					packet_type  = ROHC_PACKET_TYPE_SEQ4;
				else if(ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(16)) && \
					ROHC_ENCODE_P_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_TCP_WLSB_K_R_2_TO_P) && \
					ip_seq_ip_id_encode_sets_test(ip_context,pkt_info,4))
					packet_type = ROHC_PACKET_TYPE_SEQ3;
				else if(is_can_trans_by_seq6(tcph_new_update,ip_context,pkt_info,4))
					packet_type = ROHC_PACKET_TYPE_SEQ6;
				else if(is_can_trans_by_seq5(tcph_new_update,ip_context,pkt_info,4))
					packet_type = ROHC_PACKET_TYPE_SEQ5;
				else if(ip_seq_ip_id_encode_sets_test(ip_context,pkt_info,ROHC_ENCODE_BY_BITS(4)) && \
					ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(15)) && \
					ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(14)))
					packet_type = ROHC_PACKET_TYPE_SEQ8;
				else{
					packet_type = ROHC_PACKET_TYPE_CO_COMMON;
					rohc_pr(ROHC_DTCP,"%s [%d]\n",__func__,__LINE__);
				}
			}else if(!tcph_new_update->ack_seq_update /*&& !tcph_new_update->ack_seq_residue_update*/){
				if(!tcph_new_update->seq_scale_factor_or_residue_update && \
				    ip_seq_ip_id_encode_sets_test(ip_context,pkt_info,7) && \
				    ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_scaled_encode_bits,ROHC_ENCODE_BY_BITS(4)))
					packet_type = ROHC_PACKET_TYPE_SEQ2;
				else if(ip_seq_ip_id_encode_sets_test(ip_context,pkt_info,4) && \
					ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(16)) && \
					ROHC_ENCODE_P_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_TCP_WLSB_K_R_1_TO_P))
					packet_type = ROHC_PACKET_TYPE_SEQ1;
				else if(is_can_trans_by_seq6(tcph_new_update,ip_context,pkt_info,4))
					packet_type = ROHC_PACKET_TYPE_SEQ6;
				else if(is_can_trans_by_seq5(tcph_new_update,ip_context,pkt_info,4))
					packet_type = ROHC_PACKET_TYPE_SEQ5;
				else if(ip_seq_ip_id_encode_sets_test(ip_context,pkt_info,ROHC_ENCODE_BY_BITS(4)) && \
					ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(15)) && \
					ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(14)))
					packet_type = ROHC_PACKET_TYPE_SEQ8;
				else{
					packet_type = ROHC_PACKET_TYPE_CO_COMMON;
					rohc_pr(ROHC_DTCP,"%s [%d]\n",__func__,__LINE__);
				}
			}else{
				/*tcph ack seq and tcph seq all update */
				if(is_can_trans_by_seq6(tcph_new_update,ip_context,pkt_info,4))
						packet_type = ROHC_PACKET_TYPE_SEQ6;
				else if(is_can_trans_by_seq5(tcph_new_update,ip_context,pkt_info,4))
					packet_type = ROHC_PACKET_TYPE_SEQ5;
				else if(ip_seq_ip_id_encode_sets_test(ip_context,pkt_info,ROHC_ENCODE_BY_BITS(4)) && \
					ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(15)) && \
					ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(14)))
					packet_type = ROHC_PACKET_TYPE_SEQ8;
				else{
					packet_type = ROHC_PACKET_TYPE_CO_COMMON;
					rohc_pr(ROHC_DTCP,"%s [%d],%d,seq_update=%d,ack_seq_update=%d\n",__func__,__LINE__,tcph_new_update->seq_scale_factor_or_residue_update,tcph_new_update->seq_update,tcph_new_update->ack_seq_update);
				}
			}
		}else{
			if(tcph_new_update->window_update){
				if(!tcph_new_update->seq_update && \
				   !tcph_new_update->seq_scale_factor_or_residue_update && \
				   ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(18)))
					packet_type = ROHC_PACKET_TYPE_RND7;
				else{
					packet_type = ROHC_PACKET_TYPE_CO_COMMON;
					rohc_pr(ROHC_DTCP,"%s [%d]\n",__func__,__LINE__);
				}
			}else if(!tcph_new_update->ack_seq_update){
				if(!tcph_new_update->seq_scale_factor_or_residue_update && \
				   ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_scaled_encode_bits,ROHC_ENCODE_BY_BITS(4)))
					packet_type = ROHC_PACKET_TYPE_RND2;
				else if(ROHC_ENCODE_BITS_TEST(&tcph_new_update->seq_encode_bits,ROHC_ENCODE_BY_BITS(18)))
					packet_type = ROHC_PACKET_TYPE_RND1;
				else if(is_can_trans_by_rnd6(tcph_new_update))
					packet_type = ROHC_PACKET_TYPE_RND6;
				else if(is_can_trans_by_rnd5(tcph_new_update))
					packet_type = ROHC_PACKET_TYPE_RND5;
				else if(ack_and_seq_is_can_trans_by_rnd8(tcph_new_update))
					packet_type = ROHC_PACKET_TYPE_RND8;
				else{
					packet_type = ROHC_PACKET_TYPE_CO_COMMON;
					rohc_pr(ROHC_DTCP,"%s [%d]\n",__func__,__LINE__);
				}


			}else if(!tcph_new_update->seq_update && !tcph_new_update->seq_scale_factor_or_residue_update){
				if(!tcph_new_update->ack_seq_residue_update && \
				   ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_scaled_encode_bits,ROHC_ENCODE_BY_BITS(4)))
					packet_type = ROHC_PACKET_TYPE_RND4;
				else if(ROHC_ENCODE_BITS_TEST(&tcph_new_update->ack_seq_encode_bits,ROHC_ENCODE_BY_BITS(15)))
					packet_type = ROHC_PACKET_TYPE_RND3;
				else if(is_can_trans_by_rnd6(tcph_new_update))
					packet_type = ROHC_PACKET_TYPE_RND6;
				else if(is_can_trans_by_rnd5(tcph_new_update))
					packet_type = ROHC_PACKET_TYPE_RND5;
				else if(ack_and_seq_is_can_trans_by_rnd8(tcph_new_update))
					packet_type = ROHC_PACKET_TYPE_RND8;
				else{

					packet_type = ROHC_PACKET_TYPE_CO_COMMON;
					rohc_pr(ROHC_DTCP,"%s [%d]\n",__func__,__LINE__);
				}
			}else{
				//tcp header ack sequential and sequential all update.
				if(is_can_trans_by_rnd6(tcph_new_update))
					packet_type = ROHC_PACKET_TYPE_RND6;
				else if(is_can_trans_by_rnd5(tcph_new_update))
					packet_type = ROHC_PACKET_TYPE_RND5;
				else if(ack_and_seq_is_can_trans_by_rnd8(tcph_new_update))
					packet_type = ROHC_PACKET_TYPE_RND8;
				else{
					packet_type = ROHC_PACKET_TYPE_CO_COMMON;

					rohc_pr(ROHC_DTCP,"%s [%d]\n",__func__,__LINE__);
				}
			}
		}
	}

	return packet_type;
}
enum rohc_packet_type comp_tcp_adjust_packet_type(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct comp_tcp_context *c_tcp_context;

	enum rohc_packet_type packet_type;

	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	/*probe update */

	comp_tcp_update_probe(c_tcp_context,pkt_info,context->co_fields.msn);

	switch(context->context_state){
		case	COMP_STATE_IR:
			packet_type = ROHC_PACKET_TYPE_IR;
			break;
		case	COMP_STATE_CR:
			packet_type = ROHC_PACKET_TYPE_IR_CR;
			break;
		case	COMP_STATE_FO:
			packet_type = ROHC_PACKET_TYPE_IR_DYN;
			break;
		case	COMP_STATE_SO:
			packet_type = comp_tcp_adjust_packet_type_so(c_tcp_context,pkt_info);
			break;

	}
	rohc_pr(ROHC_DTCP,"tcp cid-%d decide packet_type=%d\n",context->cid,packet_type);
	pkt_info->packet_type = packet_type;
	return packet_type;
}


int comp_tcp_build_comp_header(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,enum rohc_packet_type type)
{
	int retval;
	switch(type){
		case ROHC_PACKET_TYPE_IR:
			retval = rohc_comp_build_ir(context,skb,pkt_info);
			break;
		case ROHC_PACKET_TYPE_IR_DYN:
			retval = rohc_comp_build_ir_dyn(context,skb,pkt_info);
			break;
		default:
			retval = comp_tcp_build_co_header(context,skb,pkt_info);
			break;
	}
	return retval;
}

u32 comp_tcp_new_msn(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u32 msn;
	msn = context->co_fields.msn;
	msn = (u16)(msn + 1);
	return msn;
}

static void comp_tcp_update_ip_context(struct tcp_iph_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info,u32 msn)
{
	struct iphdr *new_iph,*to_iph;
	struct ipv6hdr *new_ipv6h,*to_ipv6h;
	struct last_comped_iph_ref *iph_ref;
	struct iph_update	*new_iph_update;
	new_iph = &pkt_info->iph;
	new_iph_update = &ip_context->update_by_packet;
	iph_ref = &ip_context->iph_ref;
	if(rohc_iph_is_v4(new_iph->version)){
		iph_ref->ipid_bh = new_iph_update->new_ipid_bh;
		to_iph = &iph_ref->iph;
		memcpy(to_iph,new_iph,sizeof(struct iphdr));
		comp_wlsb_add(ip_context->ipid_wlsb,NULL,msn,new_iph_update->new_ip_id_offset);

	}else{
		new_ipv6h = &pkt_info->ipv6h;
		to_ipv6h = &iph_ref->ipv6h;
		memcpy(to_ipv6h,new_ipv6h,sizeof(struct ipv6hdr));
	}
	if(pkt_info->has_inner_iph){
		new_iph = &pkt_info->inner_iph;
		new_iph_update = &ip_context->inner_update_by_packet;
		if(rohc_iph_is_v4(new_iph->version)){
			iph_ref->inner_ipid_bh = new_iph_update->new_ipid_bh;
			to_iph = &iph_ref->inner_iph;
			memcpy(to_iph,new_iph,sizeof(struct iphdr));
			comp_wlsb_add(ip_context->inner_ipid_wlsb,NULL,msn,new_iph_update->new_ip_id_offset);
		}else{
			new_ipv6h = &pkt_info->inner_ipv6h;
			to_ipv6h = &iph_ref->inner_ipv6h;
			memcpy(to_ipv6h,new_ipv6h,sizeof(struct ipv6hdr));
		}
	}
	if(pkt_info->has_inner_iph){
		new_iph = &pkt_info->inner_iph;
		if(rohc_iph_is_v4(new_iph->version))
			comp_wlsb_add(ip_context->ttl_hl_wlsb,NULL,msn,new_iph->ttl);
		else{
			new_ipv6h = &pkt_info->inner_ipv6h;
			comp_wlsb_add(ip_context->ttl_hl_wlsb,NULL,msn,new_ipv6h->hop_limit);
		}
	}else{
		new_iph = &pkt_info->iph;
		if(rohc_iph_is_v4(new_iph->version))
			comp_wlsb_add(ip_context->ttl_hl_wlsb,NULL,msn,new_iph->ttl);
		else{
			new_ipv6h = &pkt_info->ipv6h;
			comp_wlsb_add(ip_context->ttl_hl_wlsb,NULL,msn,new_ipv6h->hop_limit);
		}
	}
	ip_context->is_first_packet = false;
}


static int comp_tcp_init_ip_context(struct tcp_iph_context *ip_context,int oa_max)
{
	int retval,i;
	ip_context->ttl_hl_wlsb = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_UCHAR,GFP_ATOMIC);
	if(IS_ERR(ip_context->ttl_hl_wlsb)){
		retval = -ENOMEM;
		goto err0;
	}
	for(i = 0 ; i < ROHC_MAX_IP_HDR; i++){
		ip_context->ip_id_wlsb[i] = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_USHORT,GFP_ATOMIC);
		if(IS_ERR(ip_context->ip_id_wlsb[i])){
			if(i == ROHC_INNER_IPH)
				comp_wlsb_destroy(ip_context->ip_id_wlsb[i - 1]);
			retval = -ENOMEM;
			goto err1;
		}
	}
	ip_context->is_first_packet = true;
	return 0;
err1:
	comp_wlsb_destroy(ip_context->ttl_hl_wlsb);
err0:
	return retval;
}
static void comp_tcp_destroy_ip_context(struct tcp_iph_context *ip_context)
{
	
	comp_wlsb_destroy(ip_context->ipid_wlsb);
	comp_wlsb_destroy(ip_context->inner_ipid_wlsb);
	comp_wlsb_destroy(ip_context->ttl_hl_wlsb);
}


static void comp_tcp_update_tcp_context(struct tcph_context *tcp_context,struct rohc_comp_packet_hdr_info *pkt_info,u32 msn)
{
	struct tcphdr *new_tcph,*to_tcph;
	struct last_comped_tcph_ref *tcph_ref;
	struct tcph_update *new_tcph_update;
	u32 msn_ref;
	tcph_ref = &tcp_context->tcph_ref;
	new_tcph_update = &tcp_context->tcph_update_by_packet;
	new_tcph = &pkt_info->tcph;
	to_tcph = &tcph_ref->tcph;
	memcpy(to_tcph,new_tcph,sizeof(struct tcphdr));
	tcph_ref->ack_stride = new_tcph_update->ack_stride_use;
	tcph_ref->ack_seq_residue = new_tcph_update->ack_seq_residue;
	tcph_ref->seq_factor = new_tcph_update->seq_factor;
	tcph_ref->seq_residue = new_tcph_update->seq_residue;
	/*add wlsb*/
	if(new_tcph_update->ack_stride_true)
		comp_wlsb_add(tcp_context->ack_stride_wlsb,NULL,msn,new_tcph_update->ack_stride_true);
	comp_wlsb_add(tcp_context->ack_seq_wlsb,NULL,msn,ntohl(new_tcph->ack_seq));
	comp_wlsb_add(tcp_context->seq_wlsb,NULL,msn,ntohl(new_tcph->seq));
	comp_wlsb_add(tcp_context->seq_scaled_wlsb,NULL,msn,new_tcph_update->seq_scaled);
	comp_wlsb_add(tcp_context->ack_seq_scaled_wlsb,NULL,msn,new_tcph_update->ack_seq_scaled);
	comp_wlsb_add(tcp_context->window_wlsb,NULL,msn,ntohs(new_tcph->window));

	comp_wlsb_add(tcp_context->msn_wlsb,NULL,msn,msn);

}
static int comp_tcp_init_tcp_context(struct tcph_context *tcp_context,int oa_max)
{
	int retval = 0;
	tcp_context->ack_seq_wlsb = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(tcp_context->ack_seq_wlsb)){
		pr_err("alloc ack seq wlsb failed\n");
		retval = -ENOMEM;
		goto out;
	}
	tcp_context->ack_seq_scaled_wlsb = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(tcp_context->ack_seq_scaled_wlsb)){
		pr_err("alloc ack seq scaled wlsb failed");
		retval = -ENOMEM;
		goto err1;
	}
	tcp_context->seq_wlsb = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(tcp_context->seq_wlsb)){
		pr_err("alloc seq wlsb failed\n");
		retval = -ENOMEM;
		goto err2;
	}
	tcp_context->seq_scaled_wlsb = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(tcp_context->seq_scaled_wlsb)){
		pr_err("alloc seq scaled wlsb failed\n");
		retval = -ENOMEM;
		goto err3;
	}
	tcp_context->ack_stride_wlsb = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_UINT,GFP_ATOMIC);
	if(IS_ERR(tcp_context->ack_stride_wlsb)){
		pr_err("alloc ack stride wlsb failed\n");
		retval = -ENOMEM;
		goto err4;
	}
	tcp_context->window_wlsb = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_USHORT,GFP_ATOMIC);
	if(IS_ERR(tcp_context->window_wlsb)){
		pr_err("alloc window wlsb failed\n");
		retval = -ENOMEM;
		goto err5;
	}
	tcp_context->msn_wlsb = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_USHORT,GFP_ATOMIC);
	if(IS_ERR(tcp_context->msn_wlsb)){
		pr_err("alloc msn wlsb failed\n");
		retval = -ENOMEM;
		goto err6;
	}
	return 0;
err6:
	comp_wlsb_destroy(tcp_context->window_wlsb);
err5:
	comp_wlsb_destroy(tcp_context->ack_stride_wlsb);
err4:
	comp_wlsb_destroy(tcp_context->seq_scaled_wlsb);
err3:
	comp_wlsb_destroy(tcp_context->seq_wlsb);
err2:
	comp_wlsb_destroy(tcp_context->ack_seq_scaled_wlsb);
err1:
	comp_wlsb_destroy(tcp_context->ack_seq_wlsb);
out:
	return retval;
}

void comp_tcp_destroy_tcp_context(struct tcph_context *tcp_context)
{
	comp_wlsb_destroy(tcp_context->msn_wlsb);
	comp_wlsb_destroy(tcp_context->window_wlsb);
	comp_wlsb_destroy(tcp_context->ack_stride_wlsb);
	comp_wlsb_destroy(tcp_context->seq_scaled_wlsb);
	comp_wlsb_destroy(tcp_context->seq_wlsb);
	comp_wlsb_destroy(tcp_context->ack_seq_scaled_wlsb);
	comp_wlsb_destroy(tcp_context->ack_seq_wlsb);
}
int comp_tcp_init_context(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct comp_tcp_context *c_tcp_context;
	struct iphdr *iph;
	int retval = 0;
	c_tcp_context = kzalloc(sizeof(struct comp_tcp_context),GFP_ATOMIC);
	if(!c_tcp_context){
		pr_err("%s : alloc memeroy for comp tcp context failed\n",__func__);
		retval = -ENOMEM;
	}
	c_tcp_context->oa_upward_pkts = 3;//context->compresser->refresh_thresholds.oa_upward_pkts;
	retval = comp_tcp_init_ip_context(&c_tcp_context->ip_context,c_tcp_context->oa_upward_pkts);
	if(retval)
		goto out;
	retval = comp_tcp_init_tcp_context(&c_tcp_context->tcp_context,c_tcp_context->oa_upward_pkts);
	if(retval)
		goto err0;
	retval = tcp_option_init_context(&c_tcp_context->tcp_opt_context,c_tcp_context->oa_upward_pkts);
	if(retval)
		goto err1;
	context->prof_context = c_tcp_context;
	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		if(rohc_iph_is_v4(iph->version))
			context->co_fields.msn = ntohl(iph->id);
		else{
			iph = &pkt_info->iph;
			if(rohc_iph_is_v4(iph->version))
				context->co_fields.msn = ntohl(iph->id);
			else
				get_random_bytes(&context->co_fields.msn,2);
		}
	}else{
		iph = &pkt_info->iph;
		if(rohc_iph_is_v4(iph->version))
			context->co_fields.msn = ntohl(iph->id);
		else
			get_random_bytes(&context->co_fields.msn,2);
	}
	return 0 ;
err1:
	comp_tcp_destroy_tcp_context(&c_tcp_context->tcp_context);
err0:
	comp_tcp_destroy_ip_context(&c_tcp_context->ip_context);
out:
	return retval;
}
void comp_tcp_update_context(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct sk_buff *skb;
	struct comp_tcp_context *c_tcp_context;
	struct tcp_iph_context *ip_context;
	struct tcph_context *tcp_context;
	struct tcph_option_context *opt_context;
	u32 msn;

	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	ip_context = &c_tcp_context->ip_context;
	tcp_context = &c_tcp_context->tcp_context;
	opt_context = &c_tcp_context->tcp_opt_context;
	skb = pkt_info->skb;
	msn = context->co_fields.msn;
	comp_tcp_update_ip_context(ip_context,pkt_info,msn);
	comp_tcp_update_tcp_context(tcp_context,pkt_info,msn);
	tcph_option_update_context(opt_context,skb,pkt_info,msn);
	rohc_pr(ROHC_DTCP,"tcp cid-%d msn=%d\n",context->cid,msn);
}

void comp_tcp_ack_input(struct rohc_comp_context *context,u32 msn,int msn_bits,bool sn_valid)
{
	struct comp_tcp_context *c_tcp_context;
	struct tcp_iph_context *ip_context;
	struct tcph_context *tcp_context;
	struct tcph_option_context *opt_context;
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	ip_context = &c_tcp_context->ip_context;
	tcp_context = &c_tcp_context->tcp_context;
	opt_context = &c_tcp_context->tcp_opt_context;
	if(context->context_state != COMP_STATE_SO)
		rohc_comp_context_change_state(context,COMP_STATE_SO);
	if(sn_valid){
		comp_wlsb_ack(ip_context->ipid_wlsb,msn_bits,msn);
		comp_wlsb_ack(ip_context->inner_ipid_wlsb,msn_bits,msn);
		comp_wlsb_ack(ip_context->ttl_hl_wlsb,msn_bits,msn);
		comp_wlsb_ack(tcp_context->ack_seq_wlsb,msn_bits,msn);
		comp_wlsb_ack(tcp_context->ack_seq_scaled_wlsb,msn_bits,msn);
		comp_wlsb_ack(tcp_context->seq_wlsb,msn_bits,msn);
		comp_wlsb_ack(tcp_context->seq_scaled_wlsb,msn_bits,msn);
		comp_wlsb_ack(tcp_context->window_wlsb,msn_bits,msn);
		comp_wlsb_ack(tcp_context->msn_wlsb,msn_bits,msn);
		comp_wlsb_ack(opt_context->ts_wlsb,msn_bits,msn);
		comp_wlsb_ack(opt_context->tsecho_wlsb,msn_bits,msn);
		confident_iph_all_trans_times(&ip_context->update_trans_times,c_tcp_context->oa_upward_pkts);
		confident_iph_all_trans_times(&ip_context->inner_update_trans_times,c_tcp_context->oa_upward_pkts);
		confident_tcph_all_trans_times(&tcp_context->update_trans_times,c_tcp_context->oa_upward_pkts);
		confident_tcp_options_all_trans_times(opt_context->update_trans_times,c_tcp_context->oa_upward_pkts);
		c_tcp_context->ecn_used_trans_time = c_tcp_context->oa_upward_pkts;
		opt_context->list_structure_update_trans_time = c_tcp_context->oa_upward_pkts;
	}


}
void comp_tcp_nack_input(struct rohc_comp_context *context,u32 msn,int msn_bits,bool sn_valid)
{
	struct comp_tcp_context *c_tcp_context;
	struct tcp_iph_context *ip_context;
	struct tcph_context *tcp_context;
	struct tcph_option_context *opt_context;
	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	ip_context = &c_tcp_context->ip_context;
	tcp_context = &c_tcp_context->tcp_context;
	opt_context = &c_tcp_context->tcp_opt_context;
	reset_iph_all_trans_times(&ip_context->update_trans_times);
	reset_iph_all_trans_times(&ip_context->inner_update_trans_times);
	reset_tcph_all_trans_times(&tcp_context->update_trans_times);
	reset_tcp_options_all_trans_times(opt_context->update_trans_times);
	opt_context->list_structure_update_trans_time = 0;
	c_tcp_context->ecn_used_trans_time = 0;
}

void comp_tcp_feedback_ack1(struct rohc_comp_context *context,struct sk_buff *skb,int size)
{
	u8 *data;
	u32 msn;
	int msn_mask_bit;
	data = skb->data;
	msn = (*data) & 0xff;
	msn_mask_bit = 8;
	if(context->mode != ROHC_MODE_O)
		rohc_comp_context_change_mode(context,ROHC_MODE_O);
	rohc_pr(ROHC_DTCP,"%s \n",__func__);
	comp_tcp_ack_input(context,msn,msn_mask_bit,true);
	skb_pull(skb,size);

}

void comp_tcp_feedback_ack2(struct rohc_comp_context *context,struct sk_buff *skb,int size)
{
	u8 *data;
	int mode;
	int ack_type;
	u32 msn;
	u32 sn_mask_bits;
	u8 crc;
	struct rohc_feedback_option_compile option_compile;
	int retval = 0;
	int decode_size = 0;
	bool sn_valid = true;

	memset(&option_compile,0,sizeof(struct rohc_feedback_option_compile));
	data = skb->data;

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


	rohc_pr(ROHC_DTCP,"tcp context-%d recv ack :%d\n",context->cid,ack_type);
	option_compile.sn = msn;
	skb_pull(skb,decode_size);
	size -= decode_size;

	rohc_feeback_parse_options(skb,&option_compile,ROHC_V1_PROFILE_TCP,size);
	sn_mask_bits += option_compile.sn_opt_bits;
	msn = option_compile.sn;
	if(option_compile.option_apprear[FEEDBACK_OPTION_TYPE_UNVALID_SN] > 0)
		sn_valid = false;
	switch(ack_type){
		case ROHC_FEEDBACK_ACK:
			comp_tcp_ack_input(context,msn,sn_mask_bits,sn_valid);
			break;
		case ROHC_FEEDBACK_NACK:
			if(context->context_state == COMP_STATE_SO){
				rohc_comp_context_change_state(context,COMP_STATE_FO);
				comp_tcp_nack_input(context,msn,sn_mask_bits,sn_valid);
			}
			break;
		case ROHC_FEEDBACK_STATIC_NACK:
			rohc_comp_context_change_state(context,COMP_STATE_IR);
			comp_tcp_nack_input(context,msn,sn_mask_bits,sn_valid);
			break;
	}
	return 0;
}
int comp_tcp_feedback_input(struct rohc_comp_context *context,struct sk_buff *skb,int cid_len,int size)
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
	size -= cid_len;
	if(size  == 1)
		comp_tcp_feedback_ack1(context,skb,size);
	else if(size > 1)
		comp_tcp_feedback_ack2(context,skb,size);
	else{
		pr_err("context-%d,profile-%x recieved the size zero feedback\n",context->cid,prof);
		retval = -EFAULT;
	}
out:
	return retval;
}

static void comp_tcp_recover_net_header_dump(struct sk_buff *skb,int cid,u32 msn)
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	u8 *addr;
	int len,i;
	u32 *opt;
	//if(cid != 0)
	//	return;
	iph = ip_hdr(skb);
	rohc_pr(ROHC_DTCP,"COMP_TCP cid : %d msn:%d,totoal_len :%d\n",cid,msn,skb->len);
	rohc_pr(ROHC_DTCP,"ipid=%d,id_off_msn=%u,tos=%d,ttl=%d,iphl=%d,pro=%d,tot_len=%d,fragof=%x,check=%x\n",ntohs(iph->id),ntohs(iph->id) - msn,iph->tos,iph->ttl,iph->ihl,iph->protocol,ntohs(iph->tot_len),iph->frag_off,iph->check);
	addr = (u8 *)&iph->saddr;
	rohc_pr(ROHC_DTCP,"ipsrc:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	addr = (u8 *)&iph->daddr;
	rohc_pr(ROHC_DTCP,"ipdst:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	tcph = tcp_hdr(skb);
	rohc_pr(ROHC_DTCP,"dport=%d,sport=%d,doff=%d,check=%x\n",ntohs(tcph->source),ntohs(tcph->dest),tcph->doff,tcph->check);
	rohc_pr(ROHC_DTCP,"res1=%d\n",tcph->res1);
	rohc_pr(ROHC_DTCP,"seq=%x,ack_seq=%x\n",ntohl(tcph->seq),ntohl(tcph->ack_seq));
	rohc_pr(ROHC_DTCP,"fin=%d,syn=%d,rst=%d,psh=%d,ack=%d,urg=%d,ece=%d,cwr=%d\n",tcph->fin,tcph->syn,tcph->rst,tcph->psh,tcph->ack,tcph->urg,tcph->ece,tcph->cwr);
	rohc_pr(ROHC_DTCP,"win=%d,urg_ptr=%d\n",ntohs(tcph->window),ntohs(tcph->urg_ptr));

	opt  =  (u32 *)(tcph + 1);
	len = (tcph->doff * 4 - sizeof(struct tcphdr)) / 4;
	rohc_pr(ROHC_DTCP,"tcp option length: %d\n",len * 4);
	for(i = 0 ; i < len ;i++,opt++){
		rohc_pr(ROHC_DTCP,"[%d] 0x%08x\n",i,*opt);
	}

}
int comp_tcp_compress(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rohc_comp_profile *comp_profile;
	struct comp_profile_ops *prof_ops;
	struct comp_tcp_context *c_tcp_context;
	enum rohc_packet_type packet_type;
	u32 msn;
	int retval;

	c_tcp_context = (struct comp_tcp_context *)context->prof_context;
	comp_profile = context->comp_profile;
	prof_ops = comp_profile->pro_ops;
	context->co_fields.msn =  prof_ops->new_msn(context,pkt_info);
	msn = context->co_fields.msn;
	comp_tcp_recover_net_header_dump(skb,context->cid,msn);
	//comp_tcp_update_probe(c_tcp_context,pkt_info,msn);
	packet_type = prof_ops->adjust_packet_type(context,skb,pkt_info);
	retval = prof_ops->build_comp_header(context,skb,pkt_info,packet_type);
	if(retval){
		rohc_pr(ROHC_DTCP ,"TCP context-%d build compress packet failed\n ",context->cid);
		goto out;
	}
	prof_ops->update_context(context,pkt_info);
out:
	return retval;
}


struct comp_profile_ops comp_tcp_prof_ops ={
	.adjust_packet_type = comp_tcp_adjust_packet_type,
	.new_msn = comp_tcp_new_msn,
	.build_static_chain = comp_tcp_build_static_chain,
	.build_dynamic_chain = comp_tcp_build_dynamic_chain,
	.build_comp_header = comp_tcp_build_comp_header,
	.compress = comp_tcp_compress,
	.init_context = comp_tcp_init_context,
	.update_context = comp_tcp_update_context,
	.feedback_input = comp_tcp_feedback_input,
};


struct rohc_comp_profile comp_profile_tcp = {
	.profile = ROHC_V1_PROFILE_TCP,
	.pro_ops = &comp_tcp_prof_ops,
};
