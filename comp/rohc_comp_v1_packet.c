/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/string.h>
#include <linux/swab.h>
#include <net/ip.h>
#include "../rohc_packet.h"
#include "../rohc_ipid.h"
#include "../rohc_packet_field.h"
#include "../rohc_cid.h"
#include "../rohc_profile.h"
#include "../rohc_common.h"
#include "../rohc_feedback.h"

#include "rohc_comp.h"
#include "rohc_comp_profile_v1.h"

/**
 *
 */
void rohc_comp_iph_update_probe(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct iphdr *iph;
	struct comp_profile_v1_context *v1_context;
	struct ip_context *ip_context;
	struct iph_packet_update *update_by_packet;
	struct iph_update_info *iph_update;
	struct iph_behavior_info *iph_bh;
	v1_context = context->prof_context;
	ip_context = &v1_context->ip_context;
	u16 msn;
	u16 ipid;
	int i;
	int retval = 0 ;
	msn = context->co_fields.msn;
	update_by_packet = &ip_context->update_by_packet;
	memset(update_by_packet,0,sizeof(struct iph_packet_update));
	ip_id_behavior_probe(ip_context,pkt_info);
	for(i = 0 ; i < pkt_info->iph_num ; i++){
		iph_bh = &update_by_packet->iph_updates[i];
		iph_update = &update_by_packet->iph_updates[i];

		if(i == ROHC_OUTER_IPH)
			iph = &pkt_info->iph;
		else
			iph = &pkt_info->inner_iph;
		if(rohc_iph_is_v4(iph->version) && !ip_id_is_random_or_constant(iph_bh->ip_id_bh)){
			ipid = ntohs(iph->id);
			if(!ip_id_is_nbo(iph_bh->ip_id_bh))
				ipid = __swab16(ipid);
			iph_update->ip_id_offset = ipid - msn;
		}
	}
	ip_id_k_bits_probes(ip_context,pkt_info,context->comp_profile->profile);
	iph_update_probes(ip_context,pkt_info,v1_context->oa_upward_pkts);

}
bool rohc_comp_only_need_trans_one_ip_id_by_uo1(struct comp_profile_v1_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	/*If there are two ip headers,
	 * UO1 preferentially transmits the IP-ID of the internal IPH. When the internal IPH is not IPV6 or the IP-ID is random or constant, the external IPH IPID is transmitted.
	 */

	struct ip_context *ip_context;
	struct iphdr *outer_iph,*inner_iph;
	struct iph_update_info *outer_iph_update,*inner_iph_update;
	struct iph_behavior_info *outer_iph_bh,*inner_ip_bh;
	struct iph_encode_ipid_bits *outer_ipid_k_bits,*inner_ipid_k_bits;

	bool retval = false;
	ip_context = &context->ip_context;
	outer_iph_update = &ip_context->update_by_packet.iph_updates[ROHC_OUTER_IPH];
	outer_iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_OUTER_IPH];
	outer_ipid_k_bits = &ip_context->update_by_packet.ipid_k_bits[ROHC_OUTER_IPH];
	outer_iph = &pkt_info->iph;
	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		inner_iph_update = &ip_context->update_by_packet.iph_updates[ROHC_INNER_IPH];
		inner_ip_bh = &ip_context->update_by_packet.iph_behavior[ROHC_INNER_IPH];
		inner_ipid_k_bits = &ip_context->update_by_packet.ipid_k_bits[ROHC_INNER_IPH];
		if(rohc_iph_is_v4(inner_iph->version) && !ip_id_is_random_or_constant(inner_ip_bh->ip_id_bh)){
			if(!ip_id_offset_need_trans(outer_iph->version,outer_iph_bh,outer_iph_update) && inner_ipid_k_bits->can_encode_by_6_bit)
				retval = true;
		}else if(rohc_iph_is_v4(outer_iph->version) && !ip_id_is_random_or_constant(outer_iph_bh->ip_id_bh)){
			if(/*outer_iph_update->ip_id_offset_update &&*/ outer_ipid_k_bits->can_encode_by_6_bit)
				retval = true;
		}
	}else{
#if 0
		if(ip_id_offset_need_trans(outer_iph->version,outer_ip_bh,outer_iph_update) && outer_ipid_k_bits->can_encode_by_6_bit)
#endif		
		if(rohc_iph_is_v4(outer_iph->version) && !ip_id_is_random_or_constant(outer_iph_bh->ip_id_bh) && outer_ipid_k_bits->can_encode_by_6_bit)
				retval = true;
	}
	return retval;
}
void rohc_comp_pick_non_rnd_const_ipid(struct comp_profile_v1_context *context,struct rohc_comp_packet_hdr_info *pkt_info,u16 *ipid_off,bool *is_inner_iph)
{
	struct iph_behavior_info *outer_ip_bh,*inner_ip_bh;
	struct iph_packet_update *update_packet;
	struct iph_update_info *outer_iph_update,*inner_iph_update;
	struct iphdr *outer_iph,*inner_iph;
	u16 ip_id_offset;
	update_packet = &context->ip_context.update_by_packet;
	outer_iph = &pkt_info->iph;
	outer_ip_bh = &update_packet->iph_behavior[ROHC_OUTER_IPH];
	outer_iph_update = &update_packet->iph_updates[ROHC_OUTER_IPH];
	/*if there are tow ip headers ,priority select the ipid of 
	 * internal ip header
	 */
	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		inner_ip_bh = &update_packet->iph_behavior[ROHC_INNER_IPH];
		inner_iph_update = &update_packet->iph_updates[ROHC_INNER_IPH];
		if(rohc_iph_is_v4(inner_iph->version) && !ip_id_is_random_or_constant(inner_ip_bh->ip_id_bh)){
			ip_id_offset = inner_iph_update->ip_id_offset;
			if(is_inner_iph)
				*is_inner_iph = true;
		}else if(rohc_iph_is_v4(outer_iph->version) && !ip_id_is_random_or_constant(outer_ip_bh->ip_id_bh)){
			ip_id_offset = outer_iph_update->ip_id_offset;
			if(is_inner_iph)
				*is_inner_iph = false;
		}else
			pr_err("%s : error can't find the non random and non constant ip id,has_inner_iph=%s\n",__func__,pkt_info->has_inner_iph ? "true":"false");
	}else{
		if(rohc_iph_is_v4(outer_iph->version) && !ip_id_is_random_or_constant(outer_ip_bh->ip_id_bh)){
			ip_id_offset = outer_iph_update->ip_id_offset;
			if(is_inner_iph)
				*is_inner_iph = false;
		}else
			pr_err("%s : error can't find the non random and non constant ip id,has_inner_iph=%s\n",__func__,pkt_info->has_inner_iph ? "true":"false");

	}
	*ipid_off = ip_id_offset;
}
int rohc_comp_uro_2_adjust_extension(struct comp_profile_v1_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct ip_context *ip_context;
	struct iph_packet_update *update_packet;
	struct iph_update_info *outer_iph_update,*inner_iph_update;
	struct iph_behavior_info *outer_iph_bh,*inner_iph_bh;
	struct iphdr *outer_iph,*inner_iph;
	struct  packet_type_info *packet_info;
	struct  msn_encode_bits *sn_k_bits;
	struct  iph_encode_ipid_bits *outer_ipid_k_bits,*inner_ipid_k_bits;
	enum rohc_ext_type ext_type;
	bool ip_id_update,ip_id2_update,ip_id_encode_3_bit,ip_id_encode_11_bit,ip_id_encode_8_bit,ip_id2_encode_11_bit;
	int retval = 0;
	ip_context = &context->ip_context;
	update_packet = &ip_context->update_by_packet;
	packet_info = &context->packet_info;
	outer_iph_bh = &update_packet->iph_behavior[ROHC_OUTER_IPH];
	outer_iph_update = &update_packet->iph_updates[ROHC_OUTER_IPH];
	outer_ipid_k_bits = &update_packet->ipid_k_bits[ROHC_OUTER_IPH];
	outer_iph = &pkt_info->iph;
	sn_k_bits = &context->msn_k_bits;
	if(pkt_info->has_inner_iph){
		inner_iph_bh = &update_packet->iph_behavior[ROHC_INNER_IPH];
		inner_iph_update = &update_packet->iph_behavior[ROHC_INNER_IPH];
		inner_iph = &pkt_info->inner_iph;

		inner_ipid_k_bits = &update_packet->ipid_k_bits[ROHC_INNER_IPH];
		/* if inner ip header is ipv4 header,and ip id is not random and is not constant,need to carray ip id offset 
		 * */
		/*if inner ip header is non random and non constant ip-id,the extension 0 and extension 1
		 * only carray inner ip header ip-id.
		 */
		if(rohc_iph_is_v4(inner_iph->version) && !ip_id_is_random_or_constant(inner_iph_bh->ip_id_bh)){
			ip_id_update = true;
			ip_id_encode_3_bit = inner_ipid_k_bits->can_encode_by_3_bit;
			ip_id_encode_8_bit = inner_ipid_k_bits->can_encode_by_8_bit;
			ip_id_encode_11_bit = inner_ipid_k_bits->can_encode_by_11_bit;

			if(rohc_iph_is_v4(outer_iph->version) && !ip_id_is_random_or_constant(outer_iph_bh->ip_id_bh)){
				if(outer_iph_update->ip_id_offset_update)
					ip_id2_update = true;
				else
					ip_id2_update = false;
				ip_id2_encode_11_bit = outer_ipid_k_bits->can_encode_by_11_bit;
			}else{
				ip_id2_update = false;
				ip_id2_encode_11_bit = false;
			}
		}else if(rohc_iph_is_v4(outer_iph_bh->ip_id_bh) && !ip_id_is_random_or_constant(outer_iph_bh->ip_id_bh)){
			/* if inner ip header is not ipv4, or ip id is random or ip id is constant,only need carray outer ip
			 * header ip id ,and outer ip id as ip-id rather than ip-id2.
			 */
			ip_id_update = true;
			ip_id_encode_3_bit = outer_ipid_k_bits->can_encode_by_3_bit;
			ip_id_encode_8_bit = outer_ipid_k_bits->can_encode_by_8_bit;
			ip_id_encode_11_bit = outer_ipid_k_bits->can_encode_by_11_bit;
			ip_id2_update = false;
			ip_id2_encode_11_bit = false;
		}else{
			ip_id_update = false;
			ip_id_encode_3_bit = ip_id_encode_8_bit = ip_id_encode_11_bit = false;
			ip_id2_update = false;
			ip_id2_encode_11_bit = false;
		}	
	}else{
		/* only a ip header
		 */
		if(rohc_iph_is_v4(outer_iph->version) && !ip_id_is_random_or_constant(outer_iph_bh->ip_id_bh) && outer_iph_update->ip_id_offset_update){
			ip_id_update = true;
			ip_id_encode_3_bit = outer_ipid_k_bits->can_encode_by_3_bit;
			ip_id_encode_8_bit = outer_ipid_k_bits->can_encode_by_8_bit;
			ip_id_encode_11_bit = outer_ipid_k_bits->can_encode_by_11_bit;
			ip_id2_update = false;
			ip_id2_encode_11_bit = false;
		}else{
			ip_id_update = false;
			ip_id_encode_3_bit = ip_id_encode_8_bit = ip_id_encode_11_bit = false;
			ip_id2_update = false;
			ip_id2_encode_11_bit = false;
		}
	}
	if(!ip_id_update && !ip_id2_update && sn_k_bits->can_encode_by_5_bit)
		ext_type = EXT_TYPE_NONE;
	else if(ip_id_update && !ip_id2_update && sn_k_bits->can_encode_by_8_bit && ip_id_encode_3_bit)
		ext_type = EXT_TYPE_0;
	else if(ip_id_update && !ip_id2_update && sn_k_bits->can_encode_by_8_bit && ip_id_encode_11_bit)
		ext_type = EXT_TYPE_1;
	else if(ip_id_update && ip_id2_update && sn_k_bits->can_encode_by_8_bit && ip_id_encode_8_bit && ip_id2_encode_11_bit)
		ext_type = EXT_TYPE_2;
	else 
		ext_type = EXT_TYPE_3;
	rohc_pr(ROHC_DEBUG ,"inner:%d,ip_id_update=%d,ip_id2_update=%d,ipid_bh=%d\n",pkt_info->has_inner_iph,ip_id_update,ip_id2_update,outer_iph_bh->ip_id_bh);
	packet_info->ext_type = ext_type;

out:
	return retval;
}


int rohc_comp_adjust_extension(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct comp_profile_v1_context *v1_context;
	struct ip_context *ip_context;
	struct iph_packet_update *update_packet;
	struct iph_update_info *outer_iph_update,*inner_iph_update;
	struct  packet_type_info *packet_info;
	struct comp_profile_v1_ops *prof_ops;
	enum rohc_ext_type ext_type;

	int retval = 0;
	v1_context = context->prof_context;
	ip_context = &v1_context->ip_context;
	packet_info = &v1_context->packet_info;
	update_packet = &ip_context->update_by_packet;
	outer_iph_update = &update_packet->iph_updates[ROHC_OUTER_IPH];
	if(pkt_info->has_inner_iph){
		inner_iph_update = &update_packet->iph_updates[ROHC_INNER_IPH];
		/**
		 *now only support ipv4
		 */
		if(iph_dynamic_fields_update(inner_iph_update)){
			ext_type = EXT_TYPE_3;
			packet_info->ext_type = ext_type;
			goto out;
		}
	}
	if(iph_dynamic_fields_update(outer_iph_update)){
		ext_type = EXT_TYPE_3;
		packet_info->ext_type = ext_type;
		goto out;
	}

	prof_ops = v1_context->prof_v1_ops;
	if(prof_ops && prof_ops->adjust_extension)
		prof_ops->adjust_extension(context,pkt_info);
	else
		packet_info->ext_type = EXT_TYPE_NONE;
	rohc_pr(ROHC_DEBUG,"%s:packet_type=%d,ext_type=%d\n",__func__,packet_info->packet_type,packet_info->ext_type);
out:
	return retval;
}

int rohc_comp_build_ext0(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct comp_profile_v1_context *v1_context;
	u16 msn;
	u16 ip_id_offset;
	int encode_len = 0;
	int retval = 0;
	v1_context = context->prof_context;
	msn = context->co_fields.msn;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	rohc_comp_pick_non_rnd_const_ipid(v1_context,pkt_info,&ip_id_offset,NULL);
	/*extensions 0 only one byte
	 */
	/*2 bits extension type ,3 bits msn and 3 bit ipid
	 */
	*comp_hdr = ROHC_EXT_0| ((msn & 0x7) << 3) | (ip_id_offset & 0x7);
	encode_len += 1;
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;

}
int rohc_comp_build_ext1(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct comp_profile_v1_context *v1_context;
	u16 msn;
	u16 ip_id_offset;
	int encode_len = 0;
	int retval = 0;
	v1_context = context->prof_context;
	msn = context->co_fields.msn;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	rohc_comp_pick_non_rnd_const_ipid(v1_context,pkt_info,&ip_id_offset,NULL);
	/*first byte : 2 bits extension type ,3 bits msn adn 3 bits ipid
	 */
	*comp_hdr = ROHC_EXT_1 | (( msn & 0x7) << 3) | ((ip_id_offset >> 8) & 0x7);
	comp_hdr++;
	/*seconde byte : 8 bits ipid
	 */
	*comp_hdr = ip_id_offset & 0xff;

	encode_len += 2;
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rohc_comp_build_ext2(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct iph_update_info *outer_iph_update,*inner_iph_update;
	struct comp_profile_v1_context *v1_context;
	u16 outer_ipid_offset;
	u16 inner_ipid_offset;
	u16 msn;
	int encode_len = 0;
	int retval = 0;
	BUG_ON(!pkt_info->has_inner_iph);
	v1_context = context->prof_context;
	outer_iph_update = &v1_context->ip_context.update_by_packet.iph_updates[ROHC_OUTER_IPH];
	inner_iph_update = &v1_context->ip_context.update_by_packet.iph_updates[ROHC_INNER_IPH];
	outer_ipid_offset = outer_iph_update->ip_id_offset;
	inner_ipid_offset = inner_iph_update->ip_id_offset;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	msn = context->co_fields.msn;
	/*first byte : 2 bits type and 3 bits msn and 3 bits ipid2
	 */
	*comp_hdr = ROHC_EXT_2 | ((msn & 0x7) << 3) | ((outer_ipid_offset >> 8) & 0x7);
	comp_hdr++;
	/*second byte : 8 bits ipid2
	 */
	*comp_hdr = outer_ipid_offset & 0xff;
	comp_hdr++;
	/*third byte : 8 bits ipid
	 */
	*comp_hdr = inner_ipid_offset & 0xff;
	encode_len += 3;
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;

}
static inline void rohc_comp_adjust_iph_udp_i_flags(struct comp_profile_v1_context *context,struct rohc_comp_packet_hdr_info *pkt_info,bool ip1,bool ip2)
{
	
}
static inline size_t rohc_comp_build_ext3_iph_flags(u8 *comp_hdr,struct iph_behavior_info *iph_bh,struct iph_update_info *iph_update,struct rohc_comp_packet_hdr_info *pkt_info,bool is_inner_iph,bool ip)
{
	struct iphdr *iph;
	u8 flags = 0;
	if(is_inner_iph)
		iph = &pkt_info->inner_iph;
	else
		iph = &pkt_info->iph;
	if(iph_update->tos_tc_update)
		flags |= ROHC_EXT_3_IPHF_TOS;
	if(iph_update->ttl_hl_update)
		flags |= ROHC_EXT_3_IPHF_TTL;
	/**
	 *df,nbo and rand only for ipv4
	 */
	if(rohc_iph_is_v4(iph->version)){
		if(iph_bh->df)
			flags |= 1 << 5;
		if(iph_bh->nbo)
			flags |= 1 << 2;
		if(iph_bh->rnd)
			flags |= 1 << 1;
	}
	if(pkt_info->has_inner_iph && !is_inner_iph && ip)
		flags |= 1 << 0;
	/**
	 *IPV6 is not supported currently. so IPX = 0. 
	 */
	/*distinguish context through protocol .so PR = 0
	 */
	*comp_hdr = flags;
	return 1;
}
static inline size_t rohc_comp_build_ext3_iph_fields(u8 *comp_hdr,struct iph_update_info *iph_update,struct rohc_comp_packet_hdr_info *pkt_info,bool is_inner_iph)
{
	struct iphdr *iph;
	size_t encode_len = 0;
	if(is_inner_iph)
		iph = &pkt_info->inner_iph;
	else
		iph = &pkt_info->iph;
	/**
	 * First TOS / TC
	 */
	if(iph_update->tos_tc_update){
		*comp_hdr = iph->tos;
		comp_hdr++;
		encode_len++;
	}
	/*second TTL/HL
	 */
	if(iph_update->ttl_hl_update){
		*comp_hdr = iph->ttl;
		comp_hdr++;
		encode_len++;
	}
	/*third ip extension headers for ipv6
	 */
	//TODO 
	return encode_len;

}
int rohc_comp_build_ext3(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct iphdr *outer_iph,*inner_iph;
	struct comp_profile_v1_context *v1_context;
	struct ip_context *ip_context;
	struct iph_update_info *outer_iph_update,*inner_iph_update;
	struct iph_behavior_info *outer_iph_bh,*inner_iph_bh;
	struct iph_oa_send_info *outer_oa_send_info,*inner_oa_send_info;
	struct msn_encode_bits	*msn_k_bits;
	bool s;
	bool i1;
	bool i2;
	bool ip1;
	bool ip2;
	bool ttl;
	bool tos;
 
	/**
	 *IPV6 is not supported currently. so IPX = 0. 
	 */
	bool ipx = false;
	/*distinguish context through protocol .so PR = 0
	 */
	bool pr = false;
	u16 outer_ipid_offset,inner_ipid_offset;
	u16 msn;
	int retval = 0;
	int encode_len = 0;
	size_t inline_encode_len;
	v1_context = context->prof_context;
	ip_context = &v1_context->ip_context;
	outer_iph = &pkt_info->iph;
	outer_iph_update = &ip_context->update_by_packet.iph_updates[ROHC_OUTER_IPH];
	outer_iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_OUTER_IPH];
	outer_oa_send_info = &ip_context->oa_send_pkts[ROHC_OUTER_IPH];
	msn_k_bits = &v1_context->msn_k_bits;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	msn = context->co_fields.msn;
	if(!msn_k_bits->can_encode_by_5_bit)
		s = true;
	else
		s = false;
	outer_ipid_offset = outer_iph_update->ip_id_offset;
	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		inner_iph_update = &ip_context->update_by_packet.iph_updates[ROHC_INNER_IPH];
		inner_oa_send_info = &ip_context->oa_send_pkts[ROHC_INNER_IPH];
		inner_iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_INNER_IPH];
		inner_ipid_offset = inner_iph_update->ip_id_offset;
		if(rohc_iph_is_v4(inner_iph->version) && !ip_id_is_random_or_constant(inner_iph_bh->ip_id_bh)){
			/* 1 .ip_id_offset is change ,if current ip-id offset from current  MSN and last
			 * ip-id offset from last MSN is euqal,need't to transmit the IP-ID-OFFSET.
			 * ip_id_offset_update =  cur_ip_id - cur_MSN == last_ip_id - last_MSN ? 1 : 0
			 * 2. if rand flag change to random ,and transmit times less than the optimistic
			 * approach times,should transmit.
			 */
			if(inner_iph_update->ip_id_offset_update || inner_iph_update->rnd_update)
				i1 = true;
			else
				i1 = false;
			if(rohc_iph_is_v4(outer_iph->version) && !ip_id_is_random_or_constant(outer_iph_bh->ip_id_bh)){
				if(outer_iph_update->ip_id_offset_update || outer_iph_update->rnd_update)
					i2 = true;
				else
					i2 = false;
			}else
				i2 = false;
		}else if(rohc_iph_is_v4(outer_iph->version) && !ip_id_is_random_or_constant(outer_iph_bh->ip_id_bh)){
			/*if only outer ip header is ipv4 header and is not random and is not constant,set ip2  zero.
			 */
			/* 1 .ip_id_offset is change ,if current ip-id offset from current  MSN and last
			 * ip-id offset from last MSN is euqal,need't to transmit the IP-ID-OFFSET.
			 * 2. if rand flag change to random ,and transmit times less than the optimistic
			 * approach times,should transmit.
			 */
			if(outer_iph_update->ip_id_offset_update || outer_iph_update->rnd_update)
				i1 = true;
			else
				i1 = false;
			i2 = false;
		}else{
			i1 = false;
			i2 = false;
		}
		if(iph_dynamic_fields_update(inner_iph_update))
			ip1 = true;
		else
			ip1 = false;
		/**
		 *i2 flag is inside outer ip header flags.
		 */
		if(iph_dynamic_fields_update(outer_iph_update) || i2)
			ip2 = true;
		else
			ip2 = false;
	}else{
		if(rohc_iph_is_v4(outer_iph->version) && !ip_id_is_random_or_constant(outer_iph_bh->ip_id_bh)){
			/*if only outer ip header is ipv4 header and is not random and is not constant,set ip2  zero.
			 */
			if(outer_iph_update->ip_id_offset_update || outer_iph_update->rnd_update)
				i1 = true;
			else 
				i1 = false;
		}else
			i1 = false;
		i2 = false;
		if(iph_dynamic_fields_update(outer_iph_update)){
			ip1 = true;
		}else{
			ip1 = false;
		}
		ip2 = false;
	}
	if(context->cid == 2)
		rohc_pr(ROHC_DUMP,"build ext3 : s=%d,i1=%d,ip1=%d,ip2=%d,i2=%d,nbo1=%d,rnd1=%d\n ",s,i1,ip1,ip2,i2,outer_iph_bh->nbo,outer_iph_bh->rnd);
	/*first.extension flags
	 */
	*comp_hdr = ROHC_EXT_3 | (context->mode & 0x3) << 3;
	if(s)
		*comp_hdr |= ROHC_EXT3_F_S;
	if(i1)
		*comp_hdr |= ROHC_EXT3_F_I;
	if(ip1)
		*comp_hdr |= ROHC_EXT3_F_IP;
	if(ip2)
		*comp_hdr |= ROHC_EXT3_F_IP2;
	comp_hdr++;
	encode_len++;
	/*second inner ip header flags.
	 */
	if(ip1){
		if(pkt_info->has_inner_iph){
			inline_encode_len = rohc_comp_build_ext3_iph_flags(comp_hdr,inner_iph_bh,inner_iph_update,pkt_info,true,i1);
			update_iph_oa_send_info_condition(inner_iph,inner_oa_send_info,inner_iph_update);
		}else{
			inline_encode_len = rohc_comp_build_ext3_iph_flags(comp_hdr,outer_iph_bh,outer_iph_update,pkt_info,false,i1);
			update_iph_oa_send_info_condition(outer_iph,outer_oa_send_info,outer_iph_update);
		}
		comp_hdr += inline_encode_len;
		encode_len += inline_encode_len;
	}
	/*third . outer ip header if there are two ip headers.
	 */
	if(ip2){
		inline_encode_len = rohc_comp_build_ext3_iph_flags(comp_hdr,outer_iph_bh,outer_iph_update,pkt_info,false,i2);
		update_iph_oa_send_info_condition(outer_iph,outer_oa_send_info,outer_iph_update);
		comp_hdr += inline_encode_len;
		encode_len += inline_encode_len;
	}
	/*four.SN
	 */

	if(s){
		*comp_hdr = msn & 0xff;
		encode_len++;
		comp_hdr++;
	}
	/*five inner ip header fileds
	 */
	if(ip1){
		if(pkt_info->has_inner_iph)
			inline_encode_len = rohc_comp_build_ext3_iph_fields(comp_hdr,inner_iph_update,pkt_info,true);
		else
			inline_encode_len = rohc_comp_build_ext3_iph_fields(comp_hdr,outer_iph_update,pkt_info,false);
		comp_hdr += inline_encode_len;
		encode_len += inline_encode_len;
	}
	/*six IP-ID if i1 = 1.
	 */
	if(i1){
		if(pkt_info->has_inner_iph){
			if(rohc_iph_is_v4(inner_iph->version) && !ip_id_is_random_or_constant(inner_iph_bh->ip_id_bh)){
				memcpy(comp_hdr,&inner_ipid_offset,sizeof(u16));
			}else{ 
				memcpy(comp_hdr,&outer_ipid_offset,sizeof(u16));
			}
		}else
			memcpy(comp_hdr,&outer_ipid_offset,sizeof(u16));
		comp_hdr += 2;
		encode_len += 2;
	}
	/*seven. outer ip header fileds
	 */
	if(ip2){
		inline_encode_len = rohc_comp_build_ext3_iph_fields(comp_hdr,outer_iph_update,pkt_info,false);
		comp_hdr += inline_encode_len;
		encode_len += inline_encode_len;
		if(i2){
			memcpy(comp_hdr,&outer_ipid_offset,sizeof(u16));
			comp_hdr += 2;
			encode_len += 2;
		}
	}
	skb_put(comp_skb,encode_len);
	pkt_info->comp_hdr_len += encode_len;
	return retval;
}

int rohc_comp_build_header_after_extensions(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct iphdr *outer_iph,*inner_iph;
	struct comp_profile_v1_context *v1_context;
	struct ip_context *ip_context;
	struct iph_packet_update *update_packet;
	struct iph_behavior_info *outer_ip_bh,*inner_ip_bh;
	int retval = 0;
	int encode_len = 0;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	v1_context = context->prof_context;
	ip_context = &v1_context->ip_context;
	update_packet = &ip_context->update_by_packet;
	outer_iph = &pkt_info->iph;
	outer_ip_bh = &update_packet->iph_behavior[ROHC_OUTER_IPH];

	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		inner_ip_bh = &update_packet->iph_behavior[ROHC_INNER_IPH];
	}
	
	/*1. if value(RAND2) = 1,fill the outer ipv4 ip-id.
	 */
	if(pkt_info->has_inner_iph){
		if((outer_iph->version == 4) && (outer_ip_bh->rnd)){
			memcpy(comp_hdr,&outer_iph->id,sizeof(u16));
			comp_hdr += sizeof(u16);
			encode_len += sizeof(u16);
		}
	}
	/*2.AH data for outet list
	 */
	/*3 GRE checksum
	 */
	/* 2 and 3 now not support.
	 */
	/*4.if value(RAND) = 1,fill the inner ipv4 ipid
	 */
	if(pkt_info->has_inner_iph){
		if(inner_iph->version == 4 && inner_ip_bh->rnd){
			memcpy(comp_hdr,&inner_iph->id,sizeof(u16));
			comp_hdr += sizeof(u16);
			encode_len += sizeof(u16);
		}
	}else{/*if only one ip header.fill the outer iph here.*/
		if(outer_iph->version == 4 && outer_ip_bh->rnd){
			memcpy(comp_hdr,&outer_iph->id,sizeof(16));
			comp_hdr += sizeof(u16);
			encode_len += sizeof(u16);
		}
	}
	/*5.AH data for inner list.
	 */
	/*6.GRE checksum
	 */
	/*5 and 6 now not support./
	 */

	pkt_info->comp_hdr_len += encode_len;
	rohc_pr(ROHC_DEBUG,"before prof : comp_len=%d,encode_len=%d\n",pkt_info->comp_hdr_len,encode_len);
	skb_put(comp_skb,encode_len);
	if(context->comp_profile->pro_ops->build_profile_header)
		retval = context->comp_profile->pro_ops->build_profile_header(context,skb,pkt_info);
	return retval;	

}
int rohc_comp_build_uo0(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	unsigned char *comp_hdr;
	unsigned char *payload;
	struct ethhdr *eth;
	struct sk_buff *comp_skb;
	struct rohc_compresser *rohc_comp; 
	struct comp_profile_v1_context *v1_context;
	struct rohc_comp_context_common_fields *common_fields;
	int cid_encode_len;
	u16 cid;
	u32 msn;
	u8 crc;
	int pad_locat;
	int retval = 0;
	comp_skb = context->comp_skb;
	rohc_comp = context->compresser;
	common_fields = &context->co_fields;
	v1_context = context->prof_context;
	cid = context->cid;
	comp_hdr = skb_tail_pointer(comp_skb);
	/*Ethernet header add before rohc header.
	 */
	if(context->comp_eth_hdr && !comp_skb->len){
		eth = eth_hdr(skb);
		memcpy(comp_hdr,eth,sizeof(struct ethhdr));
		pkt_info->comp_hdr_len += sizeof(struct ethhdr);
		comp_hdr += sizeof(struct ethhdr);
	}
	pad_locat = pkt_info->comp_hdr_len;
	msn = common_fields->msn;
	/**
	 *TODO caculate uncompressed packet crc.default not use crc.
	 */
	crc = 0;
	if(rohc_comp->cid_type == CID_TYPE_SMALL){
		retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		comp_hdr += cid_encode_len;

		*comp_hdr = ROHC_PACKET_UO_0 | ((msn & 0xf) << 3) | (crc & 0x7);
		rohc_pr(ROHC_DEBUG,"%s : msn=%d[%d],comp=%x\n",__func__,msn,msn & 0xf,*comp_hdr);
		comp_hdr++;

	}else{
		*comp_hdr = ROHC_PACKET_UO_0 | ((msn & 0xf) << 3) | (crc & 0x7);
		comp_hdr++;
		retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		comp_hdr += cid_encode_len;
		
	}
	pkt_info->comp_hdr_len += cid_encode_len + 1;
	skb_put(comp_skb,pkt_info->comp_hdr_len);
	/*
	 *add IP-ID if ip id behavior is random.packet u0 not support extensions
	 */
	retval = rohc_comp_build_header_after_extensions(context,skb,pkt_info);
	if(retval)
		pr_err("%s : context-%d,profile-%x encode header after extensions error\n",__func__,context->cid,\
				context->comp_profile->profile);
	else{
		/*align to two bytes
		 */
		if((pkt_info->to_comp_pkt_hdr_len & 0x1) != (pkt_info->comp_hdr_len & 0x1)){
			memmove(comp_skb->data + pad_locat + 1,comp_skb->data + pad_locat,pkt_info->comp_hdr_len - pad_locat);
			skb_put(comp_skb,1);
			comp_hdr = comp_skb->data + pad_locat;
			*comp_hdr = ROHC_PACKET_PADDING;
			rohc_pr(ROHC_DEBUG,"%s:add pading,to_comp_pkt_hdr_len=%d,comp_hdr_len=%d\n",__func__,pkt_info->to_comp_pkt_hdr_len,pkt_info->comp_hdr_len);
			rohc_pr(ROHC_DEBUG,"%s : pading=%x,skblen=%d\n",__func__,*(comp_skb->data + 14),comp_skb->len);
			pkt_info->comp_hdr_len++;
		}
	}

out:
	return retval;
}

int rohc_comp_build_uo1(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	unsigned char *comp_hdr;
	unsigned char *payload;
	struct ethhdr *eth;
	struct iphdr *outer_iph,*inner_iph;
	struct sk_buff *comp_skb;
	struct rohc_compresser *rohc_comp; 
	struct comp_profile_v1_context *v1_context;
	struct iph_update_info *outer_ip_change,*inner_ip_change;
	struct iph_behavior_info *outer_ip_bh,*inner_ip_bh;
	struct iph_packet_update *update_packet;
	struct iph_encode_ipid_bits *encode_bits;
	struct rohc_comp_context_common_fields *common_fields;
	int cid_encode_len;
	u16 cid;
	u16 ip_id_offset;
	u32 msn;
	u8 crc;
	int pad_locat;
	int retval = 0;
	int encode_len = 0;
	comp_skb = context->comp_skb;
	rohc_comp = context->compresser;
	common_fields = &context->co_fields;
	v1_context = context->prof_context;
	update_packet = &v1_context->ip_context.update_by_packet;
	cid = context->cid;
	comp_hdr = skb_tail_pointer(comp_skb);
	/*
	 *UDP UO-1 packet header(IP-ID) priority to carray internal ipv4h ip-id when there are two ip header in context and outer iph is not ipv4 ,or outer ip header ipid is random or constant id.
	 *if inner ipv4h is constant id,the should carray the outer iph ipid.
	 *if only one ip header ,carray the ip id.
	 *if there are not any ipv4 header is not random,can't use the packet.
	 */
	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		outer_iph = &pkt_info->iph;
		inner_ip_change = &update_packet->iph_updates[ROHC_INNER_IPH];
		outer_ip_change = &update_packet->iph_updates[ROHC_OUTER_IPH];
		inner_ip_bh = &update_packet->iph_behavior[ROHC_INNER_IPH];
		if((rohc_iph_is_v4(inner_iph->version)) && !ip_id_is_random(inner_ip_bh->ip_id_bh) && !ip_id_is_constant(inner_ip_bh->ip_id_bh))
			ip_id_offset = inner_ip_change->ip_id_offset;
		else{
			BUG_ON((!rohc_iph_is_v4(outer_iph->version)) || (ip_id_is_random(inner_ip_bh->ip_id_bh)) || (ip_id_is_constant(outer_ip_bh->ip_id_bh)));
			ip_id_offset = outer_ip_change->ip_id_offset;
		}
	}else{
		outer_iph = &pkt_info->iph;
		outer_ip_bh = &update_packet->iph_behavior[ROHC_INNER_IPH];
		outer_ip_change = &update_packet->iph_updates[ROHC_OUTER_IPH];
		//BUG_ON((outer_iph->version != 4) || (outer_ip_bh->rnd) || (!out));
		ip_id_offset = outer_ip_change->ip_id_offset;
	}
	/*Ethernet header add before rohc header.
	 */
	if(context->comp_eth_hdr && !comp_skb->len){
		eth = eth_hdr(skb);
		memcpy(comp_hdr,eth,sizeof(struct ethhdr));
		pkt_info->comp_hdr_len += sizeof(struct ethhdr);
		comp_hdr += sizeof(struct ethhdr);
	}
	pad_locat = pkt_info->comp_hdr_len;
	msn = common_fields->msn;
	/**
	 *TODO caculate uncompressed packet crc.default not use crc.
	 */
	crc = 0;
	if(rohc_comp->cid_type == CID_TYPE_SMALL){
		retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		comp_hdr += cid_encode_len;
		encode_len += cid_encode_len;
		/*first byte: 2 bits type and 6 bits ip_id_offet.
		 */
		*comp_hdr = ROHC_PACKET_UO_1 | (ip_id_offset & 0x3f); //| ((msn & 0xf) << 3) | (crc & 0x7);
		comp_hdr++;
		/*second byte : 5 bits sn and 3 bits crc
		 */
		*comp_hdr = ((msn & 0x1f) << 3) | (crc & 0x7);
		comp_hdr++;
		encode_len += 2;


	}else{

		/*first byte: 2 bits type and 6 bits ip_id_offet. and second bytes cross tbe cid info.
		 */
		*comp_hdr = ROHC_PACKET_UO_1 | (ip_id_offset & 0x3f);
		comp_hdr++;
		retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		comp_hdr += cid_encode_len;
		/*second byte : 5 bits sn and 3 bits crc
		 */
		*comp_hdr = ((msn & 0x1f) << 3) | (crc & 0x7);
		encode_len += cid_encode_len + 2;
	}
	pkt_info->comp_hdr_len += encode_len;
	skb_put(comp_skb,pkt_info->comp_hdr_len);
	/*
	 *add IP-ID if ip id behavior is random.packet u0 not support extensions
	 */
	retval = rohc_comp_build_header_after_extensions(context,skb,pkt_info);
	if(retval)
		pr_err("%s : context-%d,profile-%x encode header after extensions error\n",__func__,context->cid,\
				context->comp_profile->profile);
	else{
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

static inline void rohc_comp_encode_uor2_sn(struct comp_profile_v1_context *context,u8 *sn,u16 msn,enum rohc_ext_type ext_type)
{
	struct  msn_encode_bits *msn_k;
	u8 sn_byte;
	msn_k = &context->msn_k_bits;

	switch(ext_type){
		case EXT_TYPE_NONE:
			sn_byte = 0;
			break;
		case EXT_TYPE_0:
		case EXT_TYPE_1:
		case EXT_TYPE_2:
			/*big endian ,high bits in the low address.
			 */
			sn_byte = (msn >> 3) & 0x1f;
			break;
		case EXT_TYPE_3:
			/*if the msn can encode by k  = 5 bits,so the extension need not carray the SN(S = 0)
			 */
			if(msn_k->can_encode_by_5_bit)
				sn_byte = msn & 0x1f;
			else
				sn_byte = (msn >> 8) & 0x1f;
			break;
		default:
			pr_err("%s : error extensions type\n",__func__);
			break;
	}
	*sn = sn_byte;
}
int rohc_comp_build_uor2(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	unsigned char *comp_hdr;
	unsigned char *payload;
	struct ethhdr *eth;
	struct iphdr *outer_iph,*inner_iph;
	struct sk_buff *comp_skb;
	struct rohc_compresser *rohc_comp; 
	struct comp_profile_v1_context *v1_context;
	struct rohc_comp_context_common_fields *common_fields;
	enum rohc_ext_type ext_type;
	int cid_encode_len;
	u16 cid;
	u32 msn;
	u8 crc;
	u8 sn_byte;
	int pad_locat;
	int retval = 0;
	int encode_len = 0;
	comp_skb = context->comp_skb;
	rohc_comp = context->compresser;
	common_fields = &context->co_fields;
	v1_context = context->prof_context;
	cid = context->cid;
	ext_type = v1_context->packet_info.ext_type;
	comp_hdr = skb_tail_pointer(comp_skb);
	/*Ethernet header add before rohc header.
	 */
	if(context->comp_eth_hdr && !comp_skb->len){
		eth = eth_hdr(skb);
		memcpy(comp_hdr,eth,sizeof(struct ethhdr));
		pkt_info->comp_hdr_len += sizeof(struct ethhdr);
		comp_hdr += sizeof(struct ethhdr);
	}
	pad_locat = pkt_info->comp_hdr_len;
	msn = common_fields->msn;
	/**
	 *TODO caculate uncompressed packet crc.default not use crc.
	 */
	crc = 0;
	rohc_comp_encode_uor2_sn(v1_context,&sn_byte,msn,ext_type);
	if(rohc_comp->cid_type == CID_TYPE_SMALL){
		retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		comp_hdr += cid_encode_len;
		/*first byte: 3 bits type and 5 bits SN.
		 */
		*comp_hdr = ROHC_PACKET_URO_2 | (sn_byte & 0x1f);
		comp_hdr++;
		/*second byte : 1 bits X bit  and 7 bits crc
		 */
		if(ext_type != EXT_TYPE_NONE)
			*comp_hdr = ROHC_CARRAY_EXT | (crc & 0x7f);
		else
			*comp_hdr = crc & 0x7f;
		comp_hdr++;
		encode_len += 2 + cid_encode_len;


	}else{

		/*first byte: 3 bits type and 5 bits SN. and second bytes cross tbe cid info.
		 */
		*comp_hdr = ROHC_PACKET_URO_2 | (sn_byte & 0x1f);
		comp_hdr++;
		retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
		if(retval)
			goto out;
		comp_hdr += cid_encode_len;
		/*second byte : 1 bit X bit  and 7 bits crc
		 */
		if(ext_type != EXT_TYPE_NONE)
			*comp_hdr = ROHC_CARRAY_EXT | (crc & 0x7f);
		else
			*comp_hdr = crc & 0x7f;
		encode_len += cid_encode_len + 2;
	}
	pkt_info->comp_hdr_len += encode_len;
	skb_put(comp_skb,pkt_info->comp_hdr_len);
	/*
	 *next add extension if extension type is not EXT_TYPE_NONE. 
	 */
	if(ext_type != EXT_TYPE_NONE){
		retval = v1_context->prof_v1_ops->bulid_extension(context,pkt_info);
		if(retval)
			goto out;
	}
	/**
	 * next bulil the remain header after extensions
	 */
	retval = rohc_comp_build_header_after_extensions(context,skb,pkt_info);
	if(!retval){
		if((pkt_info->to_comp_pkt_hdr_len & 0x1) != (pkt_info->comp_hdr_len & 0x1)){
			memmove(comp_skb->data + pad_locat + 1,comp_skb->data + pad_locat,pkt_info->comp_hdr_len - pad_locat);
			skb_put(comp_skb,1);
			comp_hdr = comp_skb->data + pad_locat;
			*comp_hdr = ROHC_PACKET_PADDING;
			pkt_info->comp_hdr_len++;
		}
	}
	if(context->cid == 2)
		rohc_pr(ROHC_DUMP,"build ur2 len = %d\n",comp_skb->len - 14);
out:
	return retval;
}


static inline int rohc_comp_build_ip_static_field(u8 *comp_hdr,struct iphdr *iph)
{
	struct ipv6hdr *ipv6h;
	struct ip_static_fields *static_part;
	if(rohc_iph_is_v4(iph->version)){
		static_part = (struct ip_static_fields *)comp_hdr;
		static_part->version = iph->version & 0xf;
		static_part->protocol = iph->protocol;
		static_part->saddr = iph->saddr;
		static_part->daddr = iph->daddr;
		return sizeof(struct ip_static_fields);
	}else{
		//IPV6
		ipv6h = (struct ipv6hdr *)iph;
	}
	return 0;
}

static inline int rohc_comp_build_ip_dynamic_field(u8 *comp_hdr,struct iphdr *iph,struct iph_behavior_info *iph_bh)
{
	struct ipv6hdr *ipv6h;
	struct ip_dynamic_fields *dynamic_part;

	if(rohc_iph_is_v4(iph->version)){
		dynamic_part = (struct ip_dynamic_fields *)comp_hdr;
		dynamic_part->tos = iph->tos;
		dynamic_part->ttl = iph->ttl;
		dynamic_part->ip_id = iph->id;
		dynamic_part->df = !!(ntohs(iph->frag_off) & IP_DF);
		dynamic_part->rnd = !!iph_bh->rnd;
		dynamic_part->nbo = !!iph_bh->nbo;
		dynamic_part->constant = !!iph_bh->constant;
		return sizeof(struct ip_dynamic_fields);
	}else{
		//ipv6
		ipv6h = (struct ipv6hdr *)iph;
	};
	return 0;
}
int rohc_comp_build_ip_static_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct iphdr *iph;
	struct sk_buff *comp_skb;
	int encode_len = 0;
	int retval = 0;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	iph = &pkt_info->iph;

	encode_len = rohc_comp_build_ip_static_field(comp_hdr,iph);
	comp_hdr += encode_len;
	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		encode_len += rohc_comp_build_ip_static_field(comp_hdr,iph);
		comp_hdr += encode_len;
	}
	pkt_info->comp_hdr_len += encode_len;
	skb_put(comp_skb,encode_len);
	return retval;
}

int rohc_comp_build_ip_dynamic_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct iphdr *iph;
	struct sk_buff *comp_skb;
	struct comp_profile_v1_context *v1_context;
	struct iph_packet_update *update_packet;
	struct iph_behavior_info *outer_iph_bh,*inner_iph_bh;
	struct iph_oa_send_info *outer_oa_send_info,*inner_oa_send_info;
	int encode_len = 0;
	int retval = 0;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	v1_context = context->prof_context;
	update_packet = &v1_context->ip_context.update_by_packet;
	iph = &pkt_info->iph;
	outer_iph_bh = &update_packet->iph_behavior[ROHC_OUTER_IPH];
	outer_oa_send_info = &v1_context->ip_context.oa_send_pkts[ROHC_OUTER_IPH];
	encode_len += rohc_comp_build_ip_dynamic_field(comp_hdr,iph,outer_iph_bh);
	update_iph_oa_send_info_all(outer_oa_send_info);
	comp_hdr += encode_len;
	if(pkt_info->has_inner_iph){
		iph = &pkt_info->inner_iph;
		inner_iph_bh = &update_packet->iph_behavior[ROHC_INNER_IPH];
		inner_oa_send_info = &v1_context->ip_context.oa_send_pkts[ROHC_INNER_IPH];
		encode_len += rohc_comp_build_ip_dynamic_field(comp_hdr,iph,inner_iph_bh);
		comp_hdr += encode_len;
		update_iph_oa_send_info_all(inner_oa_send_info);
	}
	pkt_info->comp_hdr_len += encode_len;
	skb_put(comp_skb,encode_len);
	return retval;
}

int rohc_comp_build_udp_static_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct udphdr *udph;
	struct udp_static_fields *udp_static_part;
	struct sk_buff *comp_skb;

	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	udph = &pkt_info->udph;
	udp_static_part = (struct udp_static_fields *)comp_hdr;
	udp_static_part->sport = udph->source;
	udp_static_part->dport = udph->dest;
	skb_put(comp_skb,sizeof(struct udp_static_fields));
	pkt_info->comp_hdr_len += sizeof(struct udp_static_fields);
	return 0;
}

int rohc_comp_build_udp_dynamic_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct udphdr *udph;
	struct sk_buff *comp_skb;
	struct udp_dynamic_fields *dynamic_part;
	u16 msn;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	udph = &pkt_info->udph;
	msn = context->co_fields.msn;
	dynamic_part = (struct udp_dynamic_fields *)comp_hdr;
	dynamic_part->checksum = udph->check;
	dynamic_part->msn = msn;
	pkt_info->comp_hdr_len += sizeof(struct udp_dynamic_fields);
	skb_put(comp_skb,sizeof(struct udp_dynamic_fields));
	return 0;
}

int rohc_comp_feedack_ack(struct rohc_comp_context *context ,u32 msn,int sn_bit_width,bool sn_valid)
{
	struct iphdr *iph;
	struct comp_profile_v1_ops *v1_ops;
	struct comp_profile_v1_context *v1_context;
	struct ip_context *ip_context;
	struct iph_save_info *last_iph_info;
	struct comp_win_lsb *ipid_wlsb;
	int i,ack_num;
	v1_context =  context->prof_context;
	v1_ops = v1_context->prof_v1_ops;
	ip_context = &v1_context->ip_context;
	last_iph_info = &ip_context->last_context_info.iph_info;
	if(sn_valid)
		ack_num = comp_wlsb_ack(v1_context->msn_wlsb,sn_bit_width,msn);
	if(context->context_state != COMP_STATE_SO){
		rohc_comp_context_change_state(context,COMP_STATE_SO);
	}
	if(sn_valid){
		for(i = 0 ; i < last_iph_info->iph_num ;i++){
			if(i == ROHC_OUTER_IPH)
				iph = &last_iph_info->iph;
			else
				iph = &last_iph_info->inner_iph;
			if(iph->version == 4){
				ipid_wlsb = ip_context->ip_id_wlsb[i];
				comp_wlsb_ack(ipid_wlsb,sn_bit_width,msn);
			}
		}
	}
	if(v1_ops && v1_ops->feedback_input)
		v1_ops->feedback_input(context,ROHC_FEEDBACK_ACK,msn,sn_bit_width,sn_valid);
	return 0;
}

int rohc_comp_feedack_ack1(struct rohc_comp_context *context,struct sk_buff *skb,int feedback_size)
{
	u8 *data;
	u32 msn;
	int msn_mask_bit;
	data = skb->data;
	msn = (*data) & 0xff;
	msn_mask_bit = 8;
	if(context->mode != ROHC_MODE_O)
		rohc_comp_context_change_mode(context,ROHC_MODE_O);
	rohc_comp_feedack_ack(context,msn,msn_mask_bit,true);
	skb_pull(skb,feedback_size);
	return 0;
}
int rohc_comp_feedack_ack2(struct rohc_comp_context *context,struct sk_buff *skb,int feedback_size)
{
	u8 *data;
	struct comp_profile_v1_context *v1_context;
	struct comp_profile_v1_ops *v1_ops;
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
	v1_context = context->prof_context;
	v1_ops = v1_context->prof_v1_ops;
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
	//if(context->cid == 2)
	rohc_pr(ROHC_DUMP , "cid=%d , recved feedback ,type=%d,feedback_size=%d,msn=%d,mode=%d\n",context->cid,ack_type,feedback_size,msn,mode);
	rohc_feeback_parse_options(skb,&option_compile,prof,feedback_size);
	sn_mask_bits += option_compile.sn_opt_bits;
	msn = option_compile.sn;
	if(option_compile.option_apprear[FEEDBACK_OPTION_TYPE_UNVALID_SN] > 0)
		sn_valid = false;
	switch(ack_type){
		case ROHC_FEEDBACK_ACK:
			rohc_comp_feedack_ack(context,msn,sn_mask_bits,sn_valid);
			break;
		case ROHC_FEEDBACK_NACK:
			if(context->context_state == COMP_STATE_SO){
				rohc_comp_context_change_state(context,COMP_STATE_FO);
				if(v1_ops && v1_ops->feedback_input)
					v1_ops->feedback_input(context,ack_type,msn,sn_mask_bits,sn_valid);
			}
			break;
		case ROHC_FEEDBACK_STATIC_NACK:
			rohc_comp_context_change_state(context,COMP_STATE_IR);
			if(v1_ops && v1_ops->feedback_input)
				v1_ops->feedback_input(context,ack_type,msn,sn_mask_bits,sn_valid);
			break;
	}
	return 0;
}
int rohc_comp_feedback_input(struct rohc_comp_context *context,struct sk_buff *skb,int cid_len,int feeback_size)
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
		rohc_comp_feedack_ack1(context,skb,feeback_size);
	else if(feeback_size > 1)
		rohc_comp_feedack_ack2(context,skb,feeback_size);
	else{
		pr_err("context-%d,profile-%x recieved the size zero feedback\n",context->cid,prof);
		retval = -EFAULT;
	}

out:
	return retval;
}
