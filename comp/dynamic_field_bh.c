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
#include <linux/module.h>
#include <linux/types.h>
#include <linux/swab.h>
#include <net/ip.h>

#include "../rohc_common.h"
#include "../lsb.h"
#include "../rohc_profile.h"
#include "../rohc_packet.h"
#include "../rohc_ipid.h"
#include "rohc_comp.h"
#include "dynamic_field_bh.h"

void ip_id_behavior_probe(struct ip_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	int i;
	int retval;
	u16 new_ipid;
	u16 old_ipid;
	struct iph_context_info *iph_context_info;
	struct iph_packet_update *update;
	struct iph_behavior_info *iph_bh;
	struct iph_save_info *iph_info;
	struct iphdr *new_iph,*old_iph;
	update = &ip_context->update_by_packet;
	iph_context_info = &ip_context->last_context_info;
	iph_info = &iph_context_info->iph_info;
	for(i = 0 ; i < pkt_info->iph_num ; i++){
		iph_bh = &update->iph_behavior[i];
		if(i == ROHC_OUTER_IPH){
			new_iph = &pkt_info->iph;
			old_iph = &iph_info->iph;
		}else{
			new_iph = &pkt_info->inner_iph;
			old_iph = &iph_info->inner_iph;
		}
		if(rohc_iph_is_v4(new_iph->version)){
	//		rohc_pr(ROHC_DEBUG,"i=%d,new_ipid=%d,old_ipid=%d,df=%d\n",i,ntohs(new_iph->id),ntohs(old_iph->id));
			iph_bh->df = !!(ntohs(new_iph->frag_off) & IP_DF);
			rohc_pr(ROHC_DEBUG,"i=%d,new_ipid=%d,old_ipid=%d,df=%d\n",i,ntohs(new_iph->id),ntohs(old_iph->id),iph_bh->df);
			if(ip_context->is_first_packet){
				/**
				 *if the packet is first packet,assume nbo = 1,rand = 0,id_change = 0.
				 */
				iph_bh->ip_id_bh = IP_ID_BEHAVIOR_SEQ_NBO;
				iph_bh->nbo = true;
				iph_bh->rnd = false;
				iph_bh->constant = false;
			}else{
				new_ipid = ntohs(new_iph->id);
				old_ipid = ntohs(old_iph->id);
				if(new_ipid == old_ipid){
					iph_bh->ip_id_bh = IP_ID_BEHAVIOR_CONSTANT;
					iph_bh->nbo = true;
					iph_bh->rnd = false;
					iph_bh->constant = true;
				}else if(ip_id_mon_increasing(new_ipid,old_ipid,20)){
					iph_bh->ip_id_bh = IP_ID_BEHAVIOR_SEQ_NBO;
					iph_bh->nbo = true;
					iph_bh->rnd = false;
					iph_bh->constant = false;
				}else{
					new_ipid = __swab16(new_ipid);
					old_ipid = __swab16(old_ipid);
					if(ip_id_mon_increasing(new_ipid,old_ipid,20)){
						iph_bh->ip_id_bh = IP_ID_BEHAVIOR_SEQ_SWAP;
						iph_bh->nbo = false;
						iph_bh->rnd = false;
						iph_bh->constant = false;
					}else{
						iph_bh->ip_id_bh = IP_ID_BEHAVIOR_RANDOM;
						iph_bh->nbo = true;
						iph_bh->rnd = true;
						iph_bh->constant = false;
					}
				}
			}
		}
		rohc_pr(ROHC_DUMP,"ip_id_bh = %d,nbo=%d,rnd=%d,constant=%d\n",iph_bh->ip_id_bh,iph_bh->nbo,iph_bh->rnd,iph_bh->constant);
	#if 0
		iph_bh->ip_id_bh = IP_ID_BEHAVIOR_RANDOM;
		iph_bh->nbo = true;
		iph_bh->rnd = true;
		iph_bh->constant = false;
	#endif
	}

}

static inline void iph_update_probe(struct iphdr *new_iph,struct iphdr *old_iph,struct iph_behavior_info *new_iph_bh,struct iph_behavior_info *old_iph_bh,struct iph_update_info *iph_update,struct iph_oa_send_info *oa_send_pkts,int max_oa)
{
	if(new_iph->tos != old_iph->tos){
		iph_update->tos_tc_update = true;
		oa_send_pkts->tos_tc_send_pkts = 0;
	}else if(oa_send_pkts->tos_tc_send_pkts < max_oa)
		iph_update->tos_tc_update = true;
	else
		iph_update->tos_tc_update = false;

	if(new_iph->ttl != old_iph->ttl){
		iph_update->ttl_hl_update = true;
		oa_send_pkts->ttl_hl_send_pkts = 0;
	}else if(oa_send_pkts->ttl_hl_send_pkts < max_oa)
		iph_update->ttl_hl_update = true;
	else
		iph_update->ttl_hl_update = false;
	if((ntohs(new_iph->frag_off) & IP_DF) != (ntohs(old_iph->frag_off) & IP_DF)){
		iph_update->df_update = true;
		oa_send_pkts->df_send_pkts = 0;
	}else if(oa_send_pkts->df_send_pkts < max_oa)
		iph_update->df_update = true;
	else
		iph_update->df_update = false;
	if(new_iph_bh->nbo != old_iph_bh->nbo){
		iph_update->nbo_update = true;
		oa_send_pkts->nbo_send_pkts = 0;
	}else if(oa_send_pkts->nbo_send_pkts < max_oa)
		iph_update->nbo_update = true;
	else
		iph_update->nbo_update = false;
	if(new_iph_bh->rnd != old_iph_bh->rnd){
		iph_update->rnd_update = true;
		oa_send_pkts->rnd_send_pkts = 0;
	}else if(oa_send_pkts->rnd_send_pkts < max_oa)
		iph_update->rnd_update = true;
	else
		iph_update->rnd_update = false;
	if(new_iph_bh->constant != old_iph_bh->constant){
		iph_update->constant_update = true;
		oa_send_pkts->const_send_pkts = 0;
	}else if(oa_send_pkts->const_send_pkts < max_oa)
		iph_update->constant_update = true;
	else
		iph_update->constant_update = false;
}
void iph_update_probes(struct ip_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info,int max_oa)
{
	struct iphdr *outer_iph,*inner_iph,*old_iph;
	struct iph_behavior_info *outer_iph_bh,*inner_iph_bh,*old_iph_bh;
	struct iph_update_info *outer_iph_update,*inner_iph_update;
	struct iph_oa_send_info *outer_oa_pkts,*inner_oa_pkts;
	struct iph_save_info *iph_info;
	iph_info = &ip_context->last_context_info.iph_info;
	outer_iph = &pkt_info->iph;
	old_iph = &iph_info->iph;
	old_iph_bh = &ip_context->last_context_info.iph_behavior[ROHC_OUTER_IPH];
	outer_iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_OUTER_IPH];
	outer_iph_update = &ip_context->update_by_packet.iph_updates[ROHC_OUTER_IPH];
	outer_oa_pkts = &ip_context->oa_send_pkts[ROHC_OUTER_IPH];
	if(rohc_iph_is_v4(outer_iph->version))
		iph_update_probe(outer_iph,old_iph,outer_iph_bh,old_iph_bh,outer_iph_update,outer_oa_pkts,max_oa);
	else{
		//IPV6 ip header probe.
	}
	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		old_iph = &iph_info->inner_iph;
		inner_iph_bh =&ip_context->update_by_packet.iph_behavior[ROHC_INNER_IPH];
		old_iph_bh = &ip_context->last_context_info.iph_behavior[ROHC_INNER_IPH];
		inner_iph_update = &ip_context->update_by_packet.iph_updates[ROHC_INNER_IPH];
		inner_oa_pkts = &ip_context->oa_send_pkts[ROHC_INNER_IPH];
		if(rohc_iph_is_v4(inner_iph->version))
			iph_update_probe(inner_iph,old_iph,inner_iph_bh,old_iph_bh,inner_iph_update,inner_oa_pkts,max_oa);
		else{
			//IPV6 ip header probe.
		}
	}

}
/*The 
 */
static inline void ip_id_udp_k_bits_probe(struct comp_win_lsb *wlsb,struct iph_encode_ipid_bits *k_bits,u16 ip_id_off)
{
	//u32 ipid_ref;
	//rohc_comp_wlsb_peek_last_val(wlsb,&ipid_ref);
	k_bits->can_encode_by_3_bit = comp_wlsb_can_encode_type_ushort(wlsb,3,ROHC_LSB_IPID_P,ip_id_off);
	k_bits->can_encode_by_6_bit = comp_wlsb_can_encode_type_ushort(wlsb,6,ROHC_LSB_IPID_P,ip_id_off);
	k_bits->can_encode_by_8_bit = comp_wlsb_can_encode_type_ushort(wlsb,8,ROHC_LSB_IPID_P,ip_id_off);
	k_bits->can_encode_by_11_bit = comp_wlsb_can_encode_type_ushort(wlsb,11,ROHC_LSB_IPID_P,ip_id_off);
}

static inline void ip_id_rtp_k_bits_probe(struct comp_win_lsb *wlsb,struct iph_encode_ipid_bits *k_bits,u16 ip_id_off)
{
	k_bits->can_encode_by_3_bit = comp_wlsb_can_encode_type_ushort(wlsb,3,ROHC_LSB_IPID_P,ip_id_off);
	k_bits->can_encode_by_5_bit = comp_wlsb_can_encode_type_ushort(wlsb,5,ROHC_LSB_IPID_P,ip_id_off);
	k_bits->can_encode_by_6_bit = comp_wlsb_can_encode_type_ushort(wlsb,6,ROHC_LSB_IPID_P,ip_id_off);
	k_bits->can_encode_by_8_bit = comp_wlsb_can_encode_type_ushort(wlsb,8,ROHC_LSB_IPID_P,ip_id_off);
	k_bits->can_encode_by_11_bit = comp_wlsb_can_encode_type_ushort(wlsb,11,ROHC_LSB_IPID_P,ip_id_off);
	k_bits->can_encode_by_16_bit = true;
}
void ip_id_k_bits_probes(struct ip_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info,enum rohc_profile prof)
{
	struct iphdr *outer_iph,*inner_iph;
	struct comp_win_lsb *outer_ipid_wlsb,*inner_ipid_wlsb;
	struct iph_encode_ipid_bits *outer_ipid_k_bits,*inner_ipid_k_bits;
	struct iph_update_info *outer_iph_update,*inner_iph_update;
	struct iph_behavior_info *outer_iph_bh,*inner_iph_bh;
	outer_ipid_wlsb = ip_context->ip_id_wlsb[ROHC_OUTER_IPH];
	outer_iph_update = &ip_context->update_by_packet.iph_updates[ROHC_OUTER_IPH];
	outer_iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_OUTER_IPH];
	outer_ipid_k_bits = &ip_context->update_by_packet.ipid_k_bits[ROHC_OUTER_IPH];
	u16 ip_id_offset;
	u32 last_ipid_ref;
	outer_iph = &pkt_info->iph;

	if(rohc_iph_is_v4(outer_iph->version) && !ip_id_is_random_or_constant(outer_iph_bh->ip_id_bh)){
		ip_id_offset = outer_iph_update->ip_id_offset;
		if(rohc_comp_wlsb_peek_last_val(outer_ipid_wlsb,&last_ipid_ref)){
			outer_iph_update->ip_id_offset_update = false;
		}else{
			if(ip_id_offset != last_ipid_ref)
				outer_iph_update->ip_id_offset_update = true;
			else
				outer_iph_update->ip_id_offset_update = false;
		}
		switch(prof){
			case ROHC_V1_PROFILE_UDP:
				ip_id_udp_k_bits_probe(outer_ipid_wlsb,outer_ipid_k_bits,ip_id_offset);
				break;
			case ROHC_V1_PROFILE_RTP:
				ip_id_rtp_k_bits_probe(outer_ipid_wlsb,outer_ipid_k_bits,ip_id_offset);
				break;
			default:
				break;
		}
	}
	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		if(rohc_iph_is_v4(inner_iph->version) && !ip_id_is_random_or_constant(inner_iph_bh->ip_id_bh)){
			inner_ipid_wlsb = ip_context->ip_id_wlsb[ROHC_INNER_IPH];
			inner_iph_update = &ip_context->update_by_packet.iph_updates[ROHC_INNER_IPH];
			inner_iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_OUTER_IPH];
			inner_ipid_k_bits = &ip_context->update_by_packet.ipid_k_bits[ROHC_INNER_IPH];
			ip_id_offset = inner_iph_update->ip_id_offset;
			if(rohc_comp_wlsb_peek_last_val(inner_ipid_wlsb,&last_ipid_ref)){
				inner_iph_update->ip_id_offset_update = false;
			}else{
				if(ip_id_offset != last_ipid_ref)
					inner_iph_update->ip_id_offset_update = true;
				else
					inner_iph_update->ip_id_offset_update = false;
			}
			switch(prof){
				case ROHC_V1_PROFILE_UDP:
					ip_id_udp_k_bits_probe(outer_ipid_wlsb,outer_ipid_k_bits,ip_id_offset);
					break;
				case ROHC_V1_PROFILE_RTP:
					ip_id_rtp_k_bits_probe(outer_ipid_wlsb,outer_ipid_k_bits,ip_id_offset);
					break;
				default:
					break;
			}
		}
	}
}



void iph_update_context(struct ip_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info,u32 msn)
{
	struct iphdr *outer_iph,*inner_iph;
	struct iph_context_info *last_info;
	struct iph_save_info *iph_save;
	struct iph_behavior_info *to_iph_bh,*from_iph_bh;
	struct iph_update_info *iph_update;
	struct comp_win_lsb *wlsb;
	last_info = &ip_context->last_context_info;
	iph_save = &last_info->iph_info;
	iph_save->iph_num = pkt_info->iph_num;
	iph_save->has_inner_iph = pkt_info->has_inner_iph;
	iph_update = &ip_context->update_by_packet.iph_updates[ROHC_OUTER_IPH];
	to_iph_bh = &last_info->iph_behavior[ROHC_OUTER_IPH];
	from_iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_OUTER_IPH];
	wlsb = ip_context->ip_id_wlsb[ROHC_OUTER_IPH];
	outer_iph = &pkt_info->iph;
	if(outer_iph->version == 4){
		memcpy(&iph_save->iph,outer_iph,sizeof(struct iphdr));
		memcpy(to_iph_bh,from_iph_bh,sizeof(struct iph_behavior_info));
		comp_wlsb_add(wlsb,NULL,msn,iph_update->ip_id_offset);
	}else
		memcpy(&iph_save->ipv6h,&pkt_info->ipv6h,sizeof(struct ipv6hdr));
	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		wlsb = ip_context->ip_id_wlsb[ROHC_INNER_IPH];
		iph_update = &ip_context->update_by_packet.iph_updates[ROHC_INNER_IPH];
		to_iph_bh = &last_info->iph_behavior[ROHC_INNER_IPH];
		from_iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_INNER_IPH];
		if(inner_iph->version == 4){
			memcpy(&iph_save->inner_iph,inner_iph,sizeof(struct iphdr));
			memcpy(to_iph_bh,from_iph_bh,sizeof(struct iph_behavior_info));
			comp_wlsb_add(wlsb,NULL,msn,iph_update->ip_id_offset);
		}else
			memcpy(&iph_save->inner_ipv6h,&pkt_info->inner_ipv6h,sizeof(struct ipv6hdr));
	}
	ip_context->is_first_packet = false;
}

bool high_priority_ipid_off_encode_bits_test(struct ip_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info,int encode_bits)
{
	struct iphdr *iph,*inner_iph;
	struct iph_update_info *iph_update,*inner_iph_update;
	struct iph_behavior_info *iph_bh,*inner_iph_bh;
	struct iph_encode_ipid_bits *ipid_encode_bits;
	bool retval = false;
	iph_update = &ip_context->update_by_packet.iph_updates[ROHC_OUTER_IPH];
	iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_OUTER_IPH];
	iph = &pkt_info->iph;
	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		inner_iph_update = &ip_context->update_by_packet.iph_updates[ROHC_INNER_IPH];
		inner_iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_INNER_IPH];
		if(rohc_iph_is_v4(inner_iph->version) && !ip_id_is_random_or_zero(inner_iph_bh->ip_id_bh))
			ipid_encode_bits = &ip_context->update_by_packet.ipid_k_bits[ROHC_INNER_IPH];
		else if(rohc_iph_is_v4(iph->version) && !ip_id_is_random_or_zero(iph_bh->ip_id_bh))
			ipid_encode_bits = &ip_context->update_by_packet.ipid_k_bits[ROHC_OUTER_IPH];
		else
			goto out;
	}else{
		if(rohc_iph_is_v4(iph->version) && !ip_id_is_random_or_zero(iph_bh->ip_id_bh))
			ipid_encode_bits = &ip_context->update_by_packet.ipid_k_bits[ROHC_OUTER_IPH];
		else
			goto out;
	}
	switch(encode_bits){
		case 3:
			retval = ipid_encode_bits->can_encode_by_3_bit;
			break;
		case 5:
			retval = ipid_encode_bits->can_encode_by_5_bit;
			break;
		case 6:
			retval = ipid_encode_bits->can_encode_by_6_bit;
			break;
		case 8:
			retval = ipid_encode_bits->can_encode_by_8_bit;
			break;
		case 11:
			retval = ipid_encode_bits->can_encode_by_11_bit;
			break;
		case 16:
			retval = true;
			break;
		default:
			pr_err("not support encode_bits:%d\n",encode_bits);
			break;
	}
out:
	return retval;
}

bool specified_iph_ipid_off_encode_bits_test(struct ip_context *ip_context,bool is_inner_iph,int encode_bits)
{
	struct iph_encode_ipid_bits *ipid_encode_bits;
	bool retval = false;
	if(is_inner_iph)
		ipid_encode_bits = &ip_context->update_by_packet.ipid_k_bits[ROHC_INNER_IPH];
	else
		ipid_encode_bits = &ip_context->update_by_packet.ipid_k_bits[ROHC_OUTER_IPH];
	switch(encode_bits){
		case 3:
			retval = ipid_encode_bits->can_encode_by_3_bit;
			break;
		case 5:
			retval = ipid_encode_bits->can_encode_by_5_bit;
			break;
		case 6:
			retval = ipid_encode_bits->can_encode_by_6_bit;
			break;
		case 8:
			retval = ipid_encode_bits->can_encode_by_8_bit;
			break;
		case 11:
			retval = ipid_encode_bits->can_encode_by_11_bit;
			break;
		case 16:
			retval = true;
			break;
		default:
			pr_err("not support encode_bits:%d\n",encode_bits);
			break;
	}
	return retval;
}

bool specfied_iph_ipid_off_need_full_transmit(struct ip_context *ip_context,bool is_inner_iph)
{
	struct iph_update_info *iph_update;
	if(is_inner_iph)
		iph_update = &ip_context->update_by_packet.iph_updates[ROHC_INNER_IPH];
	else
		iph_update = &ip_context->update_by_packet.iph_updates[ROHC_OUTER_IPH];
	if(iph_update->rnd_update)
		return true;
	else
		return false;
}
