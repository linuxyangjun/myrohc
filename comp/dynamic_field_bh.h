#ifndef		D__COMP_IP_H
#define		D__COMP_IP_H
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "rohc_comp_wlsb.h"
#include "../rohc_ipid.h"
#include "../lsb.h"
#include "rohc_comp.h"
struct iph_save_info{
	int iph_num;
	bool has_inner_iph;
	union{
		struct iphdr iph;
		struct ipv6hdr ipv6h;
	};
	union{
		struct iphdr inner_iph;
		struct ipv6hdr inner_ipv6h;
	};
};
struct iph_behavior_info{
	enum ip_id_behavior ip_id_bh;
	bool df;
	bool nbo;
	bool rnd;
	bool constant;
};


struct iph_context_info{
	struct iph_save_info iph_info;
	struct iph_behavior_info iph_behavior[ROHC_MAX_IP_HDR];
};


struct iph_encode_ipid_bits{
	/**
	 *for profile_udp
	 */
	bool	can_encode_by_3_bit;
	bool	can_encode_by_6_bit;
	bool	can_encode_by_8_bit;
	bool	can_encode_by_11_bit;
	/*add for profile rtp*/
	bool	can_encode_by_5_bit;
	bool	can_encode_by_16_bit;
};
struct iph_update_info{
	u16	ip_id_offset; /*ip_id_offset = ip_id - msn*/
	bool	ttl_hl_update;
	bool	tos_tc_update;
	bool	df_update;
	bool	nbo_update;
	bool	rnd_update;
	bool	constant_update;
	bool	ipv6h_ext_update;
	/*ip_id_offset is change ,if current ip-id offset from current  MSN and last
	 * ip-id offset from last MSN is euqal,need't to transmit the IP-ID-OFFSET.
	 */
	bool	ip_id_offset_update;
};

struct iph_packet_update{
	struct iph_encode_ipid_bits ipid_k_bits[ROHC_MAX_IP_HDR];
	struct iph_update_info iph_updates[ROHC_MAX_IP_HDR];
	struct iph_behavior_info iph_behavior[ROHC_MAX_IP_HDR];
};
struct iph_oa_send_info{
	int tos_tc_send_pkts;
	int ttl_hl_send_pkts;
	int df_send_pkts;
	int nbo_send_pkts;
	int rnd_send_pkts;
	int const_send_pkts;

};
struct ip_context{
	struct iph_context_info  last_context_info;
	struct iph_packet_update update_by_packet;
	/**
	 *ip id lsb window.
	 */
	struct comp_win_lsb *ip_id_wlsb[ROHC_MAX_IP_HDR];
	bool is_first_packet;
	struct iph_oa_send_info oa_send_pkts[ROHC_MAX_IP_HDR];

};

struct msn_encode_bits{
	bool	can_encode_by_3_bit;
	bool	can_encode_by_4_bit;
	bool	can_encode_by_5_bit;
	bool	can_encode_by_6_bit;
	bool	can_encode_by_8_bit;
	bool	can_encode_by_11_bit;
	bool	can_encode_by_13_bit;

	/*additional for rtp*/
	bool	can_encode_by_14_bit;
	bool	can_encode_by_7_bit;
	bool	can_encode_by_12bit;
	bool	can_encode_by_9_bit;

};

static inline void msn_udp_bits_probe(struct comp_win_lsb *wlsb,struct  msn_encode_bits *msn_k_bits,u16 msn)
{
	msn_k_bits->can_encode_by_4_bit = comp_wlsb_can_encode_type_ushort(wlsb,4,ROHC_LSB_UDP_SN_P,msn);
	msn_k_bits->can_encode_by_5_bit = comp_wlsb_can_encode_type_ushort(wlsb,5,ROHC_LSB_UDP_SN_P,msn);
	msn_k_bits->can_encode_by_8_bit = comp_wlsb_can_encode_type_ushort(wlsb,8,ROHC_LSB_UDP_SN_P,msn);
	msn_k_bits->can_encode_by_13_bit = comp_wlsb_can_encode_type_ushort(wlsb,13,ROHC_LSB_UDP_SN_P,msn);
}

static inline bool msn_encode_bits_set_test(struct msn_encode_bits *bits_set,int encode_bits)
{
	int retval = false;
	switch(encode_bits){
		case 3:
			retval = bits_set->can_encode_by_3_bit;
			break;
		case 4:
			retval = bits_set->can_encode_by_4_bit;
			break;
		case 5:
			retval = bits_set->can_encode_by_5_bit;
			break;
		case 6:
			retval = bits_set->can_encode_by_6_bit;
			break;
		case 7:
			retval = bits_set->can_encode_by_7_bit;
			break;
		case 8:
			retval = bits_set->can_encode_by_8_bit;
			break;
		case 9:
			retval = bits_set->can_encode_by_9_bit;
			break;
		case 11:
			retval = bits_set->can_encode_by_11_bit;
			break;
		case 12:
			retval = bits_set->can_encode_by_12bit;
			break;
		case 13:
			retval = bits_set->can_encode_by_13_bit;
			break;
		case 14:
			retval = bits_set->can_encode_by_14_bit;
			break;
	}
	return retval;
}


static inline bool iph_dynamic_fields_update(struct iph_update_info *iph_update)
{
	return (iph_update->ttl_hl_update || iph_update->tos_tc_update || iph_update->df_update || \
		iph_update->nbo_update || iph_update->rnd_update || iph_update->ipv6h_ext_update);
}
static inline bool ip_id_offset_need_trans(u8 version,struct iph_behavior_info *iph_bh,struct iph_update_info *iph_update)
{
	bool retval = false;
	if(rohc_iph_is_v4(version) && !ip_id_is_random_or_constant(iph_bh->ip_id_bh) && iph_update->ip_id_offset_update)
		retval = true;
	return retval;
}

static inline bool iph_has_no_ipid_offset_need_trans(struct ip_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct iphdr *iph,*inner_iph;
	struct iph_update_info *outer_iph_update,*inner_iph_update;
	struct iph_behavior_info *outer_iph_bh,*inner_iph_bh;
	bool retval = false;
	outer_iph_update = &ip_context->update_by_packet.iph_updates[ROHC_OUTER_IPH];
	outer_iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_OUTER_IPH];
	iph = &pkt_info->iph;
	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		inner_iph_update = &ip_context->update_by_packet.iph_updates[ROHC_INNER_IPH];
		inner_iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_INNER_IPH];
		if(!ip_id_offset_need_trans(inner_iph->version,inner_iph_bh,inner_iph_update) && \
		   !ip_id_offset_need_trans(iph->version,outer_iph_bh,outer_iph_update))
			retval = true;
	}else{
		if(!ip_id_offset_need_trans(iph->version,outer_iph_bh,outer_iph_update))
			retval = true;
	}
	return retval;
}
static inline bool iph_has_sequence_ipid(struct ip_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct iphdr *iph,*inner_iph;
	struct iph_behavior_info *iph_bh,*inner_iph_bh;
	bool retval = false;
	iph = &pkt_info->iph;
	iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_OUTER_IPH];
	if(pkt_info->has_inner_iph){
		inner_iph = &pkt_info->inner_iph;
		inner_iph_bh = &ip_context->update_by_packet.iph_behavior[ROHC_INNER_IPH];
		if(rohc_iph_is_v4(inner_iph->version) && !ip_id_is_random_or_constant(iph_bh->ip_id_bh) || \
		   rohc_iph_is_v4(iph->version) && !ip_id_is_random_or_constant(iph_bh->ip_id_bh))
			retval = true;

	}else{
		if(rohc_iph_is_v4(iph->version) && !ip_id_is_random_or_constant(iph_bh->ip_id_bh))
			retval = true;
	}
	return retval;

}
void iph_update_context(struct ip_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info,u32 msn);
void ip_id_behavior_probe(struct ip_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info);
void iph_update_probes(struct ip_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info,int max_oa);
void ip_id_k_bits_probes(struct ip_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info,enum rohc_profile prof);
bool high_priority_ipid_off_encode_bits_test(struct ip_context *ip_context,struct rohc_comp_packet_hdr_info *pkt_info,int encode_bits);
bool specified_iph_ipid_off_encode_bits_test(struct ip_context *ip_context,bool is_inner_iph,int encode_bits);
bool sepecfied_iph_ipid_off_need_full_transmit(struct ip_context,bool is_inner_iph);
#endif
