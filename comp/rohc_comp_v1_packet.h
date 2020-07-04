#ifndef	D__ROHC_COMP_V1_H
#define	D__ROHC_COMP_V1_H

#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/skbuff.h>

#include "dynamic_field_bh.h"
#include "rohc_comp.h"
#include "rohc_comp_profile_v1.h"
struct uo_0{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8	crc:3;
	u8	sn:4;
	u8	type:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8	type:1,
		sn:4,
		crc:3;
#else
#error "Please fix <asm/byteorder.h>"
#endif
};



bool rohc_comp_only_need_trans_one_ip_id_by_uo1(struct comp_profile_v1_context *context,struct rohc_comp_packet_hdr_info *pkt_info);
int rohc_comp_udp_uo_2_adjust_extension(struct comp_profile_v1_context *context,struct rohc_comp_packet_hdr_info *pkt_info);

int rohc_comp_build_uo1(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
int rohc_comp_build_uo0(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
int rohc_comp_build_uor2(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);

int rohc_comp_build_ip_static_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
int rohc_comp_build_ip_dynamic_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);

int rohc_comp_build_udp_static_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
int rohc_comp_build_udp_dynamic_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);

int rohc_comp_build_ext0(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info);
int rohc_comp_build_ext1(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info);
int rohc_comp_build_ext2(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info);
int rohc_comp_build_ext3(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info);

int rohc_comp_feedback_input(struct rohc_comp_context *context,struct sk_buff *skb,int cid_len,int feeback_size);


void rohc_comp_iph_update_probe(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info);

int rohc_comp_uro_2_adjust_extension(struct comp_profile_v1_context *context,struct rohc_comp_packet_hdr_info *pkt_info);
int rohc_comp_adjust_extension(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info);



void rohc_comp_pick_non_rnd_const_ipid(struct comp_profile_v1_context *context,struct rohc_comp_packet_hdr_info *pkt_info,u16 *ipid_off,bool *is_inner_iph);
#endif
