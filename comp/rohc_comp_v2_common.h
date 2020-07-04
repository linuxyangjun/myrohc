#ifndef	D__ROHC_COMP_V2_CO_H
#define	D__ROHC_COMP_V2_CO_H
#include <linux/types.h>

#include "../rohc_ipid.h"
#include "../rohc_bits_encode.h"
#include "../rohc_packet.h"

#include "../profile/rohc_v2_profile.h"
#include "../profile/rohc_v2_packet.h"
#include "rohc_comp.h"
#include "rohc_comp_wlsb.h"
struct last_comped_iph{
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
	enum ip_id_behavior ipid_bh;
	enum ip_id_behavior inner_ipid_bh;
};

struct iph_field_update{
	bool tos_tc_update;
	bool ttl_hl_update;
	bool ipid_bh_update;
	bool ipid_off_update;
	bool df_update;
	struct rohc_bits_encode_set ipid_off_encode_bits;
	enum ip_id_behavior new_ipid_bh;
	u16  new_ipid_offset;
};

struct iph_field_trans_times{
	u32 tos_tc_trans_time;
	u32 ttl_hl_trans_time;
	u32 ipid_bh_trans_time;
	u32 df_trans_time;
};

static inline void inc_iph_all_field_trans_times(struct iph_field_trans_times *trans_times)
{
	trans_times->tos_tc_trans_time++;
	trans_times->ttl_hl_trans_time++;
	trans_times->df_trans_time++;
	trans_times->ipid_bh_trans_time++;
}

static inline void confident_iph_field_trans_times(struct iph_field_trans_times *trans_times,int oa_max)
{
	trans_times->tos_tc_trans_time = oa_max;
	trans_times->ttl_hl_trans_time = oa_max;
	trans_times->df_trans_time = oa_max;
	trans_times->ipid_bh_trans_time = oa_max;
}
static inline void inc_iph_dynamic_field_trans_times(struct iph_field_trans_times *trans_times,int type)
{
	switch(type){
		case IPH_FIELD_TOS_TC:
			trans_times->tos_tc_trans_time++;
			break;
		case IPH_FIELD_TTL_HL:
			trans_times->ttl_hl_trans_time++;
			break;
		case IPH_FIELD_DF:
			trans_times->df_trans_time++;
			break;
		case IPH_FIELD_IPID_BH:
			trans_times->ipid_bh_trans_time++;
			break;
		default:
			break;
	}
}

struct rohc_v2_iph_context{
	struct last_comped_iph iph_ref;
	struct iph_field_update update_by_packet;
	struct iph_field_update inner_update_by_packet;

	struct comp_win_lsb *ip_id_wlsb[ROHC_V2_MAX_IP_HDR];
	#define	outer_ipid_wlsb		ip_id_wlsb[ROHC_OUTER_IPH]
	#define	innermost_ipid_wlsb	ip_id_wlsb[ROHC_INNER_IPH]
	bool is_first_packet;
	struct iph_field_trans_times update_trans_times;
	struct iph_field_trans_times inner_update_trans_times;
};


struct rohc_v2_common_context;
struct rohc_v2_prof_ops{
	int (*feedback_input)(struct rohc_v2_common_context *co_context,int ack_type,u32 msn,int msn_width,bool sn_valid);
};
struct rohc_v2_common_update{
	struct rohc_bits_encode_set msn_encode_bits;
};

struct rohc_v2_common_context{
	struct rohc_v2_iph_context iph_context;
	struct rohc_v2_prof_ops *prof_ops;
	struct rohc_v2_common_update co_update;
	void *inherit_context;
	struct comp_win_lsb *msn_wlsb;
	enum rohc_v2_reordering_ratio reorder_ratio;
	int oa_upward_pkts;
};
static inline void inc_spec_iph_dynamic_field_trans_times(struct rohc_v2_iph_context *iph_context,int type,bool is_innermost,bool has_inner_iph)
{
	struct iph_field_trans_times *trans_times;
	if(is_innermost){
		if(has_inner_iph)
			trans_times = &iph_context->inner_update_trans_times;
		else
			trans_times = &iph_context->update_trans_times;
	}else
		trans_times = &iph_context->update_trans_times;
	inc_iph_dynamic_field_trans_times(trans_times,type);
}
u8 rohc_v2_field_static_or_irreg_indicator(bool update);
int innermost_iph_field_static_or_irreg_build(u8 *to,struct rohc_comp_packet_hdr_info *pkt_info,int ind,int field_type);
int innermost_seq_ipid_variable_build(u8 *to,struct rohc_comp_packet_hdr_info *pkt_info,struct rohc_v2_iph_context *iph_context,int ind);
void pick_innermost_seq_ipid_offset(struct rohc_v2_iph_context *iph_context,bool has_inner_iph,u16 *ipid_off);
bool innermost_ipid_encode_set_test(struct rohc_v2_iph_context *iph_context,bool has_inner_iph,int bits);
bool outer_iph_dynamic_field_update(struct rohc_v2_iph_context *iph_context,bool has_inner_iph,int type);
bool innermost_iph_dynamic_field_update(struct rohc_v2_iph_context *iph_context,bool has_inner_iph,int type);
bool innermost_ipid_bh_is_seq(struct rohc_v2_iph_context *iph_context,struct rohc_comp_packet_hdr_info *pkt_info);
void rohc_v2_iph_update_probe(struct rohc_v2_iph_context *iph_context,struct rohc_comp_packet_hdr_info *pkt_info,int oa_max,u32 msn);
int rohc_comp_v2_build_generic_co_common(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first);
int rohc_comp_v2_build_pt_0_crc3(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first);
int rohc_comp_v2_build_pt_0_crc7(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first);
int rohc_comp_v2_build_pt_1_seq_id(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first);
int rohc_comp_v2_build_pt_2_seq_id(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,bool build_first);
int rohc_comp_v2_build_ip_static_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
int rohc_comp_v2_build_ip_dynamic_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
int rohc_comp_v2_build_ip_irr_chain(struct rohc_v2_iph_context *iph_context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info);

int rohc_v2_comp_init_ip_context(struct rohc_v2_iph_context *ip_context,int oa_max);
void rohc_v2_destroy_ip_context(struct rohc_v2_iph_context *ip_context);
void rohc_v2_update_ip_context(struct rohc_v2_iph_context *iph_context,struct rohc_comp_packet_hdr_info *pkt_info,u32 msn);
int rohc_comp_v2_feedback_input(struct rohc_comp_context *context,struct sk_buff *skb,int cid_len,int feeback_size);

void rohc_v2_cal_msn_encode_bits_set(struct rohc_bits_encode_set *msn_set,struct comp_win_lsb *msn_wlsb,enum rohc_v2_reordering_ratio r_ratio,u32 msn,int msn_type);
#endif
