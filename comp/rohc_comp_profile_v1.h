#ifndef	D__ROHC_COMP_PROFILE_V1__H
#define	D__ROHC_COMP_PROFILE_V1__H
#include <linux/ip.h>

#include "../rohc_packet.h"
#include "../rohc_profile.h"

#include "dynamic_field_bh.h"
#include "rohc_comp.h"
#include "rohc_comp_wlsb.h"
struct packet_type_info{
	enum rohc_packet_type packet_type;
	enum rohc_ext_type ext_type;
};


struct comp_profile_v1_ops{
	int (*adjust_extension)(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info);
	int (*bulid_extension)(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info);
	int (*feedback_input)(struct rohc_comp_context *context,int ack_type,u32 msn,u32 msn_bit_width,bool sn_valid);
};
struct comp_profile_v1_context{
	struct comp_profile_v1_ops *prof_v1_ops;
	int	oa_upward_pkts;
	bool	is_first_packet;
	struct  packet_type_info packet_info;
	struct	ip_context ip_context;
	void	*prof_context;
	struct sk_buff *comp_skb;
	struct  msn_encode_bits msn_k_bits; 
	struct comp_win_lsb wlsb_for_msn;
	struct comp_win_lsb *msn_wlsb;
};
static inline void update_iph_oa_send_info_condition(struct iphdr *iph,struct iph_oa_send_info *oa,struct iph_update_info *iph_update)
{
	if(iph_update->ttl_hl_update)
		oa->ttl_hl_send_pkts++;
	if(iph_update->tos_tc_update)
		oa->tos_tc_send_pkts++;
	if(iph->version == 4){
		oa->df_send_pkts++;
		oa->nbo_send_pkts++;
		oa->rnd_send_pkts++;
		oa->const_send_pkts++;
	}
}

static inline void update_iph_oa_send_info_all(struct iph_oa_send_info *oa)
{
	oa->ttl_hl_send_pkts++;
	oa->tos_tc_send_pkts++;
	oa->df_send_pkts++;
	oa->nbo_send_pkts++;
	oa->rnd_send_pkts++;
	oa->const_send_pkts++;
}


static inline void reset_iph_oa_send_info(struct iph_oa_send_info *send_info)
{
	memset(send_info,0,sizeof(struct iph_oa_send_info));
}

static inline void update_iph_oa_send_info_ack(struct iph_oa_send_info *oa_info,int max_oa)
{
	oa_info->ttl_hl_send_pkts = max_oa;
	oa_info->tos_tc_send_pkts = max_oa;
	oa_info->nbo_send_pkts = max_oa;
	oa_info->rnd_send_pkts = max_oa;
	oa_info->const_send_pkts = max_oa;
}
static inline void update_iph_oa_send_info_nack(struct iph_oa_send_info *oa_info)
{
	memset(oa_info,0,sizeof(struct iph_oa_send_info));
}
int rohc_comp_profile_v1_init_context(struct comp_profile_v1_context *context,struct rohc_comp_packet_hdr_info *pkt_info,struct comp_profile_v1_ops *prof_v1_ops,int oa_max);

#endif
