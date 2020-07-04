#ifndef	D__COMP_UDP_V2_H
#define	D__COMP_UDP_V2_H
#include <linux/types.h>
#include <linux/udp.h>
#include "rohc_comp_v2_common.h"
struct last_comped_udph{
	struct udphdr udph;
	int check_bh;
};

struct udph_field_update{
	bool check_bh_update;
	int  check_bh;
};

struct udph_field_trans_times{
	u32 check_bh_trans_time;
};


struct comp_udp_v2_context{
	struct last_comped_udph udph_ref;
	struct udph_field_update update_by_packet;
	struct udph_field_trans_times update_trans_times;
};
int rohc_v2_build_udp_irr_chain(struct comp_udp_v2_context *udp_context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info);
int rohc_v2_build_udp_static_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
int rohc_v2_build_udp_dynamic_chain(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
void rohc_v2_update_udph_context(struct comp_udp_v2_context *udp_context,struct rohc_comp_packet_hdr_info *pkt_info);
void rohc_v2_udph_update_probe(struct comp_udp_v2_context *udp_context,struct rohc_comp_packet_hdr_info *pkt_info,int oa_max);
#endif
