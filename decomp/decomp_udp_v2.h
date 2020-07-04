#ifndef	D__DECOMP_UDP_V2_H
#define	D__DECOMP_UDP_V2_H
#include <linux/types.h>
#include <linux/udp.h>
#include "rohc_decomp_wlsb.h"
struct last_decomped_udph{
	struct udphdr udph;
	int check_bh;
};

struct udph_dynamic_fields{
	struct analyze_field	check_bh;
	struct analyze_field	check;
};

struct udph_static_fields{
	u16 sport;
	u16 dport;
	bool update;
};

struct udp_analyze_fields{
	struct udph_static_fields static_fields;
	struct udph_dynamic_fields dynamic_fields;
};

struct udph_decode{
	struct udphdr udph;
};

struct decomp_udph_field_update{
	struct udp_analyze_fields udph_fields;
	struct udph_decode decoded_updh;
};

struct decomp_udp_v2_context{
	struct last_decomped_udph udph_ref;
	struct decomp_udph_field_update update_by_packet;
};
int rohc_v2_analyze_udp_irr_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
int rohc_v2_analyze_udp_static_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
int rohc_v2_analyze_udp_dynamic_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
int rohc_v2_decode_udp_header(struct decomp_udp_v2_context *udp_context,struct rohc_decomp_pkt_hdr_info *pkt_info);
int rohc_v2_rebuild_udp_header(struct decomp_udp_v2_context *udp_context,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info);

void rohc_v2_udp_update_context(struct decomp_udp_v2_context *udp_context);

#endif
