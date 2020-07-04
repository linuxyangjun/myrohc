#ifndef	D__DECOMP_RTP_CLIST_H
#define	D__DECOMP_RTP_CLIST_H
#include <linux/types.h>
#include "../profile/rtp_profile.h"
#include "rohc_decomp_wlsb.h"

struct csrc_analyze_item{
	enum ssrc_item_type item_type;
	struct analyze_field item_field;
};
struct last_decomped_rtp_csrc{
	int cc;
	struct rtp_csrc ssrcs[CSRC_CARRYED_MAX];
	struct ssrc_item_to_index ref_map[SSRC_ITEM_GENERIC_MAX];
};

struct csrc_carryed_items{
	int cc;
	struct csrc_analyze_item analyze_item[CSRC_CARRYED_MAX];
	bool	comp_list_present;
};


struct rtp_decode_csrc{
	int cc;
	struct rtp_csrc decode_ssrcs[CSRC_CARRYED_MAX];
	struct ssrc_item_to_index new_map[SSRC_ITEM_GENERIC_MAX];
};

struct decomp_rtp_csrc_update{
	struct csrc_carryed_items carryed_items;
	struct rtp_decode_csrc decode_csrc;

};

struct decomp_rtp_csrc_context{
	struct last_decomped_rtp_csrc csrc_ref;
	struct decomp_rtp_csrc_update update_by_packet;

};
int rtp_csrc_analyze_clist(struct decomp_rtp_csrc_context *csrc_context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
int rtp_v2_csrc_analyze_clist(struct decomp_rtp_csrc_context *csrc_context,const struct sk_buff *skb,struct	rohc_decomp_pkt_hdr_info *pkt_info);
int rtp_csrc_rebuild_csrc_list(struct decomp_rtp_csrc_context *csrc_context,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info,int *cc);
int rtp_csrc_decode_ssr(struct decomp_rtp_csrc_context *csrc_context,struct rohc_decomp_pkt_hdr_info *pkt_info);
int decomp_rtp_csrc_update_context(struct decomp_rtp_csrc_context *csrc_context);
void rtp_csrc_copy_static_clist(struct decomp_rtp_csrc_context *csrc_context);
#endif
