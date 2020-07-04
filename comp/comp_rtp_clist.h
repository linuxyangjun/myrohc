#ifndef	D__COMP_RTP_CLIST_H
#define	D__COMP_RTP_CLIST_H

#include <linux/types.h>
struct ssrc_item_generic{
	struct list_head list;
	enum ssrc_item_type item_type;
};

struct last_comped_rtph_csrcs{
	int cc;
	struct rtp_csrc rtp_csrcs[CSRC_CARRYED_MAX];
};
struct ssrc_update_trans_times{
	u32 item_trans_times;
};
struct rtp_ssrc_item_update{
	bool static_update;
};
struct rtp_csrc_update{
	bool csrc_list_zero_to_non_zero;
	bool csrc_list_update;
	bool csrc_insert;
	bool csrc_remove;
	enum ssrc_item_type item_type_max;
	enum ssrc_item_type insert_item_type_max;
	unsigned long insert_bit_mask;
	int insert_bit_len;
	unsigned long remove_bit_mask;
	int remove_bit_len;
	int insert_num;
	struct rtp_ssrc_item_update ssrc_item_update[SSRC_ITEM_GENERIC_MAX];
	//struct rtp_csrc item_insert[CSRC_CARRYED_MAX];
};

struct rtp_csrc_context{
	unsigned long *item_bitmap;
	struct list_head item_active_list;
	struct ssrc_item_generic ssrc_items[SSRC_ITEM_GENERIC_MAX];

	struct ssrc_update_trans_times update_trans_times[SSRC_ITEM_GENERIC_MAX];

	struct last_comped_rtph_csrcs csrc_ref;
	struct rtp_csrc_update update_by_packet;
	bool is_first_packet;
};

struct ssrc_item_map{
	bool appear_in_cur;
	bool appear_in_ref;
	int  ref_index;
	int  cur_index;
	bool maped;
};


int rtp_csrc_build_clist(struct rtp_csrc_context *context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info);
int rtp_csrc_build_generic_scheme(struct rtp_csrc_context *context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info);
int rtp_v2_csrc_build_clist(struct rtp_csrc_context *context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info);

int rtp_csrc_init_context(struct rtp_csrc_context *csrc_context);
int rtp_csrc_update_context(struct rtp_csrc_context *context,struct rohc_comp_packet_hdr_info *pkt_info);
void rtp_csrc_update_probe(struct rtp_csrc_context *context,struct rohc_comp_packet_hdr_info *pkt_info,int oa_max);

void rtp_csrc_update_probe(struct rtp_csrc_context *context,struct rohc_comp_packet_hdr_info *pkt_info,int oa_max);
#endif
