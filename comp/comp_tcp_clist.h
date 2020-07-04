#ifndef	D__COMP_TCP_CLIST_H
#define	D__COMP_TCP_CLIST_H

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/types.h>


#include "rohc_comp.h"
#include "rohc_comp_wlsb.h"
#include "../profile/tcp_profile.h"

struct tcp_opt_update_trans_times{
	u32 list_item_trans_times;
	u32 irr_chain_trans_times;
};
struct tcp_item_update{
	bool static_update;
	bool dynamic_update;
	bool carryed_by_list;
};
struct last_tcph_carryed_options{
	int opt_num;
	struct	tcph_option tcp_options[ROHC_TCP_COMP_LIST_MAX];
	u8	opt_buff[64];
};



struct item_generic{
	enum rohc_tcp_item_type type;
	struct list_head list;
};


struct tcph_options_update{
	bool	list_structure_update;
	bool	content_update_not_defined_in_irr;
	u32	tsval;
	u32	tsecho;
	bool	ts_carryed;
	bool	ts_can_encode;
	enum	rohc_tcp_item_type  item_type_max;
	struct  tcp_item_update item_update[ROHC_TCP_ITEM_MAX];
	struct  rohc_bits_encode_set tsval_encode_bits;
	struct	rohc_bits_encode_set tsecho_encode_bits;
};
struct tcph_option_context{
	unsigned long *item_generic_bitmap;
	struct list_head	item_generic_active_list;
	struct	item_generic	item_generics[ROHC_TCP_OPT_GENERIC_MAX];
	struct comp_win_lsb	*ts_wlsb;
	struct comp_win_lsb	*tsecho_wlsb;
	struct last_tcph_carryed_options tcph_opts_ref;
	struct tcph_options_update opts_update_by_packet;
	struct tcp_opt_update_trans_times update_trans_times[ROHC_TCP_ITEM_MAX];
	int	list_structure_update_trans_time;
	bool	is_first_packet;
};

struct tcp_item_table_ops{
	enum rohc_tcp_item_type item_type;
	int (*build_item)(struct tcph_option_context *opt_context,u8 *to,struct tcph_option *tcp_option,const struct sk_buff *skb,int *build_len);
	int (*build_irr_chain)(struct tcph_option_context *opt_context,u8 *to,struct tcph_option *tcp_option,const struct sk_buff *skb,int *build_len);
};


static inline void reset_tcp_options_all_trans_times(struct tcp_opt_update_trans_times *opt_trans_times)
{
	memset(opt_trans_times,0,sizeof(struct tcp_opt_update_trans_times) * ROHC_TCP_ITEM_MAX);
}

static inline void confident_tcp_options_all_trans_times(struct tcp_opt_update_trans_times *opt_trans_times,int oa_max)
{
	int i;

	for(i = 0 ; i < ROHC_TCP_ITEM_MAX;i++,opt_trans_times++){
		opt_trans_times->list_item_trans_times = oa_max;
		opt_trans_times->irr_chain_trans_times = oa_max;
	}
}
void tcp_options_update_probe(struct tcph_option_context *opt_context,struct rohc_comp_packet_hdr_info *pkt_info,int oa_max,bool ack_seq_update);

int rohc_comp_tcp_options_analyze(const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);

int tcp_options_build_clist(struct tcph_option_context *option_context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info);
int tcp_options_build_irr_chain(struct tcph_option_context *option_context,struct sk_buff *comp_skb,struct rohc_comp_packet_hdr_info *pkt_info);

int tcp_option_init_context(struct tcph_option_context *opt_context,int oa_max);
void tcp_option_destroy_context(struct tcph_option_context *opt_context);
void tcph_option_update_context(struct tcph_option_context *opt_context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,u32 msn);
#endif
