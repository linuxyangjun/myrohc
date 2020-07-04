#ifndef	D__DECOMP_TCP_CLIST_H
#define	D__DECOMP_TCP_CLIST_H
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/types.h>


#include "rohc_decomp.h"
#include "../profile/tcp_profile.h"
#include "rohc_decomp_wlsb.h"
struct tcp_analyze_item{
	u8 kind;
	u8 len;
	int item_type;
	int field_num;
	bool is_static;
	bool carryed_by_list;
	union{
		struct wlsb_analyze_field item_field;
		struct wlsb_analyze_field item_fields[8];
		struct analyze_vl_field item_vl_field;
	};
};


struct last_decomped_tcp_options{
	int opt_num;
	struct tcph_option tcp_options[ROHC_TCP_COMP_LIST_MAX];
	struct item_to_index last_map[ROHC_TCP_ITEM_MAX];
	u8 opt_buff[ROHC_TCP_OPTIONS_MAX_LEN];
};


struct tcp_carryed_items{
	bool	is_list_present;
	int opt_num;
	struct tcp_analyze_item analyze_items[ROHC_TCP_COMP_LIST_MAX];
};

struct tcp_decode_options{
	int opt_num;
	int opt_total_len;
	struct item_to_index new_map[ROHC_TCP_ITEM_MAX];
	struct tcph_option tcp_options[ROHC_TCP_COMP_LIST_MAX];
	u8 opt_buff[ROHC_TCP_OPTIONS_MAX_LEN];
};
struct decomp_tcp_options_update{
	struct tcp_carryed_items carryed_items;
	struct tcp_decode_options decode_options;
	u32 ts;
	u32 tsecho;
	bool ts_present;
};

struct decomp_tcph_options_context{
	struct last_decomped_tcp_options tcp_opt_ref;
	struct decomp_tcp_options_update update_by_packet;
	struct rohc_decomp_wlsb *ts_wlsb;
	struct rohc_decomp_wlsb *tsecho_wlsb;
};

#if 0
enum rohc_tcp_item_type tcp_option_pick_item(struct decomp_tcp_options_update *new_update,struct last_decomped_tcp_options *opts_ref,int i)
{
	enum rohc_tcp_item_type item_type;
	struct tcp_analyze_item *analyze_item;
	struct tcph_option *opt_ref;
	analyze_item = &new_update->tcp_opt_items.analyze_items[i];
	if(new_update->carryed_items.is_list_present){
		item_type = analyze_item->item_type;
	}else{
		opt_ref = &opts_ref->tcp_options[i];
		item_type = opt_ref->item_type;
		analyze_item->item_type = item_type;
	}
	return item_type;
}
#endif
static inline void tcp_option_batch_update_item_type(struct decomp_tcp_options_update *new_update,struct last_decomped_tcp_options *opts_ref)
{
	struct tcp_carryed_items *new_opt_items;
	struct tcph_option *opt_ref;
	struct tcp_analyze_item  *analyze_item;
	int i;
	new_opt_items = &new_update->carryed_items;
	if(new_opt_items->is_list_present)
		return;
	new_opt_items->opt_num = opts_ref->opt_num;
	for(i = 0 ; i < opts_ref->opt_num;i++){
		analyze_item = &new_opt_items->analyze_items[i];
		opt_ref = &opts_ref->tcp_options[i];
		analyze_item->item_type = opt_ref->item_type;
		analyze_item->kind = opt_ref->kind;
		analyze_item->len = opt_ref->len;
	}

}

struct decomp_tcp_item_ops{
	enum rohc_tcp_item_type item_type;
	int (*analyze_item)(struct decomp_tcph_options_context *opt_context,u8 *from,struct tcp_analyze_item *analyze_item,int *analyze_len);
	int (*analyze_irr_chain)(struct decomp_tcph_options_context *opt_context,u8 *from,struct tcp_analyze_item *analyze_item,int *analyze_len);
	int (*decode_option)(struct decomp_tcph_options_context *opt_context,struct tcp_analyze_item *analyze_item,const struct tcphdr *tcph);
};
int tcp_options_analyze_clist(struct decomp_tcph_options_context *opt_context,const struct sk_buff *skb,struct	rohc_decomp_pkt_hdr_info *pkt_info);
int tcp_options_analyze_irr_chain(struct decomp_tcph_options_context *opt_context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
int tcp_options_decode(struct decomp_tcph_options_context *opt_context,struct rohc_decomp_pkt_hdr_info *pkt_info,const struct tcphdr *tcph);
int tcp_option_rebuild(struct decomp_tcph_options_context *opt_context,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info,int *option_total_len);

int decomp_tcp_option_init_context(struct decomp_tcph_options_context *opt_context);
void tcp_option_update_context(struct decomp_tcph_options_context *opt_context);
#endif
