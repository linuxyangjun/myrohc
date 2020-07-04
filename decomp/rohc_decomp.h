#ifndef		D__ROHC_DECOMP_H
#define		D__ROHC_DECOMP_H

#include <linux/types.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include "rohc_decomp_k_out_n.h"
#include "../rohc_profile.h"
#include "../rohc_rb.h"
#include "../rohc_packet.h"
#include "../rohc_cid.h"
#include "../rohc_crc.h"
struct rohc_decomp_pkt_hdr_info;
struct rohc_decomp_context;

struct rohc_decomp_profile_ops{
	enum rohc_packet_type (*adjust_packet_type)(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
	int (*analyze_packet_header)(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
	int (*analyze_profile_header)(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
	int (*analyze_static_chain)(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
	int (*analyze_dynamic_chain)(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
	int (*decode_packet_header)(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info);
	int (*rebuild_packet_header)(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
	int (*recover_net_packet_header)(struct rohc_decomp_context *context,struct sk_buff *skb ,struct rohc_decomp_pkt_hdr_info *pkt_info);
	int (*decompress)(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
	int (*feedback)(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info,struct sk_buff *feedback,bool is_fail);
	u32 (*last_decompressed_sn)(struct rohc_decomp_context *context);
	u8 (*sn_bit_width)(struct rohc_decomp_context *context);
	int (*init_context)(struct rohc_decomp_context *context);
	int (*destroy_context)(struct rohc_decomp_context *context);
	int (*update_context)(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info);
	int (*crc_verify)(const struct sk_buff *skb,struct rohc_crc_info *crc_info);
	u8 (*crc_cal)(const struct sk_buff *skb,struct rohc_crc_info *crc_info);
};

struct rohc_decomp_profile{
	int profile;
	struct list_head list;
	const struct rohc_decomp_profile_ops *pro_ops;
};
struct	rohc_decomp_pkt_hdr_info{
	int	iph_num;

	bool	has_inner_iph;
	enum rohc_packet_type packet_type;
	enum rohc_profile prof;
	union{
		struct	iphdr iph;
		struct	ipv6hdr ipv6h;
	};
	union{
		struct iphdr inner_iph;
		struct ipv6hdr inner_ipv6h;
	};
	union{
		struct tcphdr tcph;
		struct udphdr udph;
	};
	struct	ethhdr eth;
	u16	decomped_hdr_len;
	u16	rebuild_hdr_len;
	u16	cid_len;
	void	*staic_info;   //static chain info
	void	*dynamic_info; //dynamic chain info
	void	*co_info; //co-packet info
	void	*priv_info; //extend info
	struct sk_buff *skb;
	/*for crc cal*/
	struct rohc_crc_info header_crc;
	struct rohc_crc_info ctrl_crc;
};

struct rohc_decomp_period_update{
	struct downward_kn nack_kn_fc;
	struct downward_kn static_nack_kn_sc;
	struct downward_kn nack_kn_sc;
	struct downward_kn static_nack_kn_nc;
	struct upward_kn sparse_ack_up;
	struct downward_kn sparse_ack_down;
};
struct rohc_decomp_context{
	u16 cid;
	bool	decomp_eth_hdr;
	int	context_state;
#define	DECOMP_STATE_NO_CONTEXT		1
#define	DECOMP_STATE_STATIC_CONTEXT	2
#define	DECOMP_STATE_FULL_CONTEXT	3
	int	mode;
	int	set_mode;
	unsigned int capability;

#define	ROHC_DECOMP_CAP_CRC_VERIFY		(1 << 0)

	bool	mode_update;
	bool	need_mode_trans;
	bool	need_establish_feedback_channel;
	struct rohc_rb_node	context_rb;
	struct rohc_decomp_period_update period_update;
	struct rohc_decomp_profile *decomp_profile;
	struct rohc_decompresser *decompresser;
	struct sk_buff *decomp_skb;
	void *inherit_context;

};

struct rohc_decomp_refresh_threshold{
	unsigned long	downward_fc_n;
	unsigned long	downward_fc_k;
	unsigned long	downward_sc_n;
	unsigned long	downward_sc_k;
	unsigned long	downward_nc_n;
	unsigned long	downward_nc_k;
	unsigned long	sparse_ack_n;
	unsigned long	sparse_ack_k;
};
struct rohc_decompresser{
	char name[ROHC_NAME_LEN];
	enum rohc_cid_type cid_type;
	u32	max_cid;
	bool	decomp_eth_hdr;
	struct rohc_rb_root decomp_rb;
	struct rohc_decomp_context *uncomp_context;
	struct rohc_decomp_profile **decomp_profiles;
	struct rohc_decomp_refresh_threshold refresh_threshold;
	struct rohc_decomp_pkt_hdr_info pkt_info;

};

#define	DECOMP_CONTEXT_CID_TYPE(context)	((context)->decompresser->cid_type)

static inline int rohc_decomp_decode_padding(struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *start;
	int retval = 0;
	start = skb->data + pkt_info->decomped_hdr_len;
	if(rohc_packet_is_padding(start)){
		pkt_info->decomped_hdr_len++;
		rohc_pr(ROHC_DTCP,"Has padding\n");
	}
	return retval;
}


int rohc_decomp_decompress(struct rohc_decompresser *rohc_decomp,struct sk_buff *skb,struct sk_buff *rcv_feedback,struct sk_buff *feedback,gfp_t flags);
struct rohc_decompresser *rohc_decomp_alloc(enum rohc_cid_type cid_type,u32 max_cid,void (*setup)(struct rohc_decompresser *decomp),char *name);
void rohc_decomp_set_refresh_param(struct rohc_decompresser *decomp,struct rohc_decomp_refresh_threshold *set);
#endif
