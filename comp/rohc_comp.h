#ifndef		D__ROHC_COMP_H
#define		D__ROHC_COMP_H
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include "../rohc_rb.h"
#include "../rohc_packet.h"
#include "../rohc_cid.h"
#include "../rohc_crc.h"
#include "rohc_comp_hash.h"
#include "rohc_comp_wlsb.h"
#include "../profile/tcp_profile.h"
#include "../profile/rtp_profile.h"
//#include "ip_bh.h"
struct rohc_comp_context;
//struct tcph_carryed_options;

struct rohc_comp_packet_hdr_info{
	struct ethhdr eth;
	int iph_num;
	bool has_inner_iph;
	bool has_iph;
	union{
		struct iphdr iph;
		struct ipv6hdr ipv6h;
	};
	union{
		struct iphdr inner_iph;
		struct ipv6hdr inner_ipv6h;
	};
	union{
		struct tcphdr tcph;
		struct udphdr udph;
	};

	/*for tcp heade option
	  */
	struct tcph_carryed_options tcph_options;
	u16 to_comp_pkt_hdr_len;
	u16 comp_hdr_len;
	struct sk_buff *skb;
	enum rohc_packet_type packet_type;

	/*for rtp*/
	struct rtphdr rtph;

	struct rtp_new_csrcs rtph_csrc;

	/*for crc cal*/
	struct rohc_crc_info crc_info;
};




struct comp_profile_ops{
	enum rohc_packet_type (*adjust_packet_type)(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
	u32 (*new_msn)(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info);
	int (*build_static_chain)(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
	int (*build_dynamic_chain)(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
	int (*build_profile_header)(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
	int (*compress)(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
	int (*build_comp_header)(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,enum rohc_packet_type type);
	u8  (*crc_cal)(const struct sk_buff *skb,struct rohc_crc_info *crc_info);
	int (*feedback_input)(struct rohc_comp_context *context,struct sk_buff *skb,int cid_len,int feedback_size);
	int (*init_context)(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info);
	int (*destroy_context)(struct rohc_comp_context *context);
	void (*update_context)(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info);
};

struct rohc_comp_profile{
	struct list_head list;
	int profile;
	struct comp_profile_ops *pro_ops;

};
struct ori_net_header{
	u16 net_header_start;
	u16 net_header_len;
};

struct rohc_comp_period_update{
	unsigned long oa_upward_sent;
	unsigned long oa_downward_timeout_fo_sent;
	unsigned long oa_downward_timeout_fo_base_jiffies;
	unsigned long oa_downward_timeout_so_sent;
	unsigned long oa_downward_timeout_so_base_jiffies;
};

struct rohc_comp_context_common_fields{
	u32 msn;
	u32 last_msn_for_update_contxt;
	//bool is_first
};
struct rohc_comp_context{
	struct rohc_comp_profile *comp_profile;
	struct ori_net_header all_header;
	struct rohc_comp_packet_hdr_info pkt_hdr_info;
	void	*prv_context;
	bool	comp_eth_hdr;
	unsigned long	oa_com_pkts;
	int	context_state;
#define		COMP_STATE_IR	1
#define		COMP_STATE_CR	2
#define		COMP_STATE_FO	3
#define		COMP_STATE_SO	4
	/*normal state only for uncompress profile */
#define		COMP_STATE_NORMAL 5
	int mode;

	u16	cid;
	u8    hdr_len_resv;
	unsigned int capability;
#define	ROHC_COMP_CAP_CRC_VERIFY	(1 << 0)

	struct rohc_comp_context_hnode hash_node;
	struct list_head	list;
	struct rohc_rb_node	context_rb;
	struct sk_buff *comp_skb;
	struct rohc_compresser *compresser;
	struct rohc_comp_period_update	period_update;
	/**
	 *profiles common context fileds.
	 */
	struct rohc_comp_context_common_fields co_fields;
	void *prof_context;
	/*timer for downward context states*/
	struct timer_list downward_timer;
	unsigned long update_jiffies;
};



struct rohc_comp_refresh_threshold{
	unsigned long oa_upward_pkts;
	unsigned long oa_downward_timeout_fo_pkts;
	unsigned long oa_downward_timeout_so_pkts;
	unsigned long oa_downward_timeout_fo_jiffies;
	unsigned long oa_downward_timeout_so_jiffies;
	int oa_downward_policy;
#define	OA_DOWN_PKTS		1
#define	OA_DOWN_JIFFIES		2
};
struct rohc_compresser{
	char  name[ROHC_NAME_LEN];
	u8    hdr_len_resv;
	bool  comp_eth_hdr;
	enum rohc_cid_type cid_type;
	u32	max_cid;

	unsigned long *context_bitmap;
	struct list_head context_list;
	struct rohc_rb_root	 comp_rb;
	struct rohc_comp_refresh_threshold refresh_thresholds;
	struct rohc_comp_context_hash  ipv4_hash;
	struct rohc_comp_context_hash  ipv6_hash;
	struct rohc_comp_context *uncomp_context;
	spinlock_t	ctxt_lock;
	struct rohc_comp_profile **profiles;
	void *priv;
};


#define		COMP_CONTEXT_CID_TYPE(context)	((context)->compresser->cid_type)

int rohc_comp_deliver_feedback(struct rohc_compresser *comp,struct sk_buff *feedback_skb);
void rohc_comp_context_change_mode(struct rohc_comp_context *context,int mode);
void rohc_comp_context_change_state(struct rohc_comp_context *context,int state);
void rohc_comp_set_refresh_param(struct rohc_compresser *comp,struct rohc_comp_refresh_threshold *set);
struct rohc_compresser *rohc_comp_alloc(enum rohc_cid_type cid_type,u32 max_cids,void (*setup)(struct rohc_compresser *comp),char *name);
int rohc_comp_compress(struct rohc_compresser *comp,struct sk_buff *skb,gfp_t flags);
#endif
