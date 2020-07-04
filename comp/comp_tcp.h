#ifndef	D__COMP_TCP_H
#define D__COMP_TCP_H

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/types.h>

#include "rohc_comp_wlsb.h"
#include "comp_tcp_clist.h"

#define	RATE_PERCENT_50		(50)

#define	ROHC_TCP_WLSB_K_R_0_TO_P	0
#define	ROHC_TCP_WLSB_K_R_1_TO_P	1
#define	ROHC_TCP_WLSB_K_R_2_TO_P	2
#define	ROHC_TCP_WLSB_K_R_3_TO_P	3


#define	IP_FIELD_DSCP	1
#define	IP_FIELD_TTL_HL	2
#define	IP_FIELD_DF	3
#define	IP_FIELD_IPID_BH 4



#define	TCP_FIELD_WIN		1
#define	TCP_FIELD_ACK_SEQ	2
#define	TCP_FIELD_SEQ		3
#define	TCP_FIELD_ACK_STRIDE	4
#define	TCP_FIELD_SEQ_SCALED	5
#define	TCP_FIELD_ACK_SEQ_RESIDUE 6

struct last_comped_iph_ref{
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

struct iph_update{
	/*ipv4 header update */
	bool dscp_update;
	bool ttl_hl_update;
	bool ipid_bh_update;
	bool ip_id_offset_update;
	bool df_update;
	bool ecn_carryed;
	u16  new_ip_id_offset;
	struct	rohc_bits_encode_set new_ipid_off_encode_bits;
	struct  rohc_bits_encode_set inner_ttl_hl_encode_bits;
	enum	ip_id_behavior new_ipid_bh;
	/*ipv6 header update*/

};
struct iph_update_trans_times{
	int dscp_trans_time;
	int ttl_hl_trans_time;
	int df_trans_time;
	int ipid_bh_trans_time;
};


struct tcp_iph_context{
	/* ip header reference
	 */
	struct last_comped_iph_ref iph_ref;
	struct iph_update	update_by_packet;
	struct iph_update	inner_update_by_packet;

	struct comp_win_lsb	*ttl_hl_wlsb;
	struct comp_win_lsb *ip_id_wlsb[ROHC_MAX_IP_HDR];
	#define	ipid_wlsb		ip_id_wlsb[ROHC_OUTER_IPH]
	#define	inner_ipid_wlsb		ip_id_wlsb[ROHC_INNER_IPH]
	bool is_first_packet;
	struct iph_update_trans_times update_trans_times;
	struct iph_update_trans_times inner_update_trans_times;
};


struct last_comped_tcph_ref{
	struct tcphdr tcph;
	u32	ack_stride;
	u32	ack_seq_residue;
	u32	seq_factor;
	u32	seq_residue;
	//struct tcph_carryed_options tcph_options;
};

struct tcph_update{
	u32	ack_stride_use;
	u32	ack_stride_true;
	u32	ack_seq_scaled;
	u32	ack_seq_residue;
	u32	seq_factor;
	u32	seq_scaled;
	u32	seq_residue;
	bool	ack_flag_update;
	bool	urg_flag_update;
	bool	urg_ptr_update;
	bool	rsf_flags_update;
	bool	rsf_carray_one_or_zero_bit;
	bool	res1_flags_update;
	bool	ack_stride_update;
	bool	ack_seq_update;
	bool	seq_update;
	bool	window_update;
	bool	ack_seq_residue_update;
	bool	seq_scale_factor_or_residue_update;
	bool	urg_carryed;
	bool	ecn_carryed;
	struct  rohc_bits_encode_set ack_seq_encode_bits;
	struct  rohc_bits_encode_set ack_seq_scaled_encode_bits;
	struct	rohc_bits_encode_set seq_encode_bits;
	struct	rohc_bits_encode_set seq_scaled_encode_bits;
	struct	rohc_bits_encode_set window_encode_bits;
	struct	rohc_bits_encode_set msn_encode_bits;
};
struct tcph_update_trans_times{
	u32 window_trans_time;
	u32 ack_seq_trans_time;
	u32 seq_trans_time;
	u32 ack_stride_trans_time;
	u32 new_ack_seq_residue_trans_time;
	u32 new_seq_scaled_encode_trans_time;
};


struct tcph_context{
	struct last_comped_tcph_ref tcph_ref;
	struct tcph_update	tcph_update_by_packet;
	struct tcph_update_trans_times update_trans_times;
	struct comp_win_lsb	*ack_seq_wlsb;
	struct comp_win_lsb	*ack_seq_scaled_wlsb;
	struct comp_win_lsb	*seq_wlsb;
	struct comp_win_lsb	*seq_scaled_wlsb;
	struct comp_win_lsb	*ack_stride_wlsb;
	struct comp_win_lsb	*window_wlsb;
	struct comp_win_lsb	*msn_wlsb;
};


struct comp_tcp_context{
	bool	last_ecn_used;
	bool	ecn_used;
	bool	ecn_used_update;
	int	ecn_used_trans_time;
	struct tcp_iph_context	ip_context;
	struct tcph_context	tcp_context;
	struct tcph_option_context tcp_opt_context;
	int	oa_upward_pkts;
};





static inline void increase_tcph_all_trans_times(struct tcph_update_trans_times *trans_times)
{
	trans_times->window_trans_time++;
	trans_times->ack_seq_trans_time++;
	trans_times->seq_trans_time++;
	trans_times->ack_stride_trans_time++;
	trans_times->new_ack_seq_residue_trans_time++;
	trans_times->new_seq_scaled_encode_trans_time++;
}

static inline void confident_tcph_all_trans_times(struct tcph_update_trans_times *trans_times,int oa_max)
{
	trans_times->window_trans_time = oa_max;
	trans_times->ack_seq_trans_time = oa_max;
	trans_times->seq_trans_time = oa_max;
	trans_times->new_ack_seq_residue_trans_time = oa_max;
	trans_times->new_seq_scaled_encode_trans_time = oa_max;
	trans_times->ack_stride_trans_time = oa_max;
}
static inline void reset_tcph_all_trans_times(struct tcph_update_trans_times *trans_times)
{
	memset(trans_times,0,sizeof(struct tcph_update_trans_times));
}
static inline void increase_iph_all_trans_times(struct iph_update_trans_times *trans_times)
{
	trans_times->dscp_trans_time++;
	trans_times->ttl_hl_trans_time++;
	trans_times->df_trans_time++;
	trans_times->ipid_bh_trans_time++;
}

static inline void confident_iph_all_trans_times(struct iph_update_trans_times *trans_times,int oa_max)
{
	trans_times->dscp_trans_time = oa_max;
	trans_times->ttl_hl_trans_time = oa_max;
	trans_times->df_trans_time = oa_max;
	trans_times->ipid_bh_trans_time = oa_max;
}
static inline void reset_iph_all_trans_times(struct iph_update_trans_times *trans_times)
{
	memset(trans_times,0,sizeof(struct iph_update_trans_times));
}
static inline void increase_iph_dynamic_field_trans_times(struct iph_update_trans_times *trans_times,int type)
{
	switch(type){
		case IP_FIELD_DSCP:
			trans_times->dscp_trans_time++;
			break;
		case IP_FIELD_TTL_HL:
			trans_times->ttl_hl_trans_time++;
			break;
		case IP_FIELD_DF:
			trans_times->df_trans_time++;
			break;
		case IP_FIELD_IPID_BH:
			trans_times->ipid_bh_trans_time++;
			break;
		default:
			break;
	}
}

static inline void increase_tcph_dynamic_field_trans_times(struct tcph_update_trans_times *trans_times,int type)
{
	switch(type){
		case TCP_FIELD_WIN:
			trans_times->window_trans_time++;
			break;
		case TCP_FIELD_ACK_SEQ:
			trans_times->ack_seq_trans_time++;
			break;
		case TCP_FIELD_SEQ:
			trans_times->seq_trans_time++;
			break;
		case TCP_FIELD_ACK_STRIDE:
			trans_times->ack_stride_trans_time++;
			break;
		case TCP_FIELD_ACK_SEQ_RESIDUE:
			trans_times->new_ack_seq_residue_trans_time++;
			break;
		case TCP_FIELD_SEQ_SCALED:
			trans_times->new_seq_scaled_encode_trans_time++;
			break;
		default:
			break;
	}
}

/*packet type adjust*/


#endif
