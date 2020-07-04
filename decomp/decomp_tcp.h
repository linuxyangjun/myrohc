#ifndef	D__DECOMP_TCP_H
#define	D__DECOMP_TCP_H
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/types.h>

#include "../rohc_common.h"
#include "../rohc_ipid.h"
#include "rohc_decomp_wlsb.h"
#include "decomp_tcp_clist.h"
#define	ANALYZE_IP_FIELD_DSCP	1
#define	ANALYZE_IP_FIELD_TTL_HL	2
#define	ANALYZE_IP_FIELD_DF	3
#define	ANALYZE_IP_FIELD_IPID_BH 4
#define	ANALYZE_IP_FIELD_ECN	5
#define ANALYZE_IP_FIELD_IPID	6


#define	DECOMP_TCP_FIELD_WIN		1
#define	DECOMP_TCP_FIELD_ACK_SEQ	2
#define	DECOMP_TCP_FIELD_SEQ		3
#define	DECOMP_TCP_FIELD_ACK_STRIDE	4
#define	DECOMP_TCP_FIELD_SEQ_SCALED	5
#define	DECOMP_TCP_FIELD_ACK_SEQ_RESIDUE 6
#define	DECOMP_TCP_FIELD_ACK_F		7
#define	DECOMP_TCP_FIELD_FIN_F		8
#define	DECOMP_TCP_FIELD_SYN_F		9
#define	DECOMP_TCP_FIELD_RST_F		10
#define	DECOMP_TCP_FIELD_URG_F		11
#define DECOMP_TCP_FIELD_RES_F		12

struct last_decomped_iph_ref{
	bool has_inner_iph;
	int iph_num;
	union{
		struct iphdr iph;
		struct ipv6hdr ipv6h;
	};
	union{
		struct iphdr inner_iph;
		struct ipv6hdr inner_ipv6;
	};
	enum ip_id_behavior ipid_bh;
	enum ip_id_behavior inner_ipid_bh;
};
struct tcp_iph_dynamic_fields{
	struct wlsb_analyze_field ttl_hl;

	struct analyze_field dscp;
	struct analyze_field ecn;

	/*next fields only ipv4*/
	struct analyze_field ipid_bh;
	struct analyze_field df;
	struct wlsb_analyze_field ipid;
};

struct tcp_ipv4h_static_fields{
	u8 version;
	u8 protocol;
	u32 saddr;
	u32 daddr;
	bool	update;
};

struct tcp_ipv4h_analyze_fields{
	struct tcp_ipv4h_static_fields static_fields;
	struct tcp_iph_dynamic_fields  dynamic_fields;
};
struct tcp_ipv6h_analyze_fields{
	struct tcp_iph_dynamic_fields dynamic_fields;
};

struct tcp_iph_analyze_fields{
	u8 ip_version;
	bool ip_version_update;
	bool outer_ttl_hl_carryed;
	union{
		struct tcp_ipv4h_analyze_fields ipv4_analyze_fields;
		struct tcp_ipv6h_analyze_fields ipv6_analyze_fields;
	};
};
struct tcp_decode_iph{
	union{
		struct iphdr iph;
		struct ipv6hdr ipv6h;
	};
	union{
		struct iphdr inner_iph;
		struct ipv6hdr inner_ipv6h;
	};
};
struct tcp_iph_update{
	bool has_inner_iph;
	struct tcp_iph_analyze_fields iph_analyze_fields;
	struct tcp_iph_analyze_fields inner_iph_analyze_fields;
#define	new_ipid_bh	iph_analyze_fields.ipv4_analyze_fields.dynamic_fields.ipid_bh
#define	new_ipid	iph_analyze_fields.ipv4_analyze_fields.dynamic_fields.ipid
#define	new_inner_ipid_bh	inner_iph_analyze_fields.ipv4_analyze_fields.dynamic_fields.ipid_bh
#define	new_inner_ipid	iph_analyze_fields.ipv4_analyze_fields.dynamic_fields.ipid
	struct tcp_decode_iph decoded_iphs;
};

struct decomp_tcp_iph_context{
	struct last_decomped_iph_ref iph_ref;
	struct tcp_iph_update update_by_packet;
	struct rohc_decomp_wlsb *ip_id_wlsb[ROHC_MAX_IP_HDR];
#define	ipid_wlsb		ip_id_wlsb[ROHC_OUTER_IPH]
#define inner_ipid_wlsb		ip_id_wlsb[ROHC_INNER_IPH]
	struct rohc_decomp_wlsb *inner_ttl_hl_wlsb;
};

struct last_decomped_tcph_ref{
	struct tcphdr tcph;
	u32	ack_stride;
	u32	ack_seq_residue;
	u32	seq_residue;
	//u32	seq_factor;
};
struct tcph_static_fields{
	u16 sport;
	u16 dport;
	bool update;
};

struct tcph_dynamic_fields{
	struct wlsb_analyze_field msn;
	struct wlsb_analyze_field seq;
	struct wlsb_analyze_field ack_seq;
	struct wlsb_analyze_field window;
	struct wlsb_analyze_field seq_scaled;
	struct wlsb_analyze_field ack_seq_scaled;
	struct analyze_field ack_stride;
	struct analyze_field res1;
	struct analyze_field fin;
	struct analyze_field syn;
	struct analyze_field rst;
	struct analyze_field psh;
	struct analyze_field urg;
	struct analyze_field urg_ptr;
	struct analyze_field ack;
	struct analyze_field check;
	struct analyze_field ecn;

	struct analyze_field seq_residue;
	struct analyze_field ack_seq_residue;
};
struct tcph_analyze_fields{
	struct tcph_static_fields static_fields;
	struct tcph_dynamic_fields dynamic_fields;
};

struct tcp_decode_tcph{
	struct tcphdr tcph;
	u16 new_msn;

};

struct decomp_tcph_update{
	struct tcph_analyze_fields analyze_fields;
	struct tcp_decode_tcph decode_tcph;
};
struct decomp_tcph_context{
	struct last_decomped_tcph_ref tcph_ref;
	struct decomp_tcph_update update_by_packet;
	struct rohc_decomp_wlsb *seq_wlsb;
	struct rohc_decomp_wlsb *seq_scaled_wlsb;
	struct rohc_decomp_wlsb *ack_seq_wlsb;
	struct rohc_decomp_wlsb *ack_seq_scaled_wlsb;
	struct rohc_decomp_wlsb *window_wlsb;
	struct rohc_decomp_wlsb *msn_wlsb;
};

struct last_decomped_tcp_common{
	bool ecn_used;
};

struct decomp_tcp_common_update{
	struct analyze_field ecn_used;
};
struct decomp_tcp_context{
	struct last_decomped_tcp_common co_ref;
	struct decomp_tcp_common_update co_update;
	struct decomp_tcp_iph_context ip_context;
	struct decomp_tcph_context tcp_context;
	struct decomp_tcph_options_context opt_context;
	/*only for debug*/
	u16 debug_msn;
};

#endif
