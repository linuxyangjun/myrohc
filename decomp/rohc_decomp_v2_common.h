#ifndef D__ROHC_DECOMP_V2_COMMON_H
#define D__ROHC_DECOMP_V2_COMMON_H
#include <linux/types.h>
#include <linux/ip.h>

#include "../rohc_ipid.h"
#include "rohc_decomp_wlsb.h"
struct last_decomped_iph{
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

struct iph_dynamic_fields{
	struct analyze_field tos_tc;
	struct analyze_field ttl_hl;

	/*next fields only ipv4 header*/
	struct analyze_field df;
	struct analyze_field ipid_bh;
	struct wlsb_analyze_field ipid;
};

struct ipv4h_static_fields{
	u8 version;
	u8 protocol;
	u32 saddr;
	u32 daddr;
	bool update;
};

struct ipv6h_static_fields{

};
struct ipv4h_analyzed_fields{
	struct ipv4h_static_fields static_fields;
	struct iph_dynamic_fields dynamic_fields;
};
struct ipv6h_analyzed_fields{
	struct ipv6h_static_fields static_fields;
	struct iph_dynamic_fields dynamic_fields;
};

struct iph_analyzed_fields{
	struct analyze_field ip_version;
	bool   outer_ind;
	union{
		struct ipv4h_analyzed_fields ipv4_fields;
		struct ipv6h_analyzed_fields ipv6_fields;
	};
};

struct iph_decoded{
	union{
		struct iphdr iph;
		struct ipv6hdr ipv6h;
	};
	union{
		struct iphdr inner_iph;
		struct ipv6hdr inner_ipv6h;
	};
};

struct decomp_iph_field_update{
	bool has_inner_iph;
	struct iph_analyzed_fields iph_fields;
	struct iph_analyzed_fields inner_iph_fields;
#define	outer_ipid	iph_fields.ipv4_fields.dynamic_fields.ipid
#define	innermost_ipid	inner_iph_fields.ipv4_fields.dynamic_fields.ipid
#define	outer_ipid_bh	iph_fields.ipv4_fields.dynamic_fields.ipid_bh
#define	innermost_ipid_bh	inner_iph_fields.ipv4_fields.dynamic_fields.ipid_bh
	struct iph_decoded decoded_iphs;
};


struct rohc_v2_decomp_iph_context{
	struct last_decomped_iph iph_ref;
	struct decomp_iph_field_update update_by_packet;
	struct rohc_decomp_wlsb	*ip_id_wlsb[ROHC_V2_MAX_IP_HDR];
#define	outer_ipidoff_wlsb		ip_id_wlsb[ROHC_OUTER_IPH]
#define	innermost_ipidoff_wlsb	ip_id_wlsb[ROHC_INNER_IPH]

};

struct rohc_v2_common_update{
	struct wlsb_analyze_field msn;
	struct analyze_field reorder_ratio;
};
struct rohc_v2_common_decode{
	u32 new_msn;
};
struct rohc_v2_decomp_common_context{
	struct rohc_v2_decomp_iph_context iph_context;
	struct rohc_v2_common_update co_update;
	struct rohc_v2_common_decode co_decode;

	enum rohc_v2_reordering_ratio r_ratio;

	struct rohc_decomp_wlsb *msn_wlsb;
	void *inherit_context;
};

u8 rohc_v2_iph_obtain_version(struct decomp_iph_field_update *iph_update,struct last_decomped_iph *iph_ref,bool is_inner);
void fill_innermost_iph_dynamic_fields(struct decomp_iph_field_update *iph_update,struct last_decomped_iph *iph_ref,int field,u32 value);
struct wlsb_analyze_field *pick_innermost_ipid_field(struct decomp_iph_field_update *iph_update,struct last_decomped_iph *iph_ref);
int rohc_v2_decode_common_msn(struct rohc_v2_decomp_common_context *co_context);
int rohc_v2_decomp_analyze_generic_co_common(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first);
int rohc_v2_decomp_analyze_pt_0_crc3(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first);
int rohc_v2_decomp_analyze_pt_0_crc7(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first);
int rohc_v2_decomp_analyze_pt_1_seq_id(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first);
int rohc_v2_decomp_analyze_pt_2_seq_id(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first);
int rohc_v2_decomp_analyze_ip_static_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
int rohc_v2_decomp_analyze_ip_dynamic_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
int rohc_v2_decomp_analyze_ip_irr_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
int rohc_v2_decode_ip_header(struct rohc_v2_decomp_iph_context *iph_context,struct rohc_decomp_pkt_hdr_info *pkt_info,u32 msn);
int rohc_v2_rebuild_ip_header(struct rohc_v2_decomp_iph_context *iph_context,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
void rohc_v2_ip_context_update(struct rohc_v2_decomp_iph_context *iph_context,u32 msn);

int rohc_v2_ip_init_context(struct rohc_v2_decomp_iph_context *iph_context);
void rohc_v2_ip_destroy_context(struct rohc_v2_decomp_iph_context *iph_context);
bool rohc_v2_has_innermost_iph(struct decomp_iph_field_update *iph_update,struct last_decomped_iph *iph_ref);
#endif
