#ifndef	D__DECOMP_IP_H
#define	D__DECOMP_IP_H
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include "../rohc_packet_field.h"
#include "../rohc_common.h"
#include "../rohc_ipid.h"
#include "rohc_decomp_wlsb.h"
#include "rohc_decomp.h"
struct last_iph_info{
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
};

struct iph_decomp_dynamic_part{
	struct analyze_field	tos_tc;
	struct analyze_field	ttl_hl;
	struct analyze_field pr_nh;

	/*only for ipv4
	 */
	struct analyze_field df;
	struct wlsb_analyze_field ip_id;
};
struct ipv4_decomp_fields{

	struct ip_static_fields iph_static_part;
	bool	ip_static_fields_update;
	struct iph_decomp_dynamic_part  iph_dynamic_part;
};
struct ipv6_decomp_fields{
	struct ipv6_static_fields iph6_static_part;
	bool ip_static_fields_update;
	struct iph_decomp_dynamic_part iph_dynamic_part;
};

struct iph_decomp_fields{
	u8 ip_version;
	bool ip_version_update;
	union{
		struct ipv4_decomp_fields iph;
		struct ipv6_decomp_fields ipv6h;
	};
};

struct decoded_iph_hdr{
	union{
		struct iphdr iph;
		struct ipv6hdr ipv6h;
	};
	union{
		struct iphdr inner_iph;
		struct ipv6hdr inner_ipv6h;
	};
};
struct iph_decomp_update{
	struct iph_decomp_fields iph_fields;
	struct iph_decomp_fields inner_iph_fields;
	bool has_inner_iph;
	int iph_num;
	struct analyze_field ipid_bh;
	struct analyze_field inner_ipid_bh;
	struct decoded_iph_hdr decoded_iphdr;

};

struct decomp_iph_context_info{

	enum ip_id_behavior ip_id_bh[ROHC_MAX_IP_HDR];
	struct last_iph_info iph_save_info;
	bool has_inner_iph;
};

struct decomp_ip_context{
	struct decomp_iph_context_info	last_context_info;
	struct iph_decomp_update	update_by_packet;
	struct rohc_decomp_wlsb	*ipid_wlsb[ROHC_MAX_IP_HDR];

};

static inline u8 decomp_ip_obain_vesion(struct decomp_iph_context_info *last_context_info,struct iph_decomp_update *iph_update,bool is_inner)
{
	struct iphdr *iph;
	struct iph_decomp_fields *new_iph_update;
	u8 version;
	if(is_inner){
		iph = &last_context_info->iph_save_info.inner_iph;
		new_iph_update = &iph_update->inner_iph_fields;
	}else{
		iph = &last_context_info->iph_save_info.iph;
		new_iph_update = &iph_update->iph_fields;
	}
	if(new_iph_update->ip_version_update)
		version = new_iph_update->ip_version;
	else
		version = iph->version;
	return version;
}
static inline enum ip_id_behavior decomp_ipv4_obain_new_ipid_bh(struct decomp_iph_context_info *last_context_info,struct iph_decomp_update *iph_update,bool is_inner)
{
	struct analyze_field *ipid_bh;
	enum ip_id_behavior new_ipid_bh;
	if(is_inner){
		ipid_bh = &iph_update->inner_ipid_bh;
		new_ipid_bh = last_context_info->ip_id_bh[ROHC_INNER_IPH];
	}else{
		ipid_bh = &iph_update->ipid_bh;
		new_ipid_bh = last_context_info->ip_id_bh[ROHC_OUTER_IPH];
	}
	if(analyze_field_is_carryed(ipid_bh))
		new_ipid_bh = (enum ip_id_behavior)ipid_bh->value;
	return new_ipid_bh;
}
static inline bool rohc_decomp_has_inner_iph(struct decomp_iph_context_info *last_context_info,struct iph_decomp_update *iph_update)
{
	int retval = false;
	if(iph_update->has_inner_iph || last_context_info->has_inner_iph)
		retval = true;
	return retval;
}

static inline struct wlsb_analyze_field *ip_pick_high_priority_ipid(struct decomp_iph_context_info *iph_ref,struct iph_decomp_update *iph_update)
{
	struct wlsb_analyze_field *ipid_field;
	if(rohc_decomp_has_inner_iph(iph_ref,iph_update)){
		if(rohc_iph_is_v4(decomp_ip_obain_vesion(iph_ref,iph_update,true)) && \
		   !ip_id_is_random_or_constant(decomp_ipv4_obain_new_ipid_bh(iph_ref,iph_update,true)))
			ipid_field = &iph_update->inner_iph_fields.iph.iph_dynamic_part.ip_id;
		else if(rohc_iph_is_v4(decomp_ip_obain_vesion(iph_ref,iph_update,false) && \
			!ip_id_is_random_or_constant(decomp_ipv4_obain_new_ipid_bh(iph_ref,iph_update,false))))
			ipid_field = &iph_update->iph_fields.iph.iph_dynamic_part.ip_id;
		else
			ipid_field = NULL;
	}else{
		if(rohc_iph_is_v4(decomp_ip_obain_vesion(iph_ref,iph_update,false) && \
			!ip_id_is_random_or_constant(decomp_ipv4_obain_new_ipid_bh(iph_ref,iph_update,false))))
			ipid_field = &iph_update->iph_fields.iph.iph_dynamic_part.ip_id;
		else
			ipid_field = NULL;
	}
	return ipid_field;
}
int rohc_rebuild_ip_header(struct decomp_ip_context *ip_context,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
int rohc_update_ip_context(struct decomp_ip_context *ip_context,struct rohc_decomp_pkt_hdr_info *pkt_info,u32 msn);
int rohc_decode_ip_packet_header(struct decomp_ip_context *ip_context,struct rohc_decomp_pkt_hdr_info *pkt_info,u32 msn);

static inline void iphdr_dump(struct iphdr *iph,char *func)
{
	u8 *addr;
	rohc_pr(ROHC_DEBUG,"++++++ %s ++++++\n",func);
	rohc_pr(ROHC_DEBUG,"ipid=%d,tos=%d,ttl=%d\n",ntohs(iph->id),iph->tos,iph->ttl);
	addr = (u8 *)&iph->saddr;
	rohc_pr(ROHC_DEBUG,"ipsrc:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	addr = (u8 *)&iph->daddr;
	rohc_pr(ROHC_DEBUG,"ipdst:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	

}
#endif
