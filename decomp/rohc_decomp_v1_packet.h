#ifndef	D__ROHC_DECOMP_V1_PACKET_H
#define	D__ROHC_DECOMP_V1_PACKET_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include "rohc_decomp.h"

int rohc_decomp_analyze_extension(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
int rohc_decomp_adjust_extension_type(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);


int rohc_decomp_analyze_uo0(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
int rohc_decomp_analyze_uo1(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
int rohc_decomp_analyze_uro2(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);

int rohc_decomp_analyze_ip_static_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
int rohc_decomp_analyze_ip_dynamic_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);

int rohc_decomp_analyze_extension(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
int rohc_decomp_adjust_extension_type(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
enum rohc_packet_type rohc_decomp_adjust_packet_type(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
#endif
