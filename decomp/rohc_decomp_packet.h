#ifndef	D__ROHC_DECOMP_PACKET_H
#define	D__ROHC_DECOMP_PACKET_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include "rohc_decomp.h"

int rohc_decomp_analyze_ir(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
int rohc_decomp_analyze_ir_dyn(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);

/*for rohcv2 co repair*/
int rohc_decomp_analyze_co_repair(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
#endif
