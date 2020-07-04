#ifndef		D_ROHC_COMP_PACKET__H
#define		D_ROHC_COMP_PACKET__H
#include <linux/skbuff.h>
#include <linux/types.h>
#include "rohc_comp.h"

int rohc_comp_build_ir(struct rohc_comp_context *context , struct sk_buff *skb , struct rohc_comp_packet_hdr_info *pkt_info);
int rohc_comp_build_ir_dyn(struct rohc_comp_context *context , struct sk_buff *skb , struct rohc_comp_packet_hdr_info *pkt_info);

int rohc_comp_build_co_repair(struct rohc_comp_context *context,const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
#endif
