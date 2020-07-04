#ifndef	D__ROHC_PROFILE_V1_H
#define D__ROHC_PROFILE_V1_H
#include <linux/skbuff.h>
#include <linux/types.h>

#include "../rohc_packet.h"

#include "rohc_decomp.h"
#include "decomp_ip.h"
#include "rohc_decomp_wlsb.h"

struct decomp_profile_v1_ops{
	int (*adjust_extension_type)(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
	int (*analyze_extension)(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info);
};


struct decomp_profile_v1_context{
	struct decomp_profile_v1_ops *prof_v1_ops;
	struct decomp_ip_context  ip_context;
	struct wlsb_analyze_field msn_update;
	struct rohc_decomp_wlsb *msn_wlsb;
	u16 msn;
	enum rohc_ext_type ext_type;
	void *inherit_context;
};
int rohc_decomp_profile_v1_init_context(struct decomp_profile_v1_context *context,struct decomp_profile_v1_ops *v1_ops);
#endif
