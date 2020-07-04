#ifndef D__DECOMP_RTP_V2_H
#define	D__DECOMP_RTP_V2_H
#include <linux/types.h>
#include "decomp_rtp_common.h"
#include "decomp_udp_v2.h"
struct decomp_rtph_field_update{
	struct rtph_analyze_fields rtph_fields;
	struct rtp_decode_rtph decoded_rtph;
};

struct decomp_v2_rtph_context{
	struct last_decomped_rth rtph_ref;
	struct decomp_rtph_field_update update_by_packet;
	struct rohc_decomp_wlsb *ts_wlsb;
	struct rohc_decomp_wlsb *ts_scaled_wlsb;
};


struct decomp_rtp_v2_context{
	struct decomp_udp_v2_context udph_context;
	struct decomp_v2_rtph_context rtph_context;
	struct decomp_rtp_csrc_context csrc_context;
};
#endif
