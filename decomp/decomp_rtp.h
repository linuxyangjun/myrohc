#ifndef	D__DECOMP_RTP_H
#define	D__DECOMP_RTP_H

#include "../profile/rtp_profile.h"
#include "decomp_rtp_common.h"
/*Because the structure of profile-udp and
 * profile-rtp packets are different,so in
 * the implementation of RTP,i merged UDP
 * and rtp
 */

struct last_decomped_udph{
	/*for udp*/
	struct udphdr udph;
	int udp_check_behavior;
};

struct udp_static_part{
	u16 sport;
	u16 dport;
	bool update;
};

struct udp_dynamic_part{
	struct analyze_field check;
	struct analyze_field check_bh;
};


struct udph_analyze_fields{
	struct udp_static_part static_field;
	struct udp_dynamic_part dynamic_fields;
};


struct udp_decode_udph{
	struct udphdr udph;
};
struct decomp_rtph_update{
	struct rtph_analyze_fields analyze_fields;
	struct rtp_decode_rtph decode_rtph;
};

struct decomp_udph_update{
	struct udph_analyze_fields analyze_fields;
	struct udp_decode_udph decomp_udph;
};


struct decomp_udph_context{
	struct last_decomped_udph udph_ref;
	struct decomp_udph_update update_by_packet;
};

struct decomp_rtph_context{
	struct last_decomped_rth rtph_ref;
	struct decomp_rtph_update update_by_packet;
	struct rohc_decomp_wlsb *ts_scaled_wlsb;
	struct rohc_decomp_wlsb *ts_wlsb;
};


struct decomp_rtp_context{
	struct decomp_udph_context udp_context;
	struct decomp_rtph_context rtp_context;
	struct decomp_rtp_csrc_context csrc_context;
};
#endif
