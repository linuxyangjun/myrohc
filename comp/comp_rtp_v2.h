#ifndef	D__COMP_RTP_V2_H
#define	D__COMP_RTP_V2_H

#include "comp_rtp_common.h"
#include "comp_udp_v2.h"

struct v2_rtph_context{
	struct last_comped_rtp rtph_ref;
	struct rtph_field_update update_by_packet;
	bool is_first_packet;

	struct comp_win_lsb *ts_wlsb;
	struct comp_win_lsb *ts_scaled_wlsb;
	struct comp_win_lsb *ts_stride_wlsb;
	struct rtph_update_trans_times update_trans_times;
};


struct comp_rtp_v2_context{
	struct comp_udp_v2_context udph_context;
	struct v2_rtph_context rtph_context;
	struct rtp_csrc_context csrc_context;
};

#endif
