#ifndef	D__COMP_RTP_H
#define	D__COMP_RTP_H
#include "../profile/rtp_profile.h"
#include "rohc_comp_profile_v1.h"
#include "comp_rtp_common.h"







struct  rtp_context{
	bool is_first_packet;
	int  oa_upward_pkts;
	struct last_comped_rtp rtph_ref;
	struct rtph_field_update update_by_packet;
	struct rohc_comp_wlsb *ts_stride_wlsb;
	struct rohc_comp_wlsb *ts_wlsb;
	struct rohc_comp_wlsb *ts_scaled_wlsb;

	struct rtph_update_trans_times update_trans_times;
};

struct comp_rtp_context{
	struct rtp_context rtp_context;
	struct rtp_csrc_context csrc_context;
};
static inline bool rohc_packet_carryed_ipid(enum rohc_packet_type packet_type)
{
	if(packet_type == ROHC_PACKET_TYPE_UO_1_ID || packet_type == ROHC_PACKET_TYPE_URO_2_ID)
		return true;
	else
		return false;
}

static inline bool rtp_dynamic_fields_update_without_m(struct rtph_update *update,struct rtp_csrc_update *csrc_update)
{
	bool retval = false;
	if(update->pt_update || \
	   update->x_update || \
	   update->ts_stride_update || \
	   update->p_update || \
	   update->tsc_update || \
	   csrc_update->csrc_list_update)
		retval = true;
	else
		retval = false;
	return retval;
}

static inline bool rohc_packet_carryed_msn_4bits(enum rohc_packet_type packet_type)
{
	bool retval = false;
	if(packet_type == ROHC_PACKET_TYPE_UO_1 || packet_type == ROHC_PACKET_TYPE_UO_1_ID || packet_type == ROHC_PACKET_TYPE_UO_1_TS)
		retval = true;
	else
		retval = false;
	return retval;
}
#endif
