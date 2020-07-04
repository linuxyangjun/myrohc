#ifndef	D__COMP_RTP_COMMON_H
#define	D__COMP_RTP_COMMON_H

#define	TS_STRIDE_DEFAULT	160
struct last_comped_rtp{
	struct rtphdr rtph;
	int tsc;
	u32 ts_stride;
	u32 ts_residue;
};


struct rtph_field_update{
	bool p_update;
	bool m_update;
	bool x_update;
	bool pt_update;
	bool ts_update;
	bool ts_stride_update;
	bool ts_residue_update;
	bool tsc_update;

	u32 ts_stride_use;
	u32 ts_stride_true;
	u32 ts_scaled;
	u32 ts_residue;
	int tsc;

	struct rohc_bits_encode_set ts_encode_bits;
	struct rohc_bits_encode_set ts_scaled_encode_bits;
	struct rohc_bits_encode_set ts_sdvl_encode_bits;
	struct rohc_bits_encode_set ts_stride_encode_bits;

};

struct rtph_update_trans_times{
	int tsc_trans_times;
	int ts_stride_trans_times;
	int ts_residue_trans_times;

	int pt_trans_times;
	int p_trans_times;
	int x_trans_times;
	int ts_trans_times;
	int m_trans_times;
};

static inline void reset_rtph_all_trans_times(struct rtph_update_trans_times *trans_times)
{
	memset(trans_times,0,sizeof(struct rtph_update_trans_times));
}
static inline void confident_rtph_all_trans_times(struct rtph_update_trans_times *trans_times,int oa_max)
{
	trans_times->tsc_trans_times = oa_max;
	trans_times->ts_stride_trans_times = oa_max;
	trans_times->ts_residue_trans_times = oa_max;
	trans_times->ts_trans_times = oa_max;

	trans_times->pt_trans_times = oa_max;
	trans_times->p_trans_times = oa_max;
	trans_times->x_trans_times = oa_max;
	trans_times->m_trans_times = oa_max;
}
static inline void inc_rtph_all_trans_times(struct rtph_update_trans_times *trans_times)
{
	trans_times->tsc_trans_times++;
	trans_times->ts_stride_trans_times++;
	trans_times->ts_residue_trans_times++;
	trans_times->ts_trans_times++;

	trans_times->pt_trans_times++;
	trans_times->p_trans_times++;
	trans_times->x_trans_times++;
	trans_times->m_trans_times++;
}

static inline void inc_rtph_dyanmic_field_trans_times(struct rtph_update_trans_times *trans_times,int field)
{
	switch(field){
		case RTPH_FIELD_X:
			trans_times->x_trans_times++;
			break;
		case RTPH_FIELD_P:
			trans_times->p_trans_times++;
			break;
		case RTPH_FIELD_M:
			trans_times->m_trans_times++;
			break;
		case RTPH_FIELD_PT:
			trans_times->pt_trans_times++;
			break;
		case RTPH_FIELD_TS:
			trans_times->ts_trans_times++;
			trans_times->ts_stride_trans_times++;
			trans_times->ts_residue_trans_times++;
			break;
		case RTPH_FIELD_TS_SCALED:
			trans_times->ts_trans_times++;
			break;
	}
}
#endif
