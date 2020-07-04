#ifndef	D__DECOMP_RTP_COMMON_H
#define	D__DECOMP_RTP_COMMON_H

struct last_decomped_rth{
	struct rtphdr rtph;
	u32 ts_stride;
	u32 ts_residue;
	bool tsc;

};


struct rtph_static_fields{
	u32 ssrc;
	bool update;
};

struct rtph_dynamic_fields{

	struct analyze_field x;
	struct analyze_field p;
	struct analyze_field version;
	struct analyze_field pt;
	struct analyze_field m;

	struct wlsb_analyze_field ts_scaled;
	struct wlsb_analyze_field ts;

	/*for timestamp scaled*/
	struct analyze_field tsc;
	struct analyze_field ts_stride;
	struct analyze_field ts_residue;

};
struct rtph_analyze_fields{
	struct rtph_static_fields static_fields;
	struct rtph_dynamic_fields dynamic_fields;
};

struct rtp_decode_rtph{
	struct rtphdr rtph;
};


#endif
