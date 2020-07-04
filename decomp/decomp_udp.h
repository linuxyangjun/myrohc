#ifndef	D__DECOMP_UDP__H
#define	D__DECOMP_UDP__H

#include <linux/udp.h>
#include <linux/types.h>
#include <linux/kernel.h>

#include "../rohc_packet_field.h"
#include "rohc_decomp_wlsb.h"

struct last_udph_info{
	struct udphdr udph;
	int check_behavior;
};

struct udph_decomp_dynamic_part{
	struct analyze_field check;

};


struct udph_decomp_fields{
	struct udp_static_fields udp_static_part;
	bool  udp_static_fields_update;
	struct udph_decomp_dynamic_part udph_dynamic_part;
};
struct udph_decomp_update{
	struct udph_decomp_fields udph_fields;
	struct analyze_field udp_check_bh;
	struct udphdr  decoded_udph;
};
struct decomp_udp_context{
	struct last_udph_info last_context_info;
	struct udph_decomp_update update_by_packet;
};
#endif
