#ifndef	D__COMP_UDP_H
#define	D__COMP_UDP_H

struct udp_context_info{
	struct udphdr udph;
	int	check_behavior;

};


struct udph_update{
	u16 checksum;
	int check_behavior;
	bool check_update;
};
struct udp_oa_send_info{
	int check_send_pkts;
};
struct comp_udp_context{
	struct udp_context_info last_context_info;
	struct udph_update update_by_packet;
	struct udp_oa_send_info oa_send_pkts;
};
#endif
