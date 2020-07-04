#ifndef D__ROHC_COMP_IPV4_HASH_H
#define	D__ROHC_COMP_IPV4_HASH_H
#include "rohc_comp_hash.h"
struct  ipv4_hash_match{
	u32 saddr;
	u32 daddr;
	u32 protocol;
	u32 src_port;
	u32 dst_port;

};

void rohc_comp_context_hash_ipv4_init(struct rohc_comp_context_hash *c_hash);

#endif
