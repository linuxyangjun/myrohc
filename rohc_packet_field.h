
#ifndef	D__ROHC_PACKET_FILED_H
#define	D__ROHC_PACKET_FILED_H
struct ip_static_fields{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8	rsv:4,
		version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8	version:4,
		rsv:4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	u8	protocol;
	u32	saddr;
	u32	daddr;
} __attribute__((packed));

struct ip_dynamic_fields{
	u8	tos;
	u8	ttl;
	u16	ip_id;
#if defined(__LITTLE_ENDIAN_BITFIELD)
        u8	rsv:4,
		constant:1,
		nbo:1,
		rnd:1,
		df:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8	df:1,
		rnd:1,
		nbo:1,
		constant:1,
		rsv:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	/**
	 *no ip extiosn header.
	 */
} __attribute__((packed));


struct ipv6_static_fields{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8			priority:4,
				version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8			version:4,
				priority:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8			flow_lbl[2];

	__u8			nexthdr;
	u8 saddr[16];
	u8 daddr[16];

} __attribute__((packed));

struct udp_static_fields{
	u16	sport;
	u16	dport;
};
struct udp_dynamic_fields{
	u16	checksum;
	/**
	 *For ROHC UDP ,the part of UDP packet is different
	 *from 5.7.7.5,a two-octet field containing the UDP
	 *SN is added after the checksum field.
	 */
	u16	msn;
};
static inline void rohc_packet_dump_ipv4_static(struct ip_static_fields *ip_static)
{
	u8 *addr;
	rohc_pr(ROHC_DEBUG,"version=%d,protocol=%x\n",ip_static->version,ip_static->protocol);
	addr = &ip_static->saddr;
	rohc_pr(ROHC_DEBUG,"ipsrc:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	addr = &ip_static->daddr;
	rohc_pr(ROHC_DEBUG,"ipsrc:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
}
#endif
