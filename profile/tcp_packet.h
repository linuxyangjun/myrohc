#ifndef	D__TCP_PACKET_H
#define	D__TCP_PACKET_H
struct profile_tcp_ipv4_static{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8	rsv:7,
		version:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8	version:1,
		rsv:7;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	u8	protocol;
	u32	saddr;
	u32	daddr;
} __attribute__((packed));

struct profile_tcp_ipv4_dynamic{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8	ipid_bh:2,
		df:1,
		rsv:5;
	u8	ecn_flags:2,
		dscp:6;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8	rsv:5,
		df:1,
		ipid_bh:2;
	u8	dscp:6,
		ecn_flags:2;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	u8	ttl_hl;
/*the filed that is dynamic exisence
 *ip_id =:= ip_id_enc_dyn(ip_id_behavior_innermost.UVALUE)
 */
} __attribute__((packed));

struct profile_tcp_ipv4_replicate{
	
} __attribute__((packed));

struct profile_tcp_static{
	u16	sport;
	u16	dport;
};

struct profile_tcp_dynamic{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8	res:4,
		urg_zero:1,
		ack_zero:1,
		ack_stride_ind:1,
		ecn_used:1;
	u8	rsf:3,
		push:1,
		ack:1,
		urg:1,
		ecn:2;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8	ecn_used:1,
		ack_stride:1,
		ack_zero:1,
		urg_zero:1,
		res:4;
	u8	ecn:2,
		urg:1,
		ack:1,
		push:1,
		rsf:3;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	u16	msn;
	u32	seq;
	u16	window;
	u16	check;
/*the filed that is dynamic exisence
 *ack_seq =:= zero_or_irreg(ack_zero.CVALUE,32)
 *urg_prtr
 *ack_stride
 *list_tcp_options
 */

} __attribute__((packed));

struct profile_tcp_replicate{};


struct profile_tcp_co_common{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ttl_hl:1,
	   disc:7;
	u8 msn:4,
	   rsf:2,
	   push:1,
	   ack:1;
	u8 urg_ind:1,
	   ip_id_ind:1,
	   win_ind:1,
	   ack_stride_ind:1,
	   ack_seq_ind:2,
	   seq_ind:2;
	u8 urg:1,
	   ipid_bh:2,
	   list_ind:1,
	   inner_ttl_hl:1,
	   dscp_ind:1,
	   ecn_used:1,
	   rsv:1;
	u8 crc:7,
	   df:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:7,
	   ttl_hl:1;
	u8 ack:1,
	   push:1,
	   rsf:2,
	   msn:4;
	u8 seq_ind:2,
	   ack_seq_ind:2,
	   ack_stride_ind:1,
	   win_ind:1,
	   ip_id_ind:1,
	   urg_ind:1;
	u8 rsv:1,
	   ecn_used:1,
	   dscp_ind:1,
	   inner_ttl_hl:1,
	   list_ind:1,
	   ipid_bh:2,
	   urg:1;
	u8 df:1,
	   crc:7;
#else
#error "wrong byteorder"
#endif
/*the next fileds is dynamic exisence
 */
/*seq =:= var_len_32_enc()
 */

} __attribute__((packed));

struct profile_tcp_rnd1{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 seq0:2,
	   disc:6;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:6,
	   seq0:2;
#endif
	u8 seq1;
	u8 seq2;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 crc:3,
	   push:1,
	   msn:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 msn:4,
	   push:1,
	   crc:3;
#endif

} __attribute__((packed));

struct profile_tcp_rnd2{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 seq_scaled:4,
	   disc:4;
	u8 crc:3,
	   push:1,
	   msn:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:4,
	   seq_scaled:4;
	u8 msn:4,
	   push:1,
	   crc:3;
#endif

} __attribute__((packed));

struct profile_tcp_rnd3{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ack_seq0:7,
	   disc:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:1,
	   ack_seq0:7;
#endif
	u8 ack_seq1;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 crc:3,
	   push:1,
	   msn:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 msn:4,
	   push:1,
	   crc:3;
#endif

} __attribute__((packed));

struct profile_tcp_rnd4{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ack_seq_scaled:4,
	   disc:4;
	u8 crc:3,
	   push:1,
	   msn:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:4,
	   ack_seq_scaled:4;
	u8 msn:4,
	   push:1,
	   crc:3;
#endif
} __attribute__((packed));

struct profile_tcp_rnd5{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 msn:4,
	   push:1,
	   disc:3;
	u8 seq0:5,
	   crc:3;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:3,
	   push:1,
	   msn:4;
	u8 crc:3,
	   seq0:5;
#endif
	u8 seq1;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ack_seq0:7,
	   seq2:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 seq2:1,
	   ack_seq0:7;
#endif
	u8 ack_seq1;
} __attribute__((packed));

struct profile_tcp_rnd6{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 push:1,
	   crc:3,
	   disc:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:4,
	   crc:3,
	   push:1;
#endif
	u16 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 seq_scaled:4,
	   msn:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 msn:4,
	   seq_scaled:4;
#endif
} __attribute__((packed));


struct profile_tcp_rnd7{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ack_seq0:2,
	   disc:6;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:6,
	   ack_seq0:2;
#endif
	u8 ack_seq1;
	u8 ack_seq2;
	u16 window;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 crc:3,
	   push:1,
	   msn:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 msn:4,
	   push:1,
	   crc:3;
#endif
} __attribute__((packed));


struct profile_tcp_rnd8{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 list_ind:1,
	   rsf:2,
	   disc:5;
	u8 msn0:1,
	   crc:7;
	u8 ecn_used:1,
	   ttl_hl:3,
	   push:1,
	   msn1:3;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:5,
	   rsf:2,
	   list_ind:1;
	u8 crc:7,
	   msn0:1;
	u8 msn1:3,
	   push:1,
	   ttl_hl:3,
	   ecn_used:1;
#endif
	u16 seq;
	u16 ack_seq;
/*next fileds is dynamic exisence
 */
/*tcp option list
 */
} __attribute__((packed));


struct profile_tcp_seq1{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ipid_off:4,
	   disc:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:4,
	   ipid_off:4;
#endif
	u16 seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 crc:3,
	   push:1,
	   msn:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 msn:4,
	   push:1,
	   crc:3;
#endif
} __attribute__((packed));

struct profile_tcp_seq2{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ipid_off0:3,
	   disc:5;
	u8 seq_scaled:4,
	   ipid_off1:4;
	u8 crc:3,
	   push:1,
	   msn:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:5,
	   ipid_off0:3;
	u8 ipid_off1:4,
	   seq_scaled:4;
	u8 msn:4,
	   push:1,
	   crc:3
#endif
} __attribute__((packed));

struct profile_tcp_seq3{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ipid_off:4,
	   disc:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:4,
	   ipid_off:4;
#endif
	u16 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 crc:3,
	   push:1,
	   msn:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 msn:4,
	   push:1,
	   crc:3;
#endif
} __attribute__((packed));


struct profile_tcp_seq4{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ipid_off:3,
	   ack_seq_scaled:4,
	   disc:1;
	u8 crc:3,
	   push:1,
	   msn:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:1,
	   ack_seq_scaled:4,
	   ipid_off:3;
	u8 msn:4,
	   push:1,
	   crc:3;
#endif
} __attribute__((packed));

struct profile_tcp_seq5{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ipid_off:4,
	   disc:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:4,
	   ipid_off:4;
#endif
	u16 ack_seq;
	u16 seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 crc:3,
	   push:1,
	   msn:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 msn:4,
	   push:1,
	   crc:3;
#endif
} __attribute__((packed));

struct profile_tcp_seq6{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 seq_scaled0:3,
	   disc:5;
	u8 ipid_off:7,
	   seq_scaled1:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:5,
	   seq_scaled0:3;
	u8 seq_scaled1:1,
	   ipid_off:7;
#endif
	u16 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 crc:3,
	   push:1,
	   msn:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 msn:4,
	   push:1,
	   crc:3;
#endif
} __attribute__((packed));

struct profile_tcp_seq7{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 win0:4,
	   disc:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:4,
	   win0:4;
#endif
	u8 win1;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ipid_off:5,
	   win2:3;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 win2:3,
	   ipid_off:5;
#endif
	u16 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 crc:3,
	   push:1,
	   msn:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 msn:4,
	   push:1,
	   crc:3;
#endif
} __attribute__((packed));

struct profile_tcp_seq8{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ipid_off:4,
	   disc:4;
	u8 crc:7,
	   list_ind:1;
	u8 ttl_hl:3,
	   push:1,
	   msn:4;
	u8 ack_seq0:7,
	   ecn_used:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:4,
	   ipid_off:4;
	u8 list_ind:1,
	   crc:7;
	u8 msn:4,
	   push:1,
	   ttl_hl:3;
	u8 ecn_used:1,
	   ack_seq0:7;
#endif
	u8 ack_seq1;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 seq0:6,
	   rsf:2;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 rsf:2,
	   seq0:6;
#endif
	u8 seq1;
/*next filed is dynamic exisence
 */
/* list option presnet
 */
} __attribute__((packed));
#endif
