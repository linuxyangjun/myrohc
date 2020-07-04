#ifndef	D__ROHC_V2_PACKET_H
#define	D__ROHC_V2_PACKET_H

struct pt_0_crc3{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 crc:3,
	   msn:4,
	   disc:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:1,
	   msn:4,
	   crc:3;
#endif
} __attribute__((packed));

struct pt_0_crc7_rtp{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 msn0:4,
	   disc:4;
	u8 crc:7,
	   msn1:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:4,
	   msn0:4;
	u8 msn1:1,
	   crc:7;
#endif
} __attribute__((packed));

struct pt_0_crc7{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 msn0:5,
	   disc:3;
	u8 crc:7,
	   msn1:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:3,
	   msn0:5,
	   msn1:1,
	   crc:7;
#endif
} __attribute__((packed));
struct pt_1_rnd{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 msn:4,
	   m:1,
	   disc:3;
	u8 crc:3,
	   ts_scaled:5;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:3,
	   m:1,
	   msn:4;
	u8 ts_scaled:5,
	   crc:3;

#endif
} __attribute__((packed));

struct pt_1_seq_id_rtp{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ipid_off:4,
	   disc:4;
	u8 crc:3,
	   msn:5;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:4,
	   ipid_off:4;
	u8 msn:5,
	   crc:3;
#endif
} __attribute__((packed));

struct pt_1_seq_id{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 msn0:2,
	   crc:3,
	   disc:3;
	u8 ipid_off:4,
	   msn1:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:3,
	   crc:3,
	   msn0:2;
	u8 msn1:4,
	   ipid_off:4
#endif
} __attribute__((packed));

struct pt_1_seq_ts{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 msn:4,
	   m:1,
	   disc:3;
	u8 crc:3,
	   ts_scaled:5;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:3,
	   m:1,
	   msn:4;
	u8 ts_scaled:5,
	   crc:3;
#endif
} __attribute__((packed));

struct pt_2_rnd{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 msn0:5,
	   disc:3;
	u8 ts_scaled:6,
	   msn1:2;
	u8 crc:7,
	   m:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:3,
	   msn0:5;
	u8 msn1:2,
	   ts_scaled:6;
	u8 m:1,
	   crc:7;
#endif
} __attribute__((packed));

struct pt_2_seq_id_rtp{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 msn0:3,
	   disc:5;
	u8 ipid_off0:4,
	   msn1:4;
	u8 crc:7,
	   ipid_off1:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:5,
	   msn0:3;
	u8 msn1:4,
	   ipid_off0:4;
	u8 ipid_off1:1,
	   crc:7;
#endif
} __attribute__((packed));

struct pt_2_seq_id{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ipid_off0:5,
	   disc:3;
	u8 crc:7,
	   ipid_off1:1;
	
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:3,
	   ipid_off0:5;
	u8 ipid_off1:1,
	   crc:7;
#endif
	u8 msn;
} __attribute__((packed));
struct pt_2_seq_both{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 msn0:3,
	   disc:5;
	u8 ipid_off0:4,
	   msn1:4;
	u8 crc:7,
	   ipid_off1:1;
	u8 m:1,
	   ts_scaled:7;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:5,
	   msn0:3;
	u8 msn1:4,
	   ipid_off0:4;
	u8 ipid_off1:1,
	   crc:7;
	u8 ts_scaled:7,
	   m:1;
#endif
} __attribute__((packed));

struct pt_2_seq_ts{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 msn0:4,
	   disc:4;
	u8 ts_scaled:5,
	   msn1:3;
	u8 crc:7,
	   m:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 disc:4,
	   msn0:4;
	u8 msn1:3,
	   ts_scaled:5;
	u8 m:1,
	   crc:7;
#endif
} __attribute__((packed));

/*  co_common_genric can be
 *  used for udp/udp-lite and
 *  ip-only
 */
struct co_common_generic{
	u8 disc;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 crc:7,
	   ipid_ind:1;
	u8 ctrl_crc:3,
	   reorder_ratio:2,
	   tos_tc_ind:1,
	   ttl_hl_ind:1,
	   flag:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 ipid_ind:1,
	   crc:7;
	u8 flag:1,
	   ttl_hl_ind:1,
	   tos_tc_ind:1,
	   reorder_ratio:2,
	   ctrl_crc:3;
#endif
	/*next fields are varibale length fields*/

} __attribute__((packed));

struct profile_rtp_co_common{
	u8 disc;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 crc:7,
	   mark:1;
	u8 ctrl_crc:3,
	   ipid_ind:1,
	   tss_ind:1,
	   tsc_ind:1,
	   flag2_ind:1,
	   flag1_ind:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 flag1_ind:1,
	   flag2_ind:1,
	   tsc_ind:1,
	   tss_ind:1,
	   ipid_ind:1,
	   ctrl_crc:3;
#endif
/*next fields are varibale length fields*/
} __attribute__((packed));

struct profile_udp_static{
	u16 sport;
	u16 dport;
};

struct profile_udp_endpoint_dynamic{
	u16 checksum;
	u16 msn;
	u8  rsv:6,
	    reorder_ratio:2;
} __attribute__((packed));

struct profile_udp_regular_dynamic{
	u16 checksum;
} __attribute__((packed));

struct profile_ipv4_static{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 rsvd:6,
	   innermost:1,
	   version:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 version:1,
	   innermost:1,
	   rsvd:6; 
#endif
	u8 protocol;
	u32 saddr;
	u32 daddr;
} __attribute__((packed));

struct profile_ipv4_endpoint_innermost_dynamic{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ipid_bh:2,
	   df:1,
	   reorder_ratio:2,
	   rsvd:3;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 rsvd:3,
	   reorder_ratio:2,
	   df:1,
	   ipid_bh:2;
#endif
	u8 tos;
	u8 ttl;
	/*next fields are varibale length fileds*/
	/*ipid = ipid_enc(ipid_bh)
	 * msn = irrguar(16)
	 */
} __attribute__((packed));

struct profile_ipv4_dynamic{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ipid_bh:2,
	   df:1,
	   rsvd:5;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 rsvd:5,
	   df:1,
	   ipid_bh:2;
#endif
	u8 tos;
	u8 ttl;
/*next field is varibale length field
 *ipid = ip_id_enc_dyn(ipid_bh)
 */
} __attribute__((packed));

struct profile_v2_rtp_dynamic{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ext:1,
	   pad_bit:1,
	   tis_ind:1,
	   tss_ind:1,
	   list_ind:1,
	   r_ratio:2,
	   rsvd:1;
	u8 pt:7,
	   mark:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 rsvd:1,
	   r_ratio:2,
	   list_ind:1,
	   tss_ind:1,
	   tis_ind:1,
	   pad_bit:1,
	   ext:1;
	u8 mark:1,
	   pt:7;
#endif
	u16 seq;
	u32 ts;
	/*next fields is variable length*/
} __attribute__((packed));
#endif
