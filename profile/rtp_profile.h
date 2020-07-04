#ifndef D__RTP_PROFILE_H
#define	D__RTP_PROFILE_H
#include <linux/types.h>

#define		RTPH_FIELD_X	1
#define		RTPH_FIELD_P	2
#define		RTPH_FIELD_PT	3
#define		RTPH_FIELD_M	4
#define		RTPH_FIELD_TS	5
#define		RTPH_FIELD_TS_SCALED	6
struct rtphdr{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 cc:4,
	   x:1,
	   p:1,
	   version:2;
	u8 pt:7,
	   m:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 version:2,
	   p:1,
	   x:1,
	   cc:4;
	u8 m:1,
	   pt:7;
#endif
	u16 seq;
	u32 ts; //timestamp
	u32 ssrc;
	/*dynamic exits csrc*/
} __attribute__((packed));


/*rtp static part */
struct profile_rtp_static{
	u32 ssrc;
};

struct profile_rtp_dynamic{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 cc:4,
	   rx:1,
	   p:1,
	   version:2;
	u8 pt:7,
	   m:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 version:2,
	   p:1,
	   rx:1,
	   cc:4;
	u8 m:1,
	   pt:7;
#endif
	u16 seq;
	u32 ts;
/*next fileds is variable fields*/
} __attribute__((packed));



struct profile_rtp_uo1{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ts:6,
	   dsc:2;
	u8 crc:3,
	   sn:4,
	   m:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 dsc:2,
	   ts:6;
	u8 m:1,
	   sn:4,
	   crc:3;
#endif
} __attribute__((packed));
/*note:UO-1 can't be used if the context contains at least one
 * IPV4 header with value(RND) = 0.This disambiguates it from
 *UO-1-ID and UO-1-TS.
*/

struct profile_rtp_uo1_id{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ipid_off:5,
	   t:1,
	   dsc:2;
	u8 crc:3,
	   sn:4,
	   x:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 dsc:2,
	   t:1,
	   ipid_off:5;
	u8 x:1,
	   sn:4,
	   crc:3;
#endif
/*next fileds is dynamic exits*/
} __attribute__((packed));


struct profile_rtp_uo1_ts{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ts:5,
	   t:1,
	   dsc:2;
	u8 crc:3,
	   sn:4,
	   m:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 dsc:2,
	   t:1,
	   ts:5;
	u8 m:1,
	   sn:4,
	   crc:3;
#endif
} __attribute__((packed));

struct profile_rtp_uor2{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ts0:5,
	   dsc:3;
	u8 sn:6,
	   m:1,
	   ts1:1;
	u8 crc:7,
	   x:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 dsc:3,
	   ts0:5;
	u8 ts1:1,
	   m:1,
	   sn:6;
	u8 x:1,
	   crc:7;
#endif
  /*the next is dynamic presence fields,extensions*/
} __attribute__((packed));

/*note:URO2 can't be used if the context contains at least one
 * IPV4 header with value(RND) = 0.This disambiguates it from
 *URO-2-ID and URO-2-TS.
*/
struct profile_rtp_uor2_id{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ipid_off:5,
	   dsc:3;
	u8 sn:6,
	   m:1,
	   t:1;
	u8 crc:7,
	   x:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 dsc:3,
	   ipid_off:5;
	u8 t:1,
	   m:1,
	   sn:6;
	u8 x:1,
	   crc:7;
#endif
/*the next is dynamic presence fields,extensions*/
} __attribute__((packed));

struct profile_rtp_uor2_ts{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 ts:5,
	   dsc:3;
	u8 sn:6,
	   m:1,
	   t:1;
	u8 crc:7,
	   x:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 dsc:3,
	   ts:5;
	u8 t:1,
	   m:1,
	   sn:6;
	u8 x:1,
	   crc:7;
#endif
/*the next is dynamic presence fields,extensions*/
} __attribute__((packed));

static inline void rtp_field_scaling(u32 stride_value,u32 *scaled_value,u32 unscaled_value,u32 *residue)
{
	if(stride_value){
		*scaled_value = unscaled_value / stride_value;
		*residue = unscaled_value % stride_value;
	}else{
		*scaled_value = 0;
		*residue = unscaled_value;
	}
}

/*for csrc list compressed*/
#define	CSRC_CARRYED_MAX	15
enum ssrc_item_type{
	SSRC_ITEM_GENERIC0,
	SSRC_ITEM_GENERIC1,
	SSRC_ITEM_GENERIC2,
	SSRC_ITEM_GENERIC3,
	SSRC_ITEM_GENERIC4,
	SSRC_ITEM_GENERIC5,

	SSRC_ITEM_GENERIC31 = 31,
	SSRC_ITEM_GENERIC_MAX = 32,
};

struct rtp_csrc{
	u32 ssrc;
	enum ssrc_item_type item_type;
};

struct rtp_new_csrcs{
	int cc;
	struct rtp_csrc rtp_csrcs[CSRC_CARRYED_MAX];
};

struct ssrc_item_to_index{
	bool maped;
	int index;
};
/*the compressed list encoding type
 */
#define ET_TYPE_0	0
#define	ET_TYPE_1	1
#define	ET_TYPE_2	2
#define	ET_TYPE_3	3


enum rtp_ext_t{
	RTP_EXT_T_TS,
	RTP_EXT_T_IPID,
};
static inline int rtp_csrc_cal_xi_table_len(int m,bool ps)
{
	int xi_len;
	if(ps)
		xi_len = m;
	else
		xi_len = (m + 1) / 2;

	return xi_len;
}

static inline int rtp_csrc_cal_xi_len_insert_scheme(int m,bool ps)
{
	int xi_len;
	if(ps)
		xi_len = m;
	else
		xi_len = m / 2;
	return xi_len;
}
#endif
