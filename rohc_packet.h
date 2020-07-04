#ifndef	D__ROHC_PACKET_H
#define	D__ROHC_PACKET_H
/**
 *author : yangjun
 *date : 15/10/19
 *
 */
#include "rohc_common.h"
/**
 *
 *rohc packet type rf5795 5.2.0
 */
#define	ROHC_PACKET_PADDING		0xe0

#define	ROHC_PACKET_FEEDBACK		(0x1e << 3)
#define	ROHC_PACKET_IR			(0x7e << 1)
#define ROHC_PACKET_IR_DYN		(0xf8)

#define	ROHC_PACKET_ADD_CID		(0xe << 4)


/*co_repair for rohcv3*/
#define	ROHC_PACKET_CO_REPAIR		(0xfb)

/*packet type is defined in rf3095 5.7
 * contains type0,type1 and type2
 */

/*packet type 0: UO-0,R-0,R-0-CRC
 */
/*R-MODE
 */
#define ROHC_PACKET_R_0			(0x0 << 6)
#define	ROHC_PACKET_R_0_CRC		(0x1 << 6)
/**
 *U/O MODE
 */
#define	ROHC_PACKET_UO_0			(0x0 << 7)

/*pacekt type 1(R-MODE) :R-1,R-1-TS,R-1-ID
 *R-1 contains subtype R-1-TS and R-1-ID
 *you can determine the extended type by the second byte.
 */

#define ROHC_PACKET_R_1			(0x2 << 6)
/**
 *adjust by the third bit in  second byte.
 */
#define	ROHC_PACKET_R_1_ID		(0x0 << 5)
#define	ROHC_PACKET_R_1_TS		(0x1 << 5)

/*
 *packet type 1(U/O-MODE):UO-1,contains subtype UO-1-ID,UO-1-TS
 *you can determine the extended type by the third bit in first byte
 */

#define	ROHC_PACKET_UO_1		(0x2 << 6)
#define	ROHC_PACKET_UO_1_ID		(0x4 << 5)
#define	ROHC_PACKET_UO_1_TS		(0x5 << 5)

/**
 *packet typ2 :UOR-2,contains subtype UOR-2-ID,ROR-2-TS.
 *you can determine the subtype by the second byte.
 */
#define	ROHC_PACKET_URO_2		(0x6 << 5)
/**
 *determine the subtype by the second byte
 */
#define	ROHC_PACKET_URO_2_ID		(0x0 << 7)
#define	ROHC_PACKET_URO_2_TS		(0x1 << 7)



/*packet type is defined in rf6846 for tcp
 * 
 */

#define	ROHC_PACKET_CO_COMMON		(0x7d << 1)
#define ROHC_PACKET_RND1		(0x2e << 2)
#define	ROHC_PACKET_RND2		(0xc << 4)
#define	ROHC_PACKET_RND3		(0x0 << 7)
#define	ROHC_PACKET_RND4		(0xd << 4)
#define	ROHC_PACKET_RND5		(0x4 << 5)
#define	ROHC_PACKET_RND6		(0xa << 4)
#define	ROHC_PACKET_RND7		(0x2f << 2)
#define	ROHC_PACKET_RND8		(0x16 << 3)

#define	ROHC_PACKET_SEQ1		(0xa << 4)
#define	ROHC_PACKET_SEQ2		(0x1a << 3)
#define	ROHC_PACKET_SEQ3		(0x9 << 4)
#define	ROHC_PACKET_SEQ4		(0x0 << 7)
#define	ROHC_PACKET_SEQ5		(0x8 << 4)
#define	ROHC_PACKET_SEQ6		(0x1b << 3)
#define	ROHC_PACKET_SEQ7		(0xc << 4)
#define	ROHC_PACKET_SEQ8		(0xb << 4)

/*packet type is defined in rf5225 for rohc v2
 *
 */
/*the following header formats descriptions apply to
 * profiles 0x101 and 0x 107:
 * pt_1_rnd
 * pt_1_seq_id_rtp
 * pt_1_seq_ts
 * pt_2_rnd
 * pt_2_seq_id_rtp
 * pt_2_seq_ts
 * pt_2_seq_both
 */

/*the following header formats descriptions apply to
 * profiles 0x102,0x103,0x104,0x108
 * pt_1_seq_id
 * pt_2_seq_id
 */

#define	ROHC_PACKET_GENERIC_CO_COMMON	(0xfa)
#define	ROHC_PACKET_PT_0_CRC3		(0x0 << 7)
#define	ROHC_PACKET_PT_0_CRC7		(0x4 << 5)
#define	ROHC_PACKET_PT_0_CRC7_RTP	(0x8 << 4)
#define	ROHC_PACKET_PT_1_RND		(0x5 << 5)
#define	ROHC_PACKET_PT_1_SEQ_ID_RTP	(0x9 << 4)
#define	ROHC_PACKET_PT_1_SEQ_ID		(0x5 << 5)
#define	ROHC_PACKET_PT_1_SEQ_TS		(0x5 << 5)
#define	ROHC_PACKET_PT_2_RND		(0x6 << 5)
#define	ROHC_PACKET_PT_2_SEQ_ID_RTP	(0x18 << 3)
#define ROHC_PACKET_PT_2_SEQ_ID		(0x6 << 5)
#define ROHC_PACKET_PT_2_SEQ_BOTH	(0x19 << 3)
#define	ROHC_PACKET_PT_2_SEQ_TS		(0xd << 4)

enum rohc_packet_type{
	ROHC_PACKET_TYPE_UNDECIDE = 0,
	ROHC_PACKET_TYPE_PADDING,
	ROHC_PACKET_TYPE_FEEDBACK,
	ROHC_PACKET_TYPE_IR = 3,
	ROHC_PACKET_TYPE_IR_CR,
	ROHC_PACKET_TYPE_IR_DYN,
	ROHC_PACKET_TYPE_NORMAL,
	/**
	 *packet type0,type1,type2 defined in rf3095
	 */
	ROHC_PACKET_TYPE_R_0,
	ROHC_PACKET_TYPE_R_0_CRC,
	ROHC_PACKET_TYPE_UO_0,
	ROHC_PACKET_TYPE_R_1,
	ROHC_PACKET_TYPE_R_1_ID,
	ROHC_PACKET_TYPE_R_1_TS,
	ROHC_PACKET_TYPE_UO_1,
	ROHC_PACKET_TYPE_UO_1_ID,
	ROHC_PACKET_TYPE_UO_1_TS,
	ROHC_PACKET_TYPE_URO_2,
	ROHC_PACKET_TYPE_URO_2_ID,
	ROHC_PACKET_TYPE_URO_2_TS,
	/*packet type for tcp
	 */
	ROHC_PACKET_TYPE_CO_COMMON,
	ROHC_PACKET_TYPE_RND1,
	ROHC_PACKET_TYPE_RND2,
	ROHC_PACKET_TYPE_RND3,
	ROHC_PACKET_TYPE_RND4,
	ROHC_PACKET_TYPE_RND5,
	ROHC_PACKET_TYPE_RND6,
	ROHC_PACKET_TYPE_RND7,
	ROHC_PACKET_TYPE_RND8,
	ROHC_PACKET_TYPE_SEQ1,
	ROHC_PACKET_TYPE_SEQ2,
	ROHC_PACKET_TYPE_SEQ3,
	ROHC_PACKET_TYPE_SEQ4,
	ROHC_PACKET_TYPE_SEQ5,
	ROHC_PACKET_TYPE_SEQ6,
	ROHC_PACKET_TYPE_SEQ7,
	ROHC_PACKET_TYPE_SEQ8,
	/*packet type for rohcv2,start 36*/
	ROHC_PACKET_TYPE_CO_REPAIR,
	ROHC_PACKET_TYPE_PT_0_CRC3,
	ROHC_PACKET_TYPE_PT_0_CRC7,
	ROHC_PACKET_TYPE_PT_1_RND,
	ROHC_PACKET_TYPE_PT_1_SEQ_ID,
	ROHC_PACKET_TYPE_PT_1_SEQ_TS,
	ROHC_PACKET_TYPE_PT_2_RND,
	ROHC_PACKET_TYPE_PT_2_SEQ_ID,
	ROHC_PACKET_TYPE_PT_2_SEQ_TS,
	ROHC_PACKET_TYPE_PT_2_SEQ_BOTH,

};


static inline bool rohc_packet_is_padding(unsigned char *buf)
{
	return *buf == ROHC_PACKET_PADDING;
}

static inline bool rohc_packet_is_ir(unsigned char *buf)
{
	return BYTE_BITS_1_7(*buf) == ROHC_PACKET_IR;
}

static inline bool rohc_packet_is_irdyn(unsigned char *buf)
{
	return *buf == ROHC_PACKET_IR_DYN;
}

static inline bool rohc_packet_is_co_repair(unsigned char *buf)
{
	return *buf == ROHC_PACKET_CO_REPAIR;
}

static inline bool rohc_packet_is_feedback(unsigned char *buf)
{
	return BYTE_BITS_3_7(*buf) == ROHC_PACKET_FEEDBACK;
}

static inline bool rohc_packet_is_r0(unsigned char *buf)
{
	return BYTE_BITS_6_7(*buf) == ROHC_PACKET_R_0;
}

static inline bool rohc_packet_is_r0_crc(unsigned char *buf)
{
	return BYTE_BITS_6_7(*buf) == ROHC_PACKET_R_0_CRC;
}
static inline bool rohc_packet_is_uo0(unsigned char *buf)
{
	return BYTE_BIT_7(*buf) == ROHC_PACKET_UO_0;
}

static inline bool rohc_packet_is_r1(unsigned char *buf)
{
	return BYTE_BITS_6_7(*buf) == ROHC_PACKET_R_1;
}

static inline bool rohc_packet_is_r1_id(unsigned char *buf,int cid_len)
{
	return (BYTE_BITS_6_7(*buf) == ROHC_PACKET_R_1 && 
		BYTE_BIT_5(*(buf + cid_len + 1) == ROHC_PACKET_R_1_ID));
}

static inline bool rohc_packet_is_r1_ts(unsigned char *buf,int cid_len)
{
	return (BYTE_BITS_6_7(*buf) == ROHC_PACKET_R_1 &&
		BYTE_BIT_5(*(buf + cid_len + 1) == ROHC_PACKET_R_1_TS));
}

static inline bool rohc_packet_is_uo1(unsigned char *buf)
{
	return BYTE_BITS_6_7(*buf) == ROHC_PACKET_UO_1;
}
static inline bool rohc_packet_is_uo1_id(unsigned char *buf)
{
	return BYTE_BITS_5_7(*buf) == ROHC_PACKET_UO_1_ID;
}
static inline bool rohc_packet_is_uo1_ts(unsigned char *buf)
{
	return BYTE_BITS_5_7(*buf) == ROHC_PACKET_UO_1_TS;
}

static inline bool rohc_packet_is_uro2(unsigned char *buf)
{
	return BYTE_BITS_5_7(*buf) == ROHC_PACKET_URO_2;
}
static inline bool rohc_packet_is_uro2_id(unsigned char *buf,int cid_len)
{
	return (BYTE_BITS_5_7(*buf) == ROHC_PACKET_URO_2 &&
		BYTE_BIT_7(*(buf + 1 + cid_len) == ROHC_PACKET_URO_2_ID));
}

static inline bool rohc_packet_is_uro2_ts(unsigned char *buf,int cid_len)
{
	return (BYTE_BITS_5_7(*buf) == ROHC_PACKET_URO_2 && 
		BYTE_BIT_7(*(buf + 1 + cid_len) == ROHC_PACKET_URO_2_TS));
}

static inline bool rohc_packet_carryed_rtp_ts(enum rohc_packet_type type)
{
	if(type == ROHC_PACKET_TYPE_UO_1_TS || type == ROHC_PACKET_TYPE_URO_2_TS || type == ROHC_PACKET_URO_2 || type == ROHC_PACKET_TYPE_UO_1)
		return true;
	else
		return false;
}
static inline bool rohc_packet_is_type_0(enum rohc_packet_type type)
{
	bool retval ;
	switch(type){
		case ROHC_PACKET_TYPE_R_0:
		case ROHC_PACKET_TYPE_R_0_CRC:
		case ROHC_PACKET_UO_0:
			retval = true;
			break;
		default:
			retval = false;
			break;

	}
	return retval;
}

static inline bool rohc_packet_is_type_1(enum rohc_packet_type type)
{
	bool retval;
	switch(type){
		case ROHC_PACKET_TYPE_R_1:
		case ROHC_PACKET_TYPE_R_1_ID:
		case ROHC_PACKET_TYPE_R_1_TS:
		case ROHC_PACKET_TYPE_UO_1:
		case ROHC_PACKET_TYPE_UO_1_ID:
		case ROHC_PACKET_TYPE_UO_1_TS:
			retval = true;
			break;
		default:
			retval = false;
			break;
	}
	return retval;
}

static inline bool rohc_packet_is_type_2(enum rohc_packet_type type)
{
	bool retval;
	switch(type){
		case ROHC_PACKET_TYPE_URO_2:
		case ROHC_PACKET_TYPE_URO_2_ID:
		case ROHC_PACKET_TYPE_URO_2_TS:
			retval = true;
			break;
		default:
			retval = false;
			break;
	}
	return retval;
}
static inline bool rohc_packet_is_covered_by_crc8(enum rohc_packet_type type)
{
	bool retval;
	switch(type){
		case ROHC_PACKET_TYPE_IR:
		case ROHC_PACKET_TYPE_IR_CR:
		case ROHC_PACKET_TYPE_IR_DYN:
			retval = true;
			break;
		default:
			retval = false;
			break;
	}
	return retval;
}
static inline bool rohc_packet_is_covered_by_crc7(enum rohc_packet_type type)
{
	bool retval;
	switch(type){
		case ROHC_PACKET_TYPE_URO_2:
		case ROHC_PACKET_TYPE_URO_2_ID:
		case ROHC_PACKET_TYPE_URO_2_TS:
		case ROHC_PACKET_TYPE_CO_COMMON:
		case ROHC_PACKET_TYPE_RND8:
		case ROHC_PACKET_TYPE_SEQ8:
			retval = true;
			break;
		default:
			retval = false;
			break;
	}
	return retval;
}

static inline bool rohc_packet_is_covered_by_crc7_or_crc8(enum rohc_packet_type type)
{
	return (rohc_packet_is_covered_by_crc8(type) || rohc_packet_is_covered_by_crc7(type));
}

static inline bool rohc_iph_is_v4(u8 version)
{
	return version == 4;
}


/*adjust packet type by rf6846 
 */
static inline bool rohc_packet_is_co_common(unsigned char *buf)
{
	return (BYTE_BITS_1_7(*buf) == ROHC_PACKET_CO_COMMON);
}

static inline bool rohc_packet_is_rnd1(unsigned char *buf)
{
	return (BYTE_BITS_2_7(*buf) == ROHC_PACKET_RND1);
}

static inline bool rohc_packet_is_rnd2(unsigned char *buf)
{
	return (BYTE_BITS_4_7(*buf) == ROHC_PACKET_RND2);
}

static inline bool rohc_packet_is_rnd3(unsigned char *buf)
{
	return (BYTE_BIT_7(*buf) == ROHC_PACKET_RND3);
}

static inline bool rohc_packet_is_rnd4(unsigned char *buf)
{
	return (BYTE_BITS_4_7(*buf) == ROHC_PACKET_RND4);
}

static inline bool rohc_packet_is_rnd5(unsigned char *buf)
{
	return (BYTE_BITS_4_7(*buf) == ROHC_PACKET_RND5);
}

static inline bool rohc_packet_is_rnd6(unsigned char *buf)
{
	return (BYTE_BITS_4_7(*buf) == ROHC_PACKET_RND6);
}

static inline bool rohc_packet_is_rnd7(unsigned char *buf)
{
	return (BYTE_BITS_2_7(*buf) == ROHC_PACKET_RND7);
}

static inline bool rohc_packet_is_rnd8(unsigned char *buf)
{
	return (BYTE_BITS_3_7(*buf) == ROHC_PACKET_RND8);
}


static inline bool rohc_packet_is_seq1(unsigned char *buf)
{
	return (BYTE_BITS_4_7(*buf) == ROHC_PACKET_SEQ1);
}

static inline bool rohc_packet_is_seq2(unsigned char *buf)
{
	return (BYTE_BITS_3_7(*buf) == ROHC_PACKET_SEQ2);
}

static inline bool rohc_packet_is_seq3(unsigned char *buf)
{
	return (BYTE_BITS_4_7(*buf) == ROHC_PACKET_SEQ3);
}

static inline bool rohc_packet_is_seq4(unsigned char *buf)
{
	return (BYTE_BIT_7(*buf) == ROHC_PACKET_SEQ4);
}

static inline bool rohc_packet_is_seq5(unsigned char *buf)
{
	return (BYTE_BITS_4_7(*buf) == ROHC_PACKET_SEQ5);
}

static inline bool rohc_packet_is_seq6(unsigned char *buf)
{
	return (BYTE_BITS_3_7(*buf) == ROHC_PACKET_SEQ6);
}

static inline bool rohc_packet_is_seq7(unsigned char *buf)
{
	return (BYTE_BITS_4_7(*buf) == ROHC_PACKET_SEQ7);
}

static inline bool rohc_packet_is_seq8(unsigned char *buf)
{
	return (BYTE_BITS_4_7(*buf) == ROHC_PACKET_SEQ8);
}

/*defined function for rohc_v2
 */
static inline bool rohc_packet_is_generic_co_common(unsigned char *buf)
{
	return (*buf) == ROHC_PACKET_GENERIC_CO_COMMON;
}

static inline bool rohc_packet_is_pt_0_crc3(unsigned char *buf)
{
	return (BYTE_BIT_7(*buf) == ROHC_PACKET_PT_0_CRC3);
}

static inline bool rohc_packet_is_pt_0_crc7(unsigned char *buf)
{
	return (BYTE_BITS_5_7(*buf) == ROHC_PACKET_PT_0_CRC7);
}

static inline bool rohc_packet_is_pt_0_crc7_rtp(unsigned char *buf)
{
	return (BYTE_BITS_4_7(*buf) == ROHC_PACKET_PT_0_CRC7_RTP);
}

static inline bool rohc_packet_is_pt_1_rnd(unsigned char *buf)
{
	return (BYTE_BITS_5_7(*buf) == ROHC_PACKET_PT_1_RND);
}

static inline bool rohc_packet_is_pt_1_seq_id_rtp(unsigned char *buf)
{
	return (BYTE_BITS_4_7(*buf) == ROHC_PACKET_PT_1_SEQ_ID_RTP);
}

static inline bool rohc_packet_is_pt_1_seq_id(unsigned char *buf)
{
	return (BYTE_BITS_5_7(*buf) == ROHC_PACKET_PT_1_SEQ_ID);
}

static inline bool rohc_packet_is_pt_1_seq_ts(unsigned char *buf)
{
	return (BYTE_BITS_4_7(*buf) == ROHC_PACKET_PT_1_SEQ_TS);
}

static inline bool rohc_packet_is_pt_2_rnd(unsigned char *buf)
{
	return (BYTE_BITS_5_7(*buf) == ROHC_PACKET_PT_2_RND);
}

static inline bool rohc_packet_is_pt_2_seq_id_rtp(unsigned char *buf)
{
	return (BYTE_BITS_3_7(*buf) == ROHC_PACKET_PT_2_SEQ_ID_RTP);
}

static inline bool rohc_packet_is_pt_2_seq_id(unsigned char *buf)
{
	return (BYTE_BITS_5_7(*buf) == ROHC_PACKET_PT_2_SEQ_ID);
}

static inline bool rohc_packet_is_pt_2_seq_ts(unsigned char *buf)
{
	return (BYTE_BITS_4_7(*buf) == ROHC_PACKET_PT_2_SEQ_TS);
}

static inline bool rohc_packet_is_pt_2_seq_both(unsigned char *buf)
{
	return (BYTE_BITS_3_7(*buf) == ROHC_PACKET_PT_2_SEQ_BOTH);
}
/**
 *The following is the extensions definition of ROHC V1 version(rf3095).
 */

/**
 *extensions formats
 */

#define		ROHC_CARRAY_EXT		(0x1 << 7)
enum rohc_ext_type{
	EXT_TYPE_NONE,
	EXT_TYPE_0,
	EXT_TYPE_1,
	EXT_TYPE_2,
	EXT_TYPE_3,
};


/*extensions type definition
 */
#define		ROHC_EXT_0		(0x0 << 6)
#define		ROHC_EXT_1		(0x1 << 6)
#define		ROHC_EXT_2		(0x2 << 6)
#define		ROHC_EXT_3		(0x3 << 6)
/**
 *extensions 3 ip header flags
 */
#define		ROHC_EXT_3_IPHF_TOS	(0x1 << 7)
#define		ROHC_EXT_3_IPHF_TTL	(0x1 << 6)
#define		ROHC_EXT_3_IPHF_PR	(0x1 << 4)
#define		ROHC_EXT_3_IPHF_IPX	(0x1 << 3)

/*
 *extension 3 flags
 */
#define		ROHC_EXT3_F_S		(0x1 << 5)
#define		ROHC_EXT3_F_I		(0x1 << 2)
#define		ROHC_EXT3_F_IP		(0x1 << 1)
#define		ROHC_EXT3_F_IP2		(0x1 << 0)
#define		ROHC_EXT3_F_RTP		(0x1 << 0)

static inline u8 rohc_packet_pick_ext_type(u8 *buf)
{
	return BYTE_BITS_6_7(*buf); 
}


#endif
