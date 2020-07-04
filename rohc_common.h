#ifndef		D_ROHC_COMMON__H
#define		D_ROHC_COMMON__H
#define		ROHC_NAME_LEN	16
#define		ROHC_MAX_IP_HDR	2

#define		ROHC_OUTER_IPH	0
#define		ROHC_INNER_IPH	1

#define		ROHC_V2_MAX_IP_HDR 2

/**
 *bits operations
 */

#define		BITS_MASK(mask,shift) ((mask) << (shift))
#define		BITS_LEFT_SHIFT(v,shift,mask) (((v) & (mask)) << (shift))

#define		BIT_LEFT_SHIFT(shift)	(1 << (shift))


#define		BYTE_BIT_0(v)		((v) & BIT_LEFT_SHIFT(0))
#define		BYTE_BIT_1(v)		((v) & BIT_LEFT_SHIFT(1))
#define		BYTE_BIT_2(v)		((v) & BIT_LEFT_SHIFT(2))
#define		BYTE_BIT_3(v)		((v) & BIT_LEFT_SHIFT(3))
#define		BYTE_BIT_4(v)		((v) & BIT_LEFT_SHIFT(4))
#define		BYTE_BIT_5(v)		((v) & BIT_LEFT_SHIFT(5))
#define		BYTE_BIT_6(v)		((v) & BIT_LEFT_SHIFT(6))
#define		BYTE_BIT_7(v)		((v) & BIT_LEFT_SHIFT(7))

#define		BYTE_BITS_5_7(v)	((v) & BITS_MASK(0x7,5))
#define		BYTE_BITS_4_7(v)	((v) & BITS_MASK(0xf,4))
#define		BYTE_BITS_3_7(v)	((v) & BITS_MASK(0x1f,3))
#define		BYTE_BITS_2_7(v)	((v) & BITS_MASK(0x3f,2))
#define		BYTE_BITS_1_7(v)	((v) & BITS_MASK(0x7f,1))
#define		BYTE_BITS_0_2(v)	((v) & BITS_MASK(0x7,0))
#define		BYTE_BITS_0_3(v)	((v) & BITS_MASK(0xf,0))
#define		BYTE_BITS_0_6(v)	((v) & BITS_MASK(0x7f,0))
#define		BYTE_BITS_0_5(v)	((v) & BITS_MASK(0x3f,0))
#define		BYTE_BITS_6_7(v)	((v) & BITS_MASK(0x3,6))



#define		BYTE_BITS_1(v,shift)		(((v) >> (shift)) & 0x1)
#define		BYTE_BITS_2(v,shift)		(((v) >> (shift)) & 0x3)
#define		BYTE_BITS_3(v,shift)		(((v) >> (shift)) & 0x7)
#define		BYTE_BITS_4(v,shift)		(((v) >> (shift)) & 0xf)
#define		BYTE_BITS_5(v,shift)		(((v) >> (shift)) & 0x1f)
#define		BYTE_BITS_6(v,shift)		(((v) >> (shift)) & 0x3f)
#define		BYTE_BITS_7(v,shift)		(((v) >> (shift)) & 0x7f)

/**
 *wlsb type size
 */
#define		TYPE_UCHAR	8
#define		TYPE_USHORT	16
#define		TYPE_UINT	32

#define		TYPE_UCHAR_BYTES	1
#define		TYPE_USHORT_BYTES	2
#define		TYPE_UINT_BYTES		4
/**
 *
 *context mode
 */

#define	ROHC_MODE_U	0
#define	ROHC_MODE_O	1
#define	ROCH_MODE_R	2
/**
 *self describng variable-lenght value
 *
 */

#define	 ROHC_SDVL_TYPE_0		1
#define  ROHC_SDVL_TYPE_10		2
#define	 ROHC_SDVL_TYPE_110		3
#define	 ROHC_SDVL_TYPE_111		4

enum rohc_sdvl_encode_len{
	SDVL_TYPE_0_ENCODE_LEN = ((1 << (ROHC_SDVL_TYPE_0 * 8 - 1)) - 1),
	SDVL_TYPE_10_ENCODE_LEN = ((1 << (ROHC_SDVL_TYPE_10 * 8 - 2)) - 1),
	SDVL_TYPE_110_ENCODE_LEN = ((1 << (ROHC_SDVL_TYPE_110 * 8 - 3)) - 1),
	SDVL_TYPE_111_ENCODE_LEN = ((1 << (ROHC_SDVL_TYPE_111 * 8 - 3)) - 1),
};

/**
 *
 *compare unsigned and deal with wrapping correctly(in small range change).
 */

#define	before8(a , b) ((s8)((a) - (b) ) < 0)
#define	after8(a , b) before8((b) , (a))

#define	before8_eq(a,b)((s8)((a) - (b)) <= 0)
#define	after8_eq(a , b) before8_eq((b) , (a))

#define	before16(a , b)	((s16)((a) - (b)) < 0)
#define	after16(a , b)	before16((b) , (a))

#define	before16_eq(a , b)	((s16)((a) - (b)) <= 0)
#define	after16_eq(a , b)	before16_eq((b) , (a))


#define	before32(a , b)	((s32)((a) - (b)) < 0)
#define	after32(a , b)	before32((b) , (a))

#define	before32_eq(a , b) ((s32)((a) - (b)) <= 0)
#define	after32_eq(a , b) before32_eq((b), (a))



#define rohc_err		(1 << 0)
#define	rohc_debug		(1 << 1)
#define	rohc_warn		(1 << 2)
#define	rohc_info		(1 << 3)

#define	ROHC_DEBUG		(1 << 17)
#define	ROHC_DUMP		(ROHC_DEBUG)
#define	DEBUG_MASK		(0xf)

#define	ROHC_DTCP		(rohc_debug)
#define ROHC_DRTP		(rohc_debug)
#define	ROHC_DUDP2		(rohc_debug)
#define ROHC_DV2		(rohc_debug)
#define	ROHC_DRTP2		(rohc_debug)
#define ROHC_DCORE		(rohc_debug)
#define	ROHC_DIP2		(rohc_debug)
#define		rohc_pr(debug,fmt,arg...)	\
do{					\
	if(debug & DEBUG_MASK){		\
		switch(debug & DEBUG_MASK){	\
			case	rohc_err:	\
				printk(KERN_ERR pr_fmt(fmt), ##arg); \
				break;			\
			case	rohc_debug:	\
				printk(KERN_DEBUG pr_fmt(fmt), ##arg);	\
				break;		\
			case	rohc_warn:		\
				pr_warn(fmt,##arg);	\
				break;		\
			case	rohc_info:	\
				pr_info(fmt,##arg);\
				break;		\
		}				\
	}					\
}while(0)					\


static inline void net_header_field_update_probe(u32 new_val,u32 old_val,bool *is_update,int *trans_times,int oa_max)
{
	if(new_val != old_val){
		*is_update = true;
		if(trans_times)
			*trans_times = 0;
	}else if(trans_times && ((*trans_times) < oa_max))
		*is_update = true;
	else
		*is_update = false;

}
#endif
