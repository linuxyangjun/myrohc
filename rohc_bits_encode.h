#ifndef	D__ROHC_BITS_ENCODE_H
#define	D__ROHC_BITS_ENCODE_H

#define	ROHC_ENCODE_BY_BITS(v)		(v)
struct rohc_bits_encode_set{
	unsigned long	k_set;
	/*if the K with different p,
	 * need to distinguish accoring to p
	 */
	unsigned long	p_set;
	int min_k;
};


#define ROHC_ENCODE_BITS_SET(set,bits)		set_bit((bits),&(set)->k_set)
#define	ROHC_ENCODE_BITS_TEST(set,bits)		test_bit(bits,&(set)->k_set)

#define	ROHC_ENCODE_BITS_P_SET(set,bits)	set_bit((bits),&(set)->p_set)
#define	ROHC_ENCODE_P_BITS_TEST(set,bits)	test_bit(bits,&(set)->p_set)


enum rohc_sd_vl_type{
	ROHC_SD_VL_TYPE_0,		
	ROHC_SD_VL_TYPE_10,
	ROHC_SD_VL_TYPE_110,
	ROHC_SD_VL_TYPE_111,
};

#define	 ROHC_SD_VL_TYPE_0_BYTES	1
#define  ROHC_SD_VL_TYPE_10_BYTES	2
#define	 ROHC_SD_VL_TYPE_110_BYTES	3
#define	 ROHC_SD_VL_TYPE_111_BYTES	4

enum rohc_sd_vl_encode_max{
	SD_VL_TYPE_0_ENCODE_MAX = ((1 << (ROHC_SD_VL_TYPE_0_BYTES * 8 - 1)) - 1),
	SD_VL_TYPE_10_ENCODE_MAX = ((1 << (ROHC_SD_VL_TYPE_10_BYTES * 8 - 2)) - 1),
	SD_VL_TYPE_110_ENCODE_MAX = ((1 << (ROHC_SD_VL_TYPE_110_BYTES * 8 - 3)) - 1),
	SD_VL_TYPE_111_ENCODE_MAX = ((1 << (ROHC_SD_VL_TYPE_111_BYTES * 8 - 3)) - 1),
};

int rohc_sd_vl_encode(unsigned char *buf,int *encode_len,u32 value,enum rohc_sd_vl_type type);
int rohc_sd_vl_decode(unsigned char *buf,int *decode_len,u32 *decode_value);
int rohc_sd_vl_value_to_type(u32 encode_v,enum rohc_sd_vl_type *sdvl_type);
#endif
