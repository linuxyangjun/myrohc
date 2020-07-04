#ifndef	D__ROHC_CID_H
#define	D__ROHC_CID_H
#include <linux/types.h>


#define		MAX_SMALL_CIDS	15
/**
 *
 *rfc3095 4.5.6
 *first bits are 10 : 2 bytes.
 *14 bits transfered, up to 16383.
 */
#define		MAX_LARGE_CIDS	((1 << 14) - 1)
enum rohc_cid_type{
	CID_TYPE_NONE,
	CID_TYPE_SMALL,
	CID_TYPE_LARGE,
};



int rohc_cid_encode(enum rohc_cid_type cid_type,unsigned char *buf,int *cid_length,u16 cid_value);
int rohc_cid_decode(enum rohc_cid_type cid_type,unsigned char *buf,int *cid_length,u16 *cid_value);
int rohc_cid_to_len(enum rohc_cid_type cid_type,u16 cid_value,int *cid_len);
#endif
