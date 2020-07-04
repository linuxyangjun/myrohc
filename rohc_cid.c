

/**
 *auhtor : yangjun
 *date : 
 */
#include <linux/types.h>
#include <linux/kernel.h>
#include "rohc_common.h"
#include "rohc_cid.h"
#include "rohc_packet.h"
int rohc_cid_to_len(enum rohc_cid_type cid_type,u16 cid_value,int *cid_len)
{
	int retval = 0;
	switch(cid_type){
		case CID_TYPE_SMALL:
			if(cid_value > 0)
				*cid_len = 1;
			else
				*cid_len = 0;
			break;
		case CID_TYPE_LARGE:
			if(cid_value <= SDVL_TYPE_0_ENCODE_LEN)
				*cid_len = 1;
			else if(cid_value <= SDVL_TYPE_10_ENCODE_LEN)
				*cid_len = 2;
			else{
				pr_err("%s : cid value is too large\n",__func__);
				retval = -EFAULT;
			}
			break;
		default:
			retval = -EFAULT;
			break;

	}
	return retval;

}
int rohc_cid_encode(enum rohc_cid_type cid_type,unsigned char *buf,int *cid_length,u16 cid_value)
{
	int retval = 0;
	*cid_length = 0;
	switch(cid_type){
		case CID_TYPE_SMALL:
			if(cid_value > 0){
				*buf = ROHC_PACKET_ADD_CID | cid_value & 0xf;
				*cid_length = 1;
			}
			break;
		case CID_TYPE_LARGE:
			if(cid_value <= SDVL_TYPE_0_ENCODE_LEN){
				*buf = cid_value & 0x7f;
				*cid_length = 1;
			}else if(cid_value <= SDVL_TYPE_10_ENCODE_LEN){ //big-endian
				*buf = (0x2 << 6) | ( (cid_value >> 8) & 0x3f);
				buf++;
				*buf = cid_value & 0xff;
				*cid_length = 2;
			}else{
				rohc_pr(ROHC_DCORE,"%s : cid value is too large %d\n",__func__,cid_value);
				retval = -EFAULT;
			}
			break;
		case CID_TYPE_NONE:
			pr_err("not support cid_type : %d\n",cid_type);
			retval = -EFAULT;
			break;
	}
	return retval;
}
int rohc_cid_decode(enum rohc_cid_type cid_type,unsigned char *buf,int *cid_length,u16 *cid_value)
{
	*cid_length = 0;
	u8 sdvl_type;
	int retval = 0;
	switch(cid_type){
		case CID_TYPE_SMALL:
			if(BYTE_BITS_4_7(*buf) == ROHC_PACKET_ADD_CID){
				*cid_value = BYTE_BITS_0_3(*buf);
				*cid_length = 1;
			}else
				*cid_value = 0;
			break;
		case CID_TYPE_LARGE:
			if(!BYTE_BIT_7(*buf)){
				*cid_value = BYTE_BITS_0_6(*buf);
				*cid_length = ROHC_SDVL_TYPE_0;
			}else if(((*buf) >> 6) == ROHC_SDVL_TYPE_10){ //big endian  fill
				*cid_value = BYTE_BITS_0_5(*buf) << 8;
				buf++;
				*cid_value |= *buf;
				*cid_length = ROHC_SDVL_TYPE_10;

			}else{
				rohc_pr(ROHC_DCORE,"%s : cid value length too long\n",__func__);
				retval = -EFAULT;
			}
			break;
		case CID_TYPE_NONE:
			retval = -EFAULT;
			break;

	}
	return retval;
}
