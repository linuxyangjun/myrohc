/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/types.h>
#include <linux/kernel.h>

#include "rohc_common.h"
#include "rohc_cid.h"
#include "rohc_packet.h"
#include "rohc_bits_encode.h"
int rohc_sd_vl_encode(unsigned char *buf,int *encode_len,u32 value,enum rohc_sd_vl_type type)
{
	int retval = 0;
	*encode_len = 0;
	switch(type){
		case ROHC_SD_VL_TYPE_0:
			*buf = BYTE_BITS_0_6(value);
			*encode_len = 1;
			break;
		case ROHC_SD_VL_TYPE_10:
			*buf = (0x2 << 6) | ((value >> 8) & 0x3f);
			buf++;
			*buf = value & 0xff;
			*encode_len = 2;
			break;
		case ROHC_SD_VL_TYPE_110:
			*buf = (0x6 << 5) | ((value >> 16) & 0x1f);
			buf++;
			*buf = (value >> 8) & 0xff;
			buf++;
			*buf = value & 0xff;
			*encode_len = 3;
			break;
		case ROHC_SD_VL_TYPE_111:
			*buf  = (0x7 << 5) | ((value >> 24) & 0x1f);
			buf++;
			*buf = (value >> 16) & 0xff;
			buf++;
			*buf = (value >> 8) & 0xff;
			buf++;
			*buf = value & 0xff;
			*encode_len = 4;
			break;
		default:
			retval = -EFAULT;
			break;
	}
	return retval;
}
int rohc_sd_vl_decode(unsigned char *buf,int *decode_len,u32 *decode_value)
{
	u32 value;
	int retval = 0;
	*decode_len = 0;
	if(!BYTE_BIT_7(*buf)){
		value = BYTE_BITS_7(*buf,0);
		*decode_len = 1;
	}else if(BYTE_BITS_2(*buf,6) == 0x2){
		value = BYTE_BITS_6(*buf,0);
		buf++;
		value  = (value << 8) | (*buf);
		*decode_len = 2;
	}else if(BYTE_BITS_3(*buf,5) == 0x6){
		value = BYTE_BITS_5(*buf,0);
		buf++;
		value = (value << 8) | (*buf);
		buf++;
		value = (value << 8) | (*buf);
		*decode_len = 3;

	}else if(BYTE_BITS_3(*buf,5) == 0x7){
		value = BYTE_BITS_5(*buf,0);
		buf++;
		value = (value << 8) | (*buf);
		buf++;
		value = (value << 8) | (*buf);
		buf++;
		value = (value << 8) | (*buf);
		*decode_len = 4;
	}else
		retval = -EFAULT;
	*decode_value = value;
	return retval;
}

int rohc_sd_vl_value_to_type(u32 encode_v,enum rohc_sd_vl_type *sdvl_type)
{
	int retval = 0;
	if(encode_v <= SD_VL_TYPE_0_ENCODE_MAX)
		*sdvl_type = ROHC_SD_VL_TYPE_0;
	else if(encode_v <= SD_VL_TYPE_10_ENCODE_MAX)
		*sdvl_type = ROHC_SD_VL_TYPE_10;
	else if(encode_v <= SD_VL_TYPE_110_ENCODE_MAX)
		*sdvl_type = ROHC_SD_VL_TYPE_110;
	else if(encode_v <= SD_VL_TYPE_111_ENCODE_MAX)
		*sdvl_type = ROHC_SD_VL_TYPE_111;
	else
		retval = -EFAULT;
	return retval;
}
