
/*
 *	rohc
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	Date   :	2020-6-16
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include "rohc_crc.h"
void crc7_lsb_byte_table_init(u8 *table)
{
	int i,j;
	u8 crc;
	for(i = 0; i < 256;i++){
		crc = i;
		for(j = 0 ; j < 8;j++){
			if(crc & 0x1)
				crc = (crc >> 1) ^ CRC7_LSB_POLY;
			else
				crc >>= 1;
		}
		table[i] = crc;
	}
}

void crc7_msb_byte_table_init(u8 *table)
{
	int i,j;
	u8 crc;
	for(i = 0 ; i < 256;i++){
		crc = i;
		for(j = 0 ; j < 8;j++){
			if(crc & 0x40)
				crc = (crc << 1) ^ CRC7_MSB_POLY;
			else
				crc <<= 1;
		}
		table[i] = crc;
	}
}
void crc8_lsb_byte_table_init(u8 *table)
{
	int i,j;
	u8 crc;
	for(i = 0 ; i < 256;i++){
		crc = i;
		for(j = 0; j < 8;j++){
			if(crc & 0x1)
				crc = (crc >> 1) ^ CRC8_LSB_POLY;
			else
				crc >>= 1;
		}
		table[i] = crc;
	}
}

void crc8_msb_byte_table_init(u8 *table)
{
	int i,j;
	u8 crc;
	for(i = 0; i < 256;i++){
		crc = i;
		for(j = 0 ;j < 8;j++){
			if(crc & 0x80)
				crc = (crc << 1) ^ CRC8_MSB_POLY;
			else
				crc <<= 1;
		}
		table[i] = crc;
	}
}

u8 crc3_lsb_byte_table_init(u8 *table)
{
	int i,j;
	u8 crc;
	for(i = 0 ; i < 256;i++){
		crc = i;
		for(j = 0 ; j < 8;j++){
			if(crc & 0x1)
				crc = (crc >> 1) & CRC3_LSB_POLY;
			else
				crc >>= 1;
		}
		table[i] = crc;
	}
}
u8 crc8_lsb_direct_cal(unsigned char *data,int len)
{
	int i;
	u8 crc = CRC8_INIT;
	while(len > 0){
		crc ^= *data;
		for(i = 0; i < 8;i++){
			if(crc & 0x1)
				crc = (crc >> 1) ^ CRC8_LSB_POLY;
			else
				crc >>= 1;
		}
		data++;
		len--;
	}
	return crc;
}

u8 crc8_lsb_cal_by_table(unsigned char *data,int len)
{
	u8 crc = CRC8_INIT;
	while(len){
		crc = crc8_lsb_table[crc ^ (*data)];
		data++;
		len--;
	}
	return crc;
}

u8 crc3_lsb_direct_cal(unsigned char *data,int len)
{
	int i;
	u8 crc = CRC3_INIT;
	while(len){
		crc ^= *data;
		for(i = 0 ; i < 8;i++){
			if(crc & 0x1)
				crc = (crc >> 1) ^ CRC3_LSB_POLY;
			else
				crc >>= 1;
		}
		data++;
		len--;
	}
	return crc;
}

u8 crc3_lsb_cal_by_table(unsigned char *data,int len)
{
	u8 crc = CRC3_INIT;
	while(len){
		crc = crc3_lsb_table[(crc & 0x7) ^ (*data)];
		data++;
		len--;
	}
	return crc;
}
u8 crc7_lsb_direct_cal(unsigned char *data,int len)
{
	int i;
	u8 crc = CRC7_INIT;
	while(len > 0){
		crc ^= *data;
		for(i= 0 ; i < 8;i++){
			if(crc & 0x1)
				crc = (crc >> 1) ^ CRC7_LSB_POLY;
			else
				crc >>= 1;
		}
		data++;
		len--;
	}
	return crc;
}

u8 crc7_lsb_cal_by_table(unsigned char *data,int len)
{
	u8 crc = CRC7_INIT;
	while(len){
		crc = crc7_lsb_table[(crc & 0x7f) ^ (*data)];
		data++;
		len--;
	}
	return crc;
}

u8 crc8_msb_direct_cal(unsigned char *data,int len)
{
	u8 mask;
	u8 crc = CRC8_INIT;
	while(len){
		for(mask = 0x80;mask > 0; mask >>= 1){
			if(crc & 0x80)
				crc = (crc << 1) ^ CRC8_MSB_POLY;
			else
				crc <<= 1;
			if((*data) & mask)
				crc ^= CRC8_MSB_POLY;
		}
		data++;
		len--;
	}
	return crc;
}

u8 crc7_msb_direct_cal(unsigned char *data,int len)
{
	u8 mask;
	u8 crc = CRC7_INIT;
	while(len){
		crc ^= *data;
		for(mask = 0x80;mask > 0;mask >>= 1){
			if(crc & 0x40)
				crc = (crc << 1) ^ CRC7_MSB_POLY;
			else
				crc <<= 1;
		}
		data++;
		len--;
	}
	return crc;
}

u8 rohc_crc_cal(const struct sk_buff *skb,struct rohc_crc_info *crc_info)
{
	u8 *start;
	enum rohc_crc_type crc_type;
	u8 crc;
	start = skb->data + crc_info->start_off;
	crc_type = crc_info->crc_type;
	switch(crc_type){
		case CRC_TYPE_8:
			crc = crc8_lsb_cal_by_table(start,crc_info->len);
			break;
		case CRC_TYPE_7:
			crc = crc7_lsb_cal_by_table(start,crc_info->len);
			break;
		case CRC_TYPE_3:
			crc = crc3_lsb_cal_by_table(start,crc_info->len);
			break;
		default:
			crc = 0;
			break;
	}
	return crc;
}


int rohc_crc_verify(const struct sk_buff *skb,struct rohc_crc_info *crc_info)
{
	u8 comp_crc;
	int retval;
	comp_crc = crc_info->crc_value;
	if(comp_crc != rohc_crc_cal(skb,crc_info))
		retval = ROHC_CRC_ERR;
	else
		retval = ROHC_CRC_OK;
	return retval;

}
