
/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	date: 2019/12/7
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */


#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/types.h>
#include "rohc_feedback.h"
#include "rohc_packet.h"
#include "rohc_cid.h"
#include "rohc_profile.h"
#include "rohc_common.h"
int rohc_feedback_option_len[FEEDBACK_OPTION_TYPE_MAX] = {
	[FEEDBACK_OPTION_TYPE_CRC] = 1,
	[FEEDBACK_OPTION_TYPE_SN] = 1,
	[FEEDBACK_OPTION_TYPE_CLOCK] = 1,
	[FEEDBACK_OPTION_TYPE_JITTER] = 1,
	[FEEDBACK_OPTION_TYPE_LOSS] = 1,
};

int rohc_feedback_add_option_bits(struct sk_buff *skb,enum rohc_feedback_option_type opt_type,u8 *data,int data_bits_width)
{
	unsigned char *data_start;
	int opt_len;
	data_start = skb_tail_pointer(skb);
	opt_len = rohc_feedback_option_len[opt_type];
	/**
	 *fill feedback option with bit endian mode.
	 */
	*data_start = (opt_type & 0xf) << 4;
	*data_start |= opt_len & 0xf;
	data_start++;

	while(data_bits_width > 0 && opt_len > 0){
		if(data_bits_width < 8){
			*data_start = ((*data) & ((1 << data_bits_width) - 1)) << (8 - data_bits_width) ;
			data_bits_width = 0;
			opt_len = 0;
		}else{
			*data_start = *data & 0xff;
			data++;
			data_start++;
			data_bits_width -= 8;
			opt_len--;
		}

	}
	skb_put(skb, 1 + rohc_feedback_option_len[opt_type]);
	return 0;
}

int rohc_feedback_add_option_byte(struct sk_buff *skb,enum rohc_feedback_option_type opt_type,u8 *data)
{
	u8 *start;
	int opt_len;
	start = skb_tail_pointer(skb);
	opt_len = rohc_feedback_option_len[opt_type];

	/*first : option type and len
	 */
	*start = (opt_type & 0xf) << 4;
	*start |= opt_len & 0xf;
	start++;
	BUG_ON(opt_len > 1);
	if(opt_len && data)
		*start = *data;
	else if(data)
		pr_warn("warning : option %d len is zero,but want to wirte option data\n",opt_len);
	skb_put(skb, 1 + rohc_feedback_option_len[opt_type]);
	return 0;
}
int rohc_feedback_add_option_bytes(struct sk_buff *skb,enum rohc_feedback_option_type opt_type,u8 *opt_data,int data_bytes)
{
	u8 *start;
	int opt_len;
	u8 *buf;
	u8  *char_buf;
	u16 *short_buf;
	u16 *int_buf;
	start = skb_tail_pointer(skb);
	opt_len = rohc_feedback_option_len[opt_type];

	/*first : option type and len
	 */
	*start = (opt_type & 0xf) << 4;
	*start |= opt_len & 0xf;
	start++;
	switch(data_bytes){
		case TYPE_UCHAR_BYTES:
			*start = *opt_data;
			break;
		case TYPE_USHORT_BYTES:
			short_buf = (unsigned short *)opt_data;
			/*
			 *change to bit endian ,high byte write into the low address.
			 */
			(*short_buf) = __cpu_to_be16(*short_buf);
			buf = (u8 *)short_buf;
			BUG_ON(opt_len != TYPE_USHORT_BYTES);
			while(opt_len){
				*start = *buf;
				buf++;
				start++;
				opt_len--;
			}
			break;
		case TYPE_UINT_BYTES:
			int_buf = (u32 *)opt_data;
			/*
			 *change to bit endian ,high byte write into the low address.
			 */
			*int_buf = __cpu_to_be32(*int_buf);
			buf = (u8 *)int_buf;
			BUG_ON(opt_len != TYPE_UINT_BYTES);
			while(opt_len){
				*start = *buf;
				buf++;
				start++;
				opt_len--;
			}
			break;
		default:
			break;
	}
	skb_put(skb, 1 + rohc_feedback_option_len[opt_type]);
	return 0;
}
static void rohc_feedback_parse_sn_option(u8 *start,u32 *sn,enum rohc_profile prof,int *opt_bit_width)
{
	/*skip the option type and len byte
	 */
	start++;

	if(prof == ROHC_V1_PROFILE_TCP){
		(*sn) <<= 2;
		(*sn) |= ((*start) >> 6) & 0x3;
		(*opt_bit_width) += 2;
	}else if(!rohc_profile_is_v2(prof)){
		(*sn) <<= 8;
		(*sn) |= (*start) & 0xff;
		(*opt_bit_width) += 8;
	}else
		pr_err("rohc v2 not support sn option\n");

}

int rohc_feeback_parse_option_bytes(struct sk_buff *skb,enum rohc_feedback_option_type opt_type,enum rohc_profile prof,u8 *data,int data_bytes)
{
	u8 *start;
	u16 *short_buf;
	u32 *int_buf;
	int opt_len;
	int retval = 0;
	start = skb->data;
	opt_len = rohc_feedback_option_len[opt_type];
	/*skip the option type and len byte.
	 */
	start++;
	BUG_ON(data_bytes > opt_len);
	switch(data_bytes){
		case TYPE_UCHAR_BYTES:
			*data = *start;
			break;
		case TYPE_USHORT_BYTES:
			short_buf = (u16 *)start;
			*short_buf = __be16_to_cpu(*short_buf);
			memcpy(data,short_buf,data_bytes);
			break;
		case TYPE_UINT_BYTES:
			int_buf = (u32 *)start;
			*int_buf = __be32_to_cpu(*int_buf);
			memcpy(data,int_buf,data_bytes);
			break;
		default:
			pr_err("feedback parse variabel length option not support the len:%d\n",data_bytes);
			retval = -EFAULT;
			break;
	}
	skb_pull(skb,1 + opt_len);
	return retval;
}
int rohc_feedback_parse_option_byte(struct sk_buff *skb,enum rohc_feedback_option_type opt_type,enum rohc_profile prof,u8 *data)
{
	u8 *start;
	u8 opt_len;
	u8 value;
	int opt_bits;
	start = skb->data;
	opt_len = rohc_feedback_option_len[opt_type];
	/*skip the type and len byte.
	 */
	start++;
	BUG_ON(opt_len > 1);
	*data = *start;
	skb_pull(skb,1 + opt_len);
	return 0;
}
int rohc_feeback_parse_options(struct sk_buff *skb,struct rohc_feedback_option_compile *option_compile,enum rohc_profile prof,int feedback_size)
{
	u8 *start;
	u8 option_data;
	int len;
	u32 sn;
	u32 sn_opt_bits;
	enum rohc_feedback_option_type opt_type; 
	int options_len = 0;
	int retval = 0;
	start = skb->data;
	len = feedback_size;
	sn = option_compile->sn;
	sn_opt_bits = 0;
	opt_type = feedback_adjust_option_type(start);
	while(len){
		switch(opt_type){
			case FEEDBACK_OPTION_TYPE_SN:
				option_compile->option_apprear[opt_type]++;
				rohc_feedback_parse_sn_option(start,&sn,prof,&sn_opt_bits);
				start += rohc_feedback_option_len[opt_type] + 1;
				len -= rohc_feedback_option_len[opt_type] + 1;
				break;
			case FEEDBACK_OPTION_TYPE_CRC:
			case FEEDBACK_OPTION_TYPE_UNVALID_SN:
			case FEEDBACK_OPTION_TYPE_CLOCK:
			case FEEDBACK_OPTION_TYPE_JITTER:
			case FEEDBACK_OPTION_TYPE_LOSS:
				option_compile->option_apprear[opt_type]++;
				start += rohc_feedback_option_len[opt_type] + 1;
				len -= rohc_feedback_option_len[opt_type] + 1;
				break;
			default:
				retval = -EFAULT;
				goto out;
				
		}
		opt_type = feedback_adjust_option_type(start);
	}
	option_compile->sn = sn;
	option_compile->sn_opt_bits = sn_opt_bits;

out:
	skb_pull(skb,feedback_size);
	return retval;
}
int rohc_feedback_1_data_sn(struct sk_buff *skb,u8 msn)
{
	u8 *data = skb_tail_pointer(skb);
	*data = msn & 0xff;
	skb_put(skb,1);
	return 0;
}

int rohc_feedback_2_data_sn(struct sk_buff *skb , enum rohc_profile prof,int ack_type,int mode,u32 sn,int sn_bits_width)
{
	int retval;
	int sn_saved_bits ;
	unsigned char sn_opt,sn_opt_bits;
	unsigned char *data_start;
	int data_len = 0;
	int sn_opts;
	bool msn_valid = true;
	data_start = skb_tail_pointer(skb);
	*data_start = ack_type << 6;
	if(sn_bits_width <= 0){
		msn_valid = false;
		sn = 0;
	}else if(rohc_profile_is_v2(prof) || prof == ROHC_V1_PROFILE_TCP){
		/* feedback-2 format body is requeired to carray
		 * at least 14 bits for MSN
		 */
		if(sn_bits_width < MIN_FEEDBACK_PROF_V2_SN_BIT)
			sn_bits_width = MIN_FEEDBACK_PROF_V2_SN_BIT;

		if(prof == ROHC_V1_PROFILE_TCP){
			/*
			 *TCP SN option has a fixed format,
			 *only the high two bits.
			 */
			if(sn_bits_width > MIN_FEEDBACK_PROF_V2_SN_BIT){
				sn_bits_width  = 16;
				sn_opts = 1;
			}else
				sn_opts = 0;
		}else{
			/*rohc profile v2 has not MSN option
			 */
			sn_bits_width = MIN_FEEDBACK_PROF_V2_SN_BIT;
			sn_opts = 0;
		}
	}else{
		/* feedback-2 format body is requeired to carray
		 * at least 12 bits for MSN in rohc v1.
		 */
		
		if(sn_bits_width < MIN_FEEDBACK_PROF_V1_SN_BIT)
			sn_bits_width = MIN_FEEDBACK_PROF_V1_SN_BIT;
		/*sn bit width aligned down to (MIN_FEEDBACK_PROF_V1_SN_BIT + n * 8)
		 */
		sn_bits_width -= (sn_bits_width - MIN_FEEDBACK_PROF_V1_SN_BIT) % 8; 
		sn_opts = (sn_bits_width - MIN_FEEDBACK_PROF_V1_SN_BIT) / (rohc_feedback_option_len[FEEDBACK_OPTION_TYPE_SN] * 8);
	}

	if(rohc_profile_is_v2(prof) || prof == ROHC_V1_PROFILE_TCP){
			/*
			 *
			 * bit-endian
			 */
			if(sn_bits_width > 0){
				*data_start |= (sn >> (sn_bits_width - 6)) & 0x3f;
				sn_bits_width -= 6;
			}
	}else{
			*data_start |= (mode & 0x3) << 4;
			if(sn_bits_width){
				*data_start |= (sn >> (sn_bits_width - 4)) & 0xf;
				sn_bits_width -= 4;
			}

	}
	data_len++;
	data_start++;
	/*feedback-2 formats the second byte carray 8 bit SN
	 */
	*data_start = (sn >> (sn_bits_width - 8)) & 0xff;
	sn_bits_width -= 8;
	data_len++;
	data_start++;

	if(rohc_profile_is_v2(prof) || prof == ROHC_V1_PROFILE_TCP){
		/**
		 *CRC is after MSN,reserve the byte and set zero
		 */
		*data_start = 0;
		data_len++;
	}
	skb_put(skb,data_len);
	/**
	 *add feedback-2 sn  option
	 */
	if(msn_valid){
		while(sn_opts > 0){
			if(prof == ROHC_V1_PROFILE_TCP){
				sn_opt_bits = sn_bits_width;
				sn_opt = sn & ((1 << sn_bits_width) - 1);
				rohc_feedback_add_option_bits(skb,FEEDBACK_OPTION_TYPE_SN,&sn_opt,sn_opt_bits);

			}else{
				sn_opt = (sn >> (sn_bits_width - 8)) & 0xff;
				rohc_feedback_add_option_byte(skb,FEEDBACK_OPTION_TYPE_SN,&sn_opt);
			}
			sn_opts--;
		}	
	}else
		rohc_feedback_add_option_byte(skb,FEEDBACK_OPTION_TYPE_UNVALID_SN,NULL);

	return 0;
}
static inline int rohc_feedback_add_cid(struct sk_buff *skb,u16 cid,enum rohc_cid_type cid_type,int *cid_len)
{
	int retval;
	retval = rohc_cid_to_len(cid_type,cid,cid_len);
	if(retval)
		return retval;
	/*add cid to the feeback header.
	 */
	skb_push(skb,*cid_len);
	retval = rohc_cid_encode(cid_type,skb->data,cid_len,cid);
	if(retval)
		return retval;
	return retval;
}

static inline void rohc_feedback_add_crc(struct sk_buff *skb,enum rohc_profile prof,int cid_len,bool add_crc_opt)
{
	u8 *crc;
	if(prof == ROHC_V1_PROFILE_TCP || rohc_profile_is_v2(prof)){
		/* crc is behind msn,msn length is 2 bytes
		 *
		 */
		crc = skb->data + cid_len + 2;
		*crc = 0;
	}else if(add_crc_opt){
		rohc_feedback_add_option_byte(skb,FEEDBACK_OPTION_TYPE_CRC,NULL);
		crc = skb_tail_pointer(skb) - 1;
		*crc = 0;
	}
	/**
	 *caculate crc value ,feedback crc contains an 8-bit crc computed over 
	 *the entire feedback packet,without the packet type and size byte,but 
	 *including any cid fields.
	 */
	//TODO CRC.
	//default zero
}
int rohc_feedback_add_header(struct sk_buff *skb,enum rohc_profile prof,u16 cid,enum rohc_cid_type cid_type,bool add_crc_opt)
{
	int retval = 0;
	int cid_len;
	int feedback_size;
	u8 *type;
	retval = rohc_feedback_add_cid(skb,cid,cid_type,&cid_len);
	if(retval)
		return retval;

	if(add_crc_opt)
		rohc_feedback_add_crc(skb,prof,cid_len,add_crc_opt);


	feedback_size = skb->len;
	if(feedback_size < 8){
		skb_push(skb,1);
		type = skb->data;
		*type = ROHC_PACKET_FEEDBACK | (feedback_size & 0x7);
	}else{

		skb_push(skb,2);
		type = skb->data;
		*type = ROHC_PACKET_FEEDBACK;
		type++;
		*type = feedback_size;
	}
	/*start address align two bytes
	 */
	if(skb_headroom(skb) & 0x1){
		memmove(skb->data + 1,skb->data,skb->len);
		skb_put(skb,1);
		skb_pull(skb,1);
	}
	return retval;
}


int rohc_feedback_parse_header(struct sk_buff *skb,enum rohc_cid_type cid_type,int *hdr_len,int *feeback_size,int *cid,int *cid_len)
{
	int retval;
	int hdr_size;
	size_t size;
	u8 *feedback_start;
	feedback_start = skb->data;
	if(!rohc_packet_is_feedback(feedback_start)){
		retval = -EFAULT;
		goto out;
	}
	/*
	 *init for feedback type length.
	 */
	hdr_size = 1;
	/*
	 *part 1. parse feedback size.
	 */
	if(BYTE_BITS_0_2(*feedback_start)){
		size = BYTE_BITS_0_2(*feedback_start);
	}else{
		feedback_start++;
		size = *feedback_start;
		hdr_size++;
	}
	/*
	 *part 2. parse cid.
	 */
	feedback_start++;
	rohc_cid_decode(cid_type,feedback_start,cid_len,cid);
	*feeback_size = size;
	*hdr_len = hdr_size;
	/*
	 *part 3.remove packet type and size bytes.
	 */
	skb_pull(skb,hdr_size);
	retval = 0;
out:
	return retval;
}
bool rohc_feeback_crc_is_ok(struct sk_buff *skb,enum rohc_profile prof,int cid_len)
{
	u8 *crc;
	u8 *data;
	bool retval = true;
	data = skb->data;
	if(rohc_profile_is_v2(prof)|| prof == ROHC_V1_PROFILE_TCP){
		crc = data + cid_len + 2;
		/**
		 *caculate crc and compare
		 */
	}else{
		/*
		 *adjust is or not with crc option
		 */
		data = skb_tail_pointer(skb) - 2;
		if((*data >> 4) & 0xf == FEEDBACK_OPTION_TYPE_CRC){
			crc = data + 1;
			/**
			 *caculate crc and compare
			 */
		}
	}

	return retval;
}
