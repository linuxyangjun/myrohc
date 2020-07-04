/**
 *author : yangjun
 *date : 14/10/2019
 *
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/string.h>
//#include <linux>
#include "../rohc_profile.h"
#include "../rohc_packet.h"
#include "../rohc_common.h"
#include "../rohc_cid.h"
#include "../rohc_feedback.h"
#include "rohc_comp.h"
#include "comp_uncomp.h"

#include "../profile/rohc_v2_profile.h"
#define	PROFILE_UNCOMP_PAD_BYTE (0x5a)
static enum rohc_packet_type profile_uncomp_adjust_packet_type(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	enum rohc_packet_type packet_type;
	struct iphdr *iph;
	if(context->context_state == COMP_STATE_IR)
		packet_type = ROHC_PACKET_TYPE_IR;
	else 
		packet_type = ROHC_PACKET_TYPE_NORMAL;
	/**
	 *normal state packet only  support  IP packet.
	 */
	//if(!pkt_info->has_inner_iph)
	//		packet_type = ROHC_PACKET_TYPE_IR;
	return packet_type;
}	

static int profile_uncomp_build_comp_header(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,enum rohc_packet_type packet_type)
{
	int retval = 0;
	int cid_encode_len;
	int pad_locat =0;
	u16 cid;
	unsigned char *comp_hdr;
	unsigned char *payload;
	struct ethhdr *eth;
	struct sk_buff *comp_skb;
	struct rohc_compresser *rohc_comp; 
	comp_skb = context->comp_skb;
	rohc_comp = context->compresser;
	cid = context->cid;
	comp_hdr = comp_skb->data;
	if(context->comp_eth_hdr){
		eth = eth_hdr(skb);
		memcpy(comp_hdr,eth,sizeof(struct ethhdr));
		pkt_info->comp_hdr_len += sizeof(struct ethhdr);
		comp_hdr += sizeof(struct ethhdr);
	}else
		pr_err("%s : error not set comp eth header\n",__func__);
	pad_locat = pkt_info->comp_hdr_len;
	if(packet_type == ROHC_PACKET_TYPE_IR){
		if(rohc_comp->cid_type == CID_TYPE_SMALL){
			retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
			if(retval)
				goto out;
			comp_hdr += cid_encode_len;
			*comp_hdr = ROHC_PACKET_IR;
			comp_hdr ++;

		}else{
			*comp_hdr = ROHC_PACKET_IR;
			comp_hdr ++;
			retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
			if(retval)
				goto out;
			comp_hdr += cid_encode_len;
		
		}
		pkt_info->comp_hdr_len += 1 + cid_encode_len;
		/**
		 *add profile
		 */
		*comp_hdr = ROHC_V1_PROFILE_UNCOMP;
		comp_hdr++;
		pkt_info->comp_hdr_len++;
		/**
		 *add crc ,
		 */
		*comp_hdr = 0;
		/**
		 *TODO calculate crc .
		 */
		pkt_info->comp_hdr_len++;
	}else{
		payload = skb->data + pkt_info->to_comp_pkt_hdr_len;
		if(rohc_comp->cid_type == CID_TYPE_SMALL){
			retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
			if(retval)
				goto out;
			comp_hdr += cid_encode_len;
			*comp_hdr = *payload;
			comp_hdr++;

		}else{
			*comp_hdr = *payload;
			comp_hdr++;
			retval = rohc_cid_encode(rohc_comp->cid_type,comp_hdr,&cid_encode_len,cid);
			if(retval)
				goto out;
			comp_hdr += cid_encode_len;
		
		}
		pkt_info->comp_hdr_len += cid_encode_len + 1;
		/**
		 *normal state packet compress header fill one byte ip packet.
		 */
		pkt_info->to_comp_pkt_hdr_len++;
		if((pkt_info->to_comp_pkt_hdr_len & 0x1) != (pkt_info->comp_hdr_len & 0x1)){
			/*
			 *pad a byte to fit the two-byte alignment of euht tx
			 */
#if 0
			comp_hdr = comp_skb->data + pkt_info->comp_hdr_len;
			*comp_hdr = PROFILE_UNCOMP_PAD_BYTE;
			pkt_info->comp_hdr_len++;
			comp_hdr++;
#else
			memmove(comp_skb->data + pad_locat + 1,comp_skb->data + pad_locat,pkt_info->comp_hdr_len - pad_locat);
			/**
			 *add padding
			 *
			 */
			comp_hdr = comp_skb->data + pad_locat;
			*comp_hdr = ROHC_PACKET_PADDING;
			pkt_info->comp_hdr_len++;
#endif
		}
	
	}

	skb_put(comp_skb,pkt_info->comp_hdr_len);
out:
	return retval;
}

static int profile_uncomp_compress(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct ethhdr *ethh;
	int retval;
	enum rohc_packet_type packet_type;
	ethh = (struct ethhdr *)skb->data;
	u8 *src = ethh->h_source;
	u8 *dst = ethh->h_dest;
	int i;
	for(i = 0 ; i < 6; i++,src++,dst++){
		//printk(KERN_DEBUG "COMP : src-%d:%x,dest-%d:%x\n",i,*src,i,*dst);
	}
	//rohc_v2_net_header_dump(skb,context->cid,msn);
	packet_type = profile_uncomp_adjust_packet_type(context,skb,pkt_info);
	pkt_info->packet_type = packet_type;
	retval = profile_uncomp_build_comp_header(context,skb,pkt_info,packet_type);

	return retval;
}

int profile_uncomp_feedack_input(struct rohc_comp_context *context,struct sk_buff *skb,int cid_len,int feeback_size)
{
	enum rohc_profile prof;
	int retval;
	struct rohc_comp_profile *comp_profile;
	u8 *data_start;
	comp_profile = context->comp_profile;
	prof = comp_profile->profile;
	if(!rohc_feeback_crc_is_ok(skb,prof,cid_len)){
		pr_err("%s : the cid-%d context feeback's crc is error\n",__func__,context->cid);
		retval = -EFAULT;
		goto out;
	}
	skb_pull(skb,cid_len);
	feeback_size -= cid_len;
	if(feeback_size  > 1){
		rohc_pr(ROHC_DCORE,"%s : PROFLE_UNCOMP not support feeback-2,total_size=%d,cid_len=%d\n",__func__,cid_len + feeback_size,cid_len);
		retval = -EINVAL;
		goto out;
	}
	skb_pull(skb,feeback_size);
	rohc_comp_context_change_mode(context,ROHC_MODE_O);
	rohc_comp_context_change_state(context,COMP_STATE_NORMAL);

out:
	return retval;
}

static int profile_uncomp_init_context(struct rohc_comp_context *context,struct sk_buff *skb)
{
	return 0;
}

static int profile_uncomp_destroy_context(struct rohc_comp_context *context)
{
	return 0;
}
struct comp_profile_ops profile_uncomp_ops = {
	.adjust_packet_type = profile_uncomp_adjust_packet_type,
	.build_comp_header = profile_uncomp_build_comp_header,
	.compress = profile_uncomp_compress,
	.feedback_input = profile_uncomp_feedack_input,
	.init_context = profile_uncomp_init_context,
	.destroy_context = profile_uncomp_destroy_context,
};

struct rohc_comp_profile profile_uncomp = {
	.profile = ROHC_V1_PROFILE_UNCOMP,
	.pro_ops = &profile_uncomp_ops,
};
