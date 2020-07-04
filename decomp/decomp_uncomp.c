/*
 *author : yangjun
 *date :
 *
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "rohc_decomp.h"
#include "../rohc_cid.h"
#include "../rohc_profile.h"
#include "../rohc_packet.h"
#include "../rohc_common.h"

#include "../profile/rohc_v2_profile.h"
#define	UNCOMP_NORMAL_PACKET_PAD_BYTE		(0x5a)
int profile_uncomp_init_context(struct rohc_decomp_context *context,struct sk_buff *skb)
{
	return 0;
}

int profile_uncomp_destroy_context(struct rohc_decomp_context *context,struct sk_buff *skb)
{
	return 0;
}

u32 profile_uncomp_last_compressed_sn(struct rohc_decomp_context *context)
{
	/**
	 *profile uncomp only support FEEDBACK-1 format,and msn is zero.only ACK type.
	 */
	return 0;
}

u32 profile_uncomp_sn_bit_width(struct rohc_decomp_context *context)
{
	return 0;
}

static int profile_uncomp_rebuild_packet_hdr(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	return 0;
}
enum rohc_packet_type profile_uncomp_adjust_packet_type(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	enum rohc_packet_type packet_type;
	packet_type = pkt_info->packet_type;
	if(packet_type != ROHC_PACKET_TYPE_IR)
		packet_type = ROHC_PACKET_TYPE_NORMAL;


	return packet_type;
}

int profile_uncomp_analyze_packet_hdr(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	int retval;
	unsigned char crc;
	enum rohc_packet_type packet_type;
	enum rohc_cid_type	cid_type;
	enum rohc_profile prof;
	unsigned char *decomp_hdr;
	struct sk_buff *decomp_skb;
	struct rohc_decompresser *rohc_decomp;
	int decomp_len = 0;
	rohc_decomp = context->decompresser;
	cid_type = rohc_decomp->cid_type;
	packet_type = pkt_info->packet_type;
	decomp_skb = context->decomp_skb;
	decomp_hdr = skb->data + pkt_info->decomped_hdr_len;
	/*copy the ether header.
	 */
	if(context->decomp_eth_hdr){
		memcpy(decomp_skb->data,skb->data,sizeof(struct ethhdr));
		pkt_info->rebuild_hdr_len = sizeof(struct ethhdr);
		skb_put(decomp_skb,sizeof(struct ethhdr));
	}else
		pr_err("%s : error not decomp eth header\n",__func__);
	if(packet_type == ROHC_PACKET_TYPE_IR){
		/**
		 *if packet_type is IR ,cid and packet type have removed.
		 */

		/*1. parse profile,IR packet has parsed profile in function rohc_decomp_decompress
		 */

		prof = *(decomp_hdr - 1);
		//decomp_len++;
		//decomp_hdr++;
		if(prof != ROHC_V1_PROFILE_UNCOMP){
			pr_err("%s : error profile in pakcet header\n",__func__);
			retval = -EFAULT;
			goto out;
		}
		/*calulate crc.
		 *
		 */
		crc = *decomp_hdr;
		/**
		 *TODO adjust crc is correct,default not do
		 */
		decomp_hdr++;
		decomp_len++;
		pkt_info->decomped_hdr_len += decomp_len;
	}else{
		if(cid_type == CID_TYPE_SMALL){
			pkt_info->decomped_hdr_len += pkt_info->cid_len;
			decomp_hdr = skb->data + pkt_info->decomped_hdr_len;
			pkt_info->decomped_hdr_len++;
		}else{
			decomp_hdr = skb->data + pkt_info->decomped_hdr_len;
			pkt_info->decomped_hdr_len += pkt_info->cid_len + 1;
		}
		/*decode the first byte of ip packet.
		*/
		memcpy(skb_tail_pointer(decomp_skb),decomp_hdr,1);
		skb_put(decomp_skb,1);
		pkt_info->rebuild_hdr_len += 1;

#if 0
		if((pkt_info->rebuild_hdr_len & 0x1) && !(pkt_info->decomped_hdr_len & 0x1)){
			/**
			 *the normal type packet pad a byte to fit the two-byte alignment of euht,
			 *so remove it
			 */
			decomp_hdr = skb->data + pkt_info->decomped_hdr_len;
			if(*decomp_hdr != UNCOMP_NORMAL_PACKET_PAD_BYTE){
				printk(KERN_DEBUG "%s : the %d bytes is not pad byte : %x\n",__func__,pkt_info->decomped_hdr_len,*decomp_hdr);
			}
			pkt_info->decomped_hdr_len++;
		}
#endif
	}
	retval = 0;
out:
	return retval;
}


int profile_uncomp_decompress(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	int retval;
	struct rohc_decomp_profile_ops *pro_ops = context->decomp_profile->pro_ops;
	retval = pro_ops->analyze_packet_header(context,skb,pkt_info);
	if(retval){
		pr_err("profile-%x analyze packet header fail\n",context->decomp_profile->profile);
		return retval;
	}

	if(pro_ops->rebuild_packet_header){
		retval = pro_ops->rebuild_packet_header(context,skb,pkt_info);
	}


	return retval;
}

struct rohc_decomp_profile_ops uncomp_prof_ops = {
	.adjust_packet_type = profile_uncomp_adjust_packet_type,
	.analyze_packet_header = profile_uncomp_analyze_packet_hdr,
	.rebuild_packet_header = profile_uncomp_rebuild_packet_hdr,
	.decompress = profile_uncomp_decompress,
	.last_decompressed_sn = profile_uncomp_last_compressed_sn,
	.sn_bit_width = profile_uncomp_sn_bit_width,
	.init_context = profile_uncomp_init_context,
	.destroy_context = profile_uncomp_destroy_context,
};

struct rohc_decomp_profile uncomp_profile = {
	.profile = ROHC_V1_PROFILE_UNCOMP,
	.pro_ops = &uncomp_prof_ops,
};
