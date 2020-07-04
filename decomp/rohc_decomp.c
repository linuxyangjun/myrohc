
/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	date: 2019/10/19
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */


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
#include "../rohc_rb.h"
#include "rohc_decomp.h"

#include "../rohc_profile.h"
#include "../rohc_cid.h"
#include "../rohc_feedback.h"
#include "rohc_decomp_k_out_n.h"




static	struct list_head decomp_profile_list[ROHC_PROFILE_MAX];
static	DEFINE_SPINLOCK(decomp_profile_lock);

int rohc_decomp_register_profile(struct rohc_decomp_profile *profile)
{
	int retval;
	enum rohc_profile prof;
	int hash;
	struct list_head *head;
	struct rohc_decomp_profile *prof_find;
	prof = profile->profile;
	hash = ROHC_PROFILE_HASH(prof);
	head = &decomp_profile_list[hash];
	spin_lock(&decomp_profile_lock);
	list_for_each_entry(prof_find,head,list){
		if(prof_find->profile == prof){
			pr_err("%s : profile-%x is exit\n",__func__,prof);
			retval = -EEXIST;
			goto out;
		}	
	}
	list_add_rcu(&profile->list,head);
	spin_unlock(&decomp_profile_lock);
	retval = 0;
out:
	return retval;
}

struct rohc_decomp_profile *rohc_decomp_find_profile(enum rohc_profile prof)
{
	int hash;
	bool found = false;
	struct list_head *head;
	struct rohc_decomp_profile *decomp_prof;
	hash = ROHC_PROFILE_HASH(prof);
	head = &decomp_profile_list[hash];
	rcu_read_lock();
	list_for_each_entry_rcu(decomp_prof,head,list){
		if(decomp_prof->profile == prof){
			found = true;
			break;
		}
	}
	rcu_read_unlock();
	if(!found)
		decomp_prof = NULL;
	return decomp_prof;
}
void rohc_decomp_set_refresh_param(struct rohc_decompresser *decomp,struct rohc_decomp_refresh_threshold *set)
{

	memcpy(&decomp->refresh_threshold,set,sizeof(struct rohc_decomp_refresh_threshold));
}
static void rohc_decomp_context_init_period_param(struct rohc_decompresser *decomp,struct rohc_decomp_context *new_context)
{
	struct rohc_decomp_refresh_threshold *thold;
	struct rohc_decomp_period_update *update;
	thold = &decomp->refresh_threshold;
	update = &new_context->period_update;
	rohc_decomp_downward_kn_init(&update->static_nack_kn_nc,thold->downward_nc_k,thold->downward_nc_n);
	rohc_decomp_downward_kn_init(&update->static_nack_kn_sc,thold->downward_sc_k,thold->downward_sc_n);
	rohc_decomp_downward_kn_init(&update->nack_kn_sc,thold->downward_sc_k,thold->downward_sc_n);
	rohc_decomp_downward_kn_init(&update->nack_kn_fc,thold->downward_fc_k,thold->downward_fc_n);
	rohc_decomp_downward_kn_init(&update->sparse_ack_down,thold->sparse_ack_k,thold->sparse_ack_n);


}
static void rohc_decomp_nack_kn_period_update(struct rohc_decomp_context *context,bool is_nack)
{
	struct downward_kn *dkn;
	struct rohc_decomp_period_update *param;
	param = &context->period_update;
	switch(context->context_state){
		case DECOMP_STATE_FULL_CONTEXT:
			dkn = &param->nack_kn_fc;
			dkn->sn++;
			break;
		case DECOMP_STATE_STATIC_CONTEXT:
			if(!is_nack)
				dkn = &param->static_nack_kn_sc;
			else
				dkn = &param->nack_kn_sc;
			dkn->sn++;
			break;
		case DECOMP_STATE_NO_CONTEXT:
			dkn = &param->static_nack_kn_nc;
			dkn->sn++;
			break;
		default:
			BUG();
	}

}
static void rohc_decomp_nack_kn_update(struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	enum rohc_profile prof;
	enum rohc_packet_type packet_type;
	struct downward_kn *dkn;
	struct rohc_decomp_period_update *update_param;
	prof = pkt_info->prof;
	update_param = &context->period_update;
	/*RF3095 5.10.4
	 * The only kind of feedback in profile 0x000 is ACKs,
	 * ACKs use feeback-1 format.
	 * when decompression recieved any type packets in any state,
	 * even the packet is not ok ,it is discarded without further
	 * action
	 */

	if(prof == ROHC_V1_PROFILE_UNCOMP)
		return;
	switch(context->context_state){
		case DECOMP_STATE_FULL_CONTEXT:
			dkn = &update_param->nack_kn_fc;
			dkn->sn++;
			break;
		case DECOMP_STATE_STATIC_CONTEXT:

			dkn = &update_param->nack_kn_sc;
			dkn->sn++;
			dkn = &update_param->static_nack_kn_sc;
			dkn->sn++;
			break;
		case DECOMP_STATE_NO_CONTEXT:
			dkn = &update_param->static_nack_kn_nc;
			dkn->sn++;
			break;
	}

}
static void rohc_decomp_nack_kn_reset(struct rohc_decomp_context *context)
{

	struct rohc_decomp_period_update *param;
	param = &context->period_update;
	switch(context->context_state){
		case DECOMP_STATE_FULL_CONTEXT:
			rohc_decomp_downward_kn_reset(&param->nack_kn_fc);
			break;
		case DECOMP_STATE_STATIC_CONTEXT:
			rohc_decomp_downward_kn_reset(&param->static_nack_kn_sc);
			rohc_decomp_downward_kn_reset(&param->nack_kn_sc);
			break;
		case DECOMP_STATE_NO_CONTEXT:
			rohc_decomp_downward_kn_reset(&param->static_nack_kn_nc);
			break;
		default:
			BUG();
	}
}
static void rohc_decomp_nack_kn_set(struct rohc_decomp_context *context,bool is_nack)
{
	struct rohc_decomp_period_update *param;
	struct downward_kn *dkn;
	param = &context->period_update;
	switch(context->context_state){
		case DECOMP_STATE_FULL_CONTEXT:
			rohc_decomp_downward_kn_set(&param->nack_kn_fc,param->nack_kn_fc.sn);
			break;
		case DECOMP_STATE_STATIC_CONTEXT:
			if(is_nack)
				dkn = &param->nack_kn_sc;
			else 
				dkn = &param->static_nack_kn_sc;
			rohc_decomp_downward_kn_set(dkn,dkn->sn);
			break;
		case DECOMP_STATE_NO_CONTEXT:
			rohc_decomp_downward_kn_set(&param->static_nack_kn_nc,param->static_nack_kn_nc.sn);
			break;
		default:
			BUG();
	
	}
}
static void rohc_decomp_ack_kn_update(struct rohc_decomp_context *context)
{
	struct downward_kn *dkn;
	struct rohc_decomp_period_update *param;
	param = &context->period_update;
	dkn = &param->sparse_ack_down;
	dkn->sn++;
}
static void rohc_decomp_ack_kn_reset(struct rohc_decomp_context *context)
{
	struct rohc_decomp_period_update *param;
	param = &context->period_update;

	rohc_decomp_downward_kn_reset(&param->sparse_ack_down);
	rohc_decomp_upward_kn_reset(&param->sparse_ack_up);
}
static void rohc_decomp_ack_kn_set(struct rohc_decomp_context *context)
{
	struct rohc_decomp_period_update *param = &context->period_update;
	rohc_decomp_downward_kn_set(&param->sparse_ack_down,param->sparse_ack_down.sn);
}
static void rohc_decomp_upward_context_state(struct rohc_decomp_context *context)
{
	if(context->context_state != DECOMP_STATE_FULL_CONTEXT){
		context->context_state = DECOMP_STATE_FULL_CONTEXT;
		rohc_decomp_ack_kn_reset(context);
		rohc_decomp_nack_kn_reset(context);
	}
}


static void rohc_decomp_downward_context_state(struct rohc_decomp_context *context)
{
	int downward_state;
	enum rohc_profile prof;
	prof = context->decomp_profile->profile;
	if(prof == ROHC_V1_PROFILE_UNCOMP)
		return;
	switch(context->context_state){
		case DECOMP_STATE_FULL_CONTEXT:
			downward_state = DECOMP_STATE_STATIC_CONTEXT;
			break;
		case DECOMP_STATE_STATIC_CONTEXT:
			downward_state = DECOMP_STATE_NO_CONTEXT;
			break;
		case DECOMP_STATE_NO_CONTEXT:
			downward_state = DECOMP_STATE_NO_CONTEXT;
			break;
		default:
			BUG();
	}

	context->context_state = downward_state;
	rohc_decomp_ack_kn_reset(context);
	rohc_decomp_nack_kn_reset(context);
}

void rohc_decomp_decode_feedback(struct rohc_decompresser *rohc_decomp,struct sk_buff *skb,struct sk_buff *rcv_feedback)
{
	int retval;
	int fb_data_len;
	int fb_hdr_len;
	u8 *comp_hdr;
	u8 *copy_to_tail;
	struct rohc_decomp_pkt_hdr_info *pkt_info;
	fb_hdr_len = 0;
	pkt_info = &rohc_decomp->pkt_info;
	comp_hdr = skb->data + pkt_info->decomped_hdr_len;
	while(rohc_packet_is_feedback(comp_hdr) && (skb->len > pkt_info->decomped_hdr_len)){
		fb_data_len = BYTE_BITS_0_3(*comp_hdr);
		fb_hdr_len = 0;
		comp_hdr++;
		fb_hdr_len++;
		if(!fb_data_len){
			fb_data_len = *comp_hdr;
			comp_hdr++;
			fb_hdr_len++;
		}
		pkt_info->decomped_hdr_len += fb_hdr_len; 
		copy_to_tail = skb_tail_pointer(rcv_feedback);
		skb_copy_bits(skb,pkt_info->decomped_hdr_len - fb_hdr_len,copy_to_tail,fb_data_len + fb_hdr_len);
		skb_put(rcv_feedback,fb_data_len + fb_hdr_len);
		pkt_info->decomped_hdr_len += fb_data_len;
		comp_hdr = skb->data + pkt_info->decomped_hdr_len;
	}


}

int rohc_decomp_decode_cid(struct rohc_decompresser *rohc_decomp,struct sk_buff *skb,u16 *cid)
{
	int retval;
	u8 *comp_hdr;
	struct rohc_decomp_pkt_hdr_info *pkt_info;
	retval = 0;
	pkt_info = &rohc_decomp->pkt_info;
	if(pkt_info->decomped_hdr_len >= skb->len){
		retval = -ENOSPC;
		goto out;
	}
	if(rohc_decomp->cid_type == CID_TYPE_SMALL)
		comp_hdr = skb->data + pkt_info->decomped_hdr_len;
	else
		comp_hdr = skb->data + pkt_info->decomped_hdr_len + 1;
	retval = rohc_cid_decode(rohc_decomp->cid_type,comp_hdr,&pkt_info->cid_len,cid);
out:
	return retval;
}
/**
 *only decode packet type,but don't increase decomped_hdr_len,except IR and IR_DYN,because some specific packet type require corresponding protocol
 *resolution
 */
enum rohc_packet_type rohc_decomp_decode_packet_type(struct rohc_decompresser *rohc_decomp,struct sk_buff *skb,int cid_len)
{
	enum rohc_packet_type packet_type;
	u8 type_value;
	u8 *comp_hdr;
	struct rohc_decomp_pkt_hdr_info *pkt_info;
	pkt_info = &rohc_decomp->pkt_info;
	if(rohc_decomp->cid_type == CID_TYPE_LARGE)
		comp_hdr = skb->data + pkt_info->decomped_hdr_len;
	else
		comp_hdr = skb->data + pkt_info->decomped_hdr_len + cid_len;
	if(rohc_packet_is_ir(comp_hdr)){
		packet_type = ROHC_PACKET_TYPE_IR;
		if(((*comp_hdr) & 0x1))
			packet_type = ROHC_PACKET_TYPE_IR_CR;
		pkt_info->decomped_hdr_len++;
	}else if(rohc_packet_is_irdyn(comp_hdr)){
		packet_type = ROHC_PACKET_TYPE_IR_DYN;
		pkt_info->decomped_hdr_len++;
	}else 
		packet_type = ROHC_PACKET_TYPE_UNDECIDE;
	if(packet_type != ROHC_PACKET_TYPE_UNDECIDE)
		pkt_info->decomped_hdr_len += cid_len;
	else
		rohc_pr(ROHC_DTCP,"type byte=%x\n",*comp_hdr);
	return packet_type;
}

/*
 * only decode the profile when the packet type is IR or IR_DYN.
 *
 */
enum rohc_profile rohc_decomp_decode_profile(struct rohc_decompresser *rohc_decomp,struct sk_buff *skb)
{
	enum rohc_profile profile;
	u8 *comp_hdr;
	struct rohc_decomp_pkt_hdr_info *pkt_info;
	pkt_info = &rohc_decomp->pkt_info;
	comp_hdr = skb->data + pkt_info->decomped_hdr_len;
	profile = *comp_hdr;
	pkt_info->decomped_hdr_len++;
	return profile;
}
struct rohc_decomp_context *rohc_decomp_context_find(struct rohc_decompresser *rohc_decomp,u16 cid)
{
	struct rohc_decomp_context *context;
	struct rohc_rb_node *rohc_node;
	rohc_node = rohc_rb_find(&rohc_decomp->decomp_rb,cid);
	if(rohc_node)
		context = container_of(rohc_node,struct rohc_decomp_context,context_rb);
	else 
		context = NULL;
	return context;
}
struct rohc_decomp_context *rohc_decomp_context_alloc(struct rohc_decompresser *rohc_decomp,struct sk_buff *skb,u16 cid,enum rohc_profile prof,gfp_t flags)
{
	u8 pro_high,pro_low;
	struct rohc_decomp_context *new_context;
	struct rohc_decomp_profile *decomp_profile;
	struct rohc_decomp_profile_ops *pro_ops;
	pro_high = (prof >> 8) & 0xff;
	pro_low = prof & 0xff;
	if(prof == 2 || prof == 1 || prof == 4)
		prof += 256;
	decomp_profile = rohc_decomp_find_profile(prof);//rohc_decomp->decomp_profiles[pro_high][pro_low];
	if(!decomp_profile){
		rohc_pr(ROHC_DV2,"can't find profile-%x decomp profile\n",prof);
		goto err0;
	}
	pro_ops = decomp_profile->pro_ops;
	new_context =  kzalloc(sizeof(struct rohc_decomp_context),flags);
	if(!new_context){
		pr_err("alloc  decomp context failed for decompresser-%s",rohc_decomp->name);
		goto err0;
	}
	new_context->decomp_skb = alloc_skb(PAGE_SIZE,flags);
	if(!new_context->decomp_skb){
		pr_err("alloc decomp skb failed");
		goto err1;
	}
	/**
	 *init context
	 */
	if(pro_ops->init_context){
		if(pro_ops->init_context(new_context))
			rohc_pr(ROHC_DCORE,"init context failed\n");
		//goto err1;
	}

	new_context->context_state = DECOMP_STATE_NO_CONTEXT;
	new_context->mode = ROHC_MODE_U;
	new_context->set_mode = ROHC_MODE_O;
	new_context->decomp_eth_hdr = rohc_decomp->decomp_eth_hdr;
	new_context->decompresser = rohc_decomp;
	new_context->decomp_profile = decomp_profile;
	new_context->cid = cid;
	new_context->context_rb.key = cid;
	rohc_rb_insert(&rohc_decomp->decomp_rb,&new_context->context_rb);
	rohc_decomp_context_init_period_param(rohc_decomp,new_context);
	return new_context;
err1:
	kfree(new_context);
err0:
	new_context = ERR_PTR(-ENOMEM);
	return new_context;

}

void rohc_decomp_context_destroy(struct rohc_decompresser *rohc_decomp,struct rohc_decomp_context *context)
{
	struct rohc_decomp_profile_ops *pro_ops;;
	pro_ops = context->decomp_profile->pro_ops;;
	if(pro_ops->destroy_context)
		pro_ops->destroy_context(context);
	rohc_rb_del(&rohc_decomp->decomp_rb,&context->context_rb);
	kfree(context);

}
static int rohc_decomp_feedback_ack(struct rohc_decompresser *rohc_decomp,struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info,struct sk_buff *feedback)
{
	int retval;
	u16 cid;
	u32 sn;
	int sn_bit_width;
	bool add_crc_opt = false;
	bool need_ack;
	enum rohc_packet_type packet_type;
	enum rohc_profile prof;
	struct rohc_decomp_period_update *update_param;
	struct rohc_decomp_profile *decomp_profile;
	update_param = &context->period_update;
	decomp_profile = context->decomp_profile;
	prof = decomp_profile->profile;
	packet_type = pkt_info->packet_type;
	/*If decompresser decompress any packet sucessfully,
	 *it should change state to full context.
	 */
	/*rf6846 5.3.1.3 
	 * once a packet has been validated and decompressed 
	 * correctly,the decompressor must transit to the 
	 * FC state.
	 */
	rohc_decomp_upward_context_state(context);

	if(context->mode == ROHC_MODE_U){
		retval = 0;
		goto out;
	}

	/*rf3095 5.3.2.2.1 
	 * In the full context state,decompression may attempted regardless of
	 * what kind of packet is received. However,for the other states decompression
	 * is not always allowed.In the No context state only IR packets,whitch carrying
	 * the static information fileds,may be decompressed.Further,when in the Static
	 * context state,only packets carrying a 7 0r 8 bit crc can be decompressed(i.e.,
	 * IR,IR_DYN,or type 2 packets)
	 */
	if(packet_type == ROHC_PACKET_TYPE_IR || packet_type == ROHC_PACKET_TYPE_IR_CR)
			need_ack = true;
	else{
		switch(context->context_state){
			case DECOMP_STATE_FULL_CONTEXT:
				/*When an IR packet is correctly decompressed ,send an ACK.
				 * When a type 2 or IR_DYN packet is correctly decompressed,optionally ACK.
				 * When a type 0 or 1 packet is correctly decompressed,no feedback is sent.
				 */
				/*full context state,decompresser can decompress any packet.
				 */
				if(rohc_packet_is_covered_by_crc7_or_crc8(packet_type) || rohc_packet_is_type_2(packet_type) || (packet_type == ROHC_PACKET_TYPE_IR_DYN))
					need_ack = true;
				else 
					need_ack = false;
				break;
			case DECOMP_STATE_STATIC_CONTEXT:
				if(rohc_packet_is_covered_by_crc7_or_crc8(packet_type) || rohc_packet_is_type_2(packet_type) || (packet_type == ROHC_PACKET_TYPE_IR_DYN))
					need_ack = true;
				else
					need_ack = false;
				break;
			case DECOMP_STATE_NO_CONTEXT:
				need_ack = false;
				break;

		}
	}
	if(context->decomp_profile->profile == ROHC_V1_PROFILE_TCP)
		printk(KERN_DEBUG "%s : mode=%d,packet_type=%d,state=%d,need_ack=%d\n",__func__,context->mode,packet_type,context->context_state,need_ack);
	if(!need_ack && !context->need_establish_feedback_channel){
		retval = 0;
		goto out;
	}
	rohc_decomp_ack_kn_update(context);
	/*
	 *if decompresser recives first packet,it 
	 *should send feedback .
	 */
	if(rohc_decomp_downward_is_k_out_n(&update_param->sparse_ack_down) && !context->need_establish_feedback_channel){
		need_ack = false;
		retval = 0;
		goto out;
	}
	rohc_decomp_ack_kn_set(context);

	/*rf3095 5.6.2
	 *any feedback packet carrying a crc 
	 *can be used with the mode paramter set to O.
	 */
	if((prof != ROHC_V1_PROFILE_UNCOMP) && context->need_mode_trans)
		add_crc_opt = true;
	sn = decomp_profile->pro_ops->last_decompressed_sn(context);
	sn_bit_width = decomp_profile->pro_ops->sn_bit_width(context);
	skb_reserve(feedback,ROHC_FEEDBACK_HEADER_MAX_LEN + sizeof(struct ethhdr));
	if(prof == ROHC_V1_PROFILE_UNCOMP){
		retval = rohc_feedback_1_data_sn(feedback,sn);
	}else{
		if(context->need_mode_trans || sn_bit_width > 8)
			retval = rohc_feedback_2_data_sn(feedback,prof,ROHC_FEEDBACK_ACK,context->mode,sn,sn_bit_width);
		else
			retval = rohc_feedback_1_data_sn(feedback,sn);

	}
	retval = rohc_feedback_add_header(feedback,prof,context->cid,rohc_decomp->cid_type,add_crc_opt);
	if(rohc_decomp->decomp_eth_hdr){
		/**
		 *reserve the eth header room
		 */
		skb_push(feedback,sizeof(struct ethhdr));
	}


out:
	return retval;
	
}
int rohc_decomp_feedback_nack(struct rohc_decompresser *rohc_decomp,struct rohc_decomp_context *context,struct rohc_decomp_pkt_hdr_info *pkt_info,struct sk_buff *feedback)
{
	int retval;
	bool add_crc_opt;
	bool is_nack;
	u32 sn;
	int sn_bit_width;
	int ack_type;
	enum rohc_packet_type packet_type;
	enum rohc_profile prof;
	struct rohc_decomp_period_update *update_param;
	struct downward_kn *dkn;
	struct rohc_decomp_profile *decomp_profile;
	decomp_profile = context->decomp_profile;
	prof = decomp_profile->profile;
	update_param = &context->period_update;
	if(context->mode = ROHC_MODE_U){
		retval = -EACCES;
		goto out;
	}
	/*RF3095 5.10.4
	 * The only kind of feedback in profile 0x000 is ACKs,
	 * ACKs use feeback-1 format.
	 * when decompression recieved any type packets in any state,
	 * even the packet is not ok ,it is discarded without further
	 * action
	 */

	if(prof == ROHC_V1_PROFILE_UNCOMP){
		retval = -EACCES;
		goto out;
	}
	switch(context->context_state){
		case DECOMP_STATE_FULL_CONTEXT:
			/* if decompresser is at full context state,any packet fails to  decompress(crc error),
			 * it should send nack(O)
			 */
			dkn = &update_param->nack_kn_fc;
			ack_type = ROHC_FEEDBACK_NACK;

			break;
		case DECOMP_STATE_STATIC_CONTEXT:

			/*If decompresser is at static context state,when a type 0 or 1 packet is recevied,
			 * treat it as decompress failed(mismatch crc),and should send nack(O).
			 * I guess this is suitable for the 
			 *  compressor and the decompressor is out of sync,  caused by round trip time
			 * the decompressor is falling to the [SC] state, and the compressor is still
			 * in the [SO] state because it has not received the nack, so the NACK needs 
			 * to be sent at this time. Instead of static nack
			 *
			 * If decompresser decompress a type 2 ,ir_dyn or ir packet failed(crc error or other),
			 * it should send a static-nack.
			 */
			 
			if(!rohc_packet_is_covered_by_crc7_or_crc8(packet_type) || rohc_packet_is_type_0(packet_type) || rohc_packet_is_type_1(packet_type)){
				dkn = &update_param->nack_kn_sc;
				is_nack = true;
				ack_type = ROHC_FEEDBACK_NACK;
			}else{
				dkn = &update_param->static_nack_kn_sc;
				is_nack = false;
				ack_type = ROHC_FEEDBACK_STATIC_NACK;
			}
			break;
		case DECOMP_STATE_NO_CONTEXT:
			/*If decompressor is at no context state,when a type 0 or 1 or 2 or ir-dyn packet is 
			 * received,treat it as decompress failed(mismatch crc),or decompress IR packet failed.
			 * it should send a static-nack.
			 */
			dkn = &update_param->static_nack_kn_nc;
			ack_type = ROHC_FEEDBACK_STATIC_NACK;
			break;
	}

	//rohc_decomp_nack_kn_update(context ,dkn);
	rohc_decomp_downward_kn_set(dkn,dkn->sn);

	if(!rohc_decomp_downward_is_k_out_n(dkn) && !context->need_establish_feedback_channel){
		retval = -EACCES;
		goto out;
	}

	/*if crc check of k_1 out of the last n_1 decompressed packets have failed,
	 *context damage should be assumed and a nack or static-nack should sent.
	 */
	if(context->need_mode_trans)
		add_crc_opt = true;
	else
		add_crc_opt = false;
	sn = decomp_profile->pro_ops->last_decompressed_sn(context);
	sn_bit_width = decomp_profile->pro_ops->sn_bit_width(context);
	skb_reserve(feedback,ROHC_FEEDBACK_HEADER_MAX_LEN);
	if((sn_bit_width < 8) && !context->need_mode_trans){
		rohc_feedback_1_data_sn(feedback,sn);
	}else{
		retval =rohc_feedback_2_data_sn(feedback,prof,ack_type,context->mode,sn,sn_bit_width);
	}
	if(retval)
		goto out;
	
	retval = rohc_feedback_add_header(feedback,prof,context->cid,rohc_decomp->cid_type,add_crc_opt);
	if(retval)
		goto out;
	/*if decompression is in static context,and send 
	 * a nack,i guess should keep the state int static context state.
	 *
	 */
	if(dkn != &update_param->nack_kn_sc)
		rohc_decomp_downward_context_state(context);
	retval = 0;
out:
	return retval;

}
/*RF3095 5.3.2.2.1
 * In full Context state,decompression may be attempted regardless of 
 * what kind of packet is received.However ,for the ohter states decompression
 * is not always allowed.In the No Context state only IR packets,whitch carry the 
 * static information fileds,may be decompressed.Further,when in the Static Context
 * state,only packets carrying a 7- or 8-bit crc can be decompressed(i.e.,IR,IR_DYN,or 
 * URO-2 packets). 
 */
static bool rohc_decomp_decompression_is_allowed(struct rohc_decomp_context *context,enum rohc_packet_type packet_type)
{
	bool retval;
	switch(context->context_state){
		case DECOMP_STATE_NO_CONTEXT:
			/*In the NC state ,only packets carrying sufficient information on
			 * the static fileds can be decompressed.
			 */
			if(packet_type == ROHC_PACKET_TYPE_IR || packet_type == ROHC_PACKET_TYPE_IR_CR)
				retval = true;
			else
				retval = false;
			break;
		case DECOMP_STATE_STATIC_CONTEXT:
			if(rohc_packet_is_covered_by_crc7_or_crc8(packet_type))
				retval = true;
			else
				retval = false;
			break;
		case DECOMP_STATE_FULL_CONTEXT:
			retval = true;
			break;
	}
	return retval;
}
extern struct rohc_decompresser *decompresser;
int rohc_decomp_decompress(struct rohc_decompresser *rohc_decomp,struct sk_buff *skb,struct sk_buff *rcv_feedback,struct sk_buff *feedback,gfp_t flags)
{

	int retval;
	u16 cid_value;
	enum rohc_profile prof;
	enum rohc_packet_type packet_type;

	struct rohc_decomp_pkt_hdr_info *pkt_info;
	struct rohc_decomp_profile *decomp_profile;
	struct rohc_decomp_context *context;
	struct ethhdr *ethh;
	pkt_info = &rohc_decomp->pkt_info;
	memset(pkt_info,0,sizeof(struct rohc_decomp_pkt_hdr_info));
	/*ethernet header is add the beginning of the entire compressed packet.
	 *
	 */
	if(rohc_decomp->decomp_eth_hdr)
		pkt_info->decomped_hdr_len += sizeof(struct ethhdr);

	rohc_decomp_decode_padding(skb,pkt_info);
	rohc_decomp_decode_feedback(rohc_decomp,skb,rcv_feedback);

	retval = rohc_decomp_decode_cid(rohc_decomp,skb,&cid_value);
	if(retval == -ENOSPC){ //the packet is a pure feedback
		/*
		 *no data payload   to deliver to uplayor
		 */
		skb->len = 0;
		retval = 0;
		goto out;
	}
	//if(rohc_decomp == decompresser)
	//	return 0;

	packet_type = rohc_decomp_decode_packet_type(rohc_decomp,skb,pkt_info->cid_len);
	context = rohc_decomp_context_find(rohc_decomp,cid_value);
	printk(KERN_DEBUG "%s : cid_type : %d ,cid_value=%d,packet_type=%d\n",__func__,rohc_decomp->cid_type,cid_value,packet_type);
	if(packet_type == ROHC_PACKET_TYPE_IR || packet_type == ROHC_PACKET_TYPE_IR_DYN || packet_type == ROHC_PACKET_TYPE_IR_CR)
		prof = rohc_decomp_decode_profile(rohc_decomp,skb);
	else if(!context){
		rohc_pr(ROHC_DV2,"%s[%d],packet_type=%d\n",__func__,__LINE__,packet_type);
		retval = -EFAULT;
		goto out;
	}
	if(context)
		decomp_profile = context->decomp_profile;
	

	if(packet_type == ROHC_PACKET_TYPE_IR || packet_type == ROHC_PACKET_TYPE_IR_CR){
		/**
		 *only  ir or ir-cr can create or change context.
		 *
		 */
		if(context && prof != decomp_profile->profile){
		
			/**
			 *compresser has uesd this cid for new context,so free the old context firstly.
			 */
			rohc_decomp_context_destroy(rohc_decomp,context);
			context = NULL;
		}	
	}else if(!context){

		printk(KERN_DEBUG "can't find the decompresser context when cid = %d\n",cid_value);
		retval = -EFAULT;
		goto out;
	}
	if(!context){
		context = rohc_decomp_context_alloc(rohc_decomp,skb,cid_value,prof,flags);
		if(IS_ERR_OR_NULL(context)){
			retval = -ENOMEM;
			goto out;
		}
		decomp_profile = context->decomp_profile;
	}
	pkt_info->packet_type = packet_type;
	if(packet_type == ROHC_PACKET_TYPE_UNDECIDE){
		if(decomp_profile->pro_ops->adjust_packet_type)
			packet_type = decomp_profile->pro_ops->adjust_packet_type(context,skb,pkt_info);
	}
	//if(context->decomp_profile->profile == ROHC_V1_PROFILE_TCP)
	printk(KERN_DEBUG "%s :context-%d cid_value=%d,decode_packet_type=%d\n",rohc_profile_to_protocol(context->decomp_profile->profile),context->cid,cid_value,packet_type);
	pkt_info->packet_type = packet_type;
	pkt_info->prof = decomp_profile->profile;
	if(context->mode != context->set_mode){
		context->mode = context->set_mode;
		context->need_mode_trans = true;
		context->need_establish_feedback_channel = true;
	}else{
		context->need_mode_trans = false;
		context->need_establish_feedback_channel = false;
	}
	/**
	 *update the nack downward_kn when received any packets.
	 */
	rohc_decomp_nack_kn_update(context ,pkt_info);
	if(!rohc_decomp_decompression_is_allowed(context,packet_type)){
		rohc_decomp_feedback_nack(rohc_decomp,context,pkt_info,feedback);
		printk(KERN_DEBUG "prfile -%d context-%d[%d] receives a packet %d that is not allowed to decompress.\n",context->decomp_profile->profile,context->cid,context->context_state,packet_type);
		retval = -EFAULT;
		goto out;
	
	}
	retval = decomp_profile->pro_ops->decompress(context,skb,pkt_info);
	if(retval){
		//crc is error ,or decompress failed
		printk(KERN_DEBUG "prfile-%d decompress packet failed\n",decomp_profile->profile);
		rohc_decomp_feedback_nack(rohc_decomp,context,pkt_info,feedback);
		retval = -EFAULT;
	}else{
		/**
		 *decompress sucessfully
		 *so we may send ack to compresser.
		 */
		rohc_decomp_feedback_ack(rohc_decomp,context,pkt_info,feedback);
		if(context->context_state != DECOMP_STATE_FULL_CONTEXT)
			context->context_state = DECOMP_STATE_FULL_CONTEXT;
		/*remove the rohc compressed header from skb
		 */
		pskb_pull(skb,pkt_info->decomped_hdr_len);
		/* If skb has not enough free space at head, get new one
		 * for future expansions. 
		 */
		if(skb_headroom(skb) < pkt_info->rebuild_hdr_len)
			pskb_expand_head(skb,(pkt_info->rebuild_hdr_len - skb_headroom(skb)),0,flags);

		/*reserve enough  free space for recover net header.
		 *and copy the rebuild net header form decomp skb to skb.
		*/
		skb_push(skb,pkt_info->rebuild_hdr_len);
		if(decomp_profile->pro_ops->recover_net_packet_header)
			decomp_profile->pro_ops->recover_net_packet_header(context,skb,pkt_info);
		else
			skb_copy_bits(context->decomp_skb,0,skb->data,pkt_info->rebuild_hdr_len);
		if(decomp_profile->pro_ops->update_context)
			decomp_profile->pro_ops->update_context(context,pkt_info);
		if(skb_headroom(skb) & 0x1){
			skb_put(skb,1);
			memmove(skb->data + 1,skb->data,skb->len);
			skb_pull(skb,1);
		}
		/*reset the decomp skb
		 */
		skb_reset_tail_pointer(context->decomp_skb);
		context->decomp_skb->len = 0;
		retval = 0;
	}
	/*
	 *debug info
	 */
	ethh = (struct ethhdr *)skb->data;
	u8 *src = ethh->h_source;
	u8 *dst = ethh->h_dest;
	int i;
	for(i = 0 ; i < 6; i++,src++,dst++){
	//	printk(KERN_DEBUG "DECOMP : src-%d:%x,dest-%d:%x\n",i,*src,i,*dst);
	}
	//printk(KERN_DEBUG "eth_pro=%x\n",ntohs(ethh->h_proto));
out:
	return retval;
}
struct rohc_decompresser *rohc_decomp_alloc(enum rohc_cid_type cid_type,u32 max_cid,void (*setup)(struct rohc_decompresser *decomp),char *name)
{
	struct rohc_decompresser *decomp;
	BUG_ON(strlen(name) > ROHC_NAME_LEN);
	if(cid_type == CID_TYPE_LARGE){
		if(max_cid > MAX_LARGE_CIDS)
			max_cid = MAX_LARGE_CIDS;
	}else{
		if(max_cid > MAX_SMALL_CIDS)
			max_cid = MAX_SMALL_CIDS;
	}
	decomp = kzalloc(sizeof(struct rohc_decompresser),GFP_KERNEL);
	if(!decomp){
		pr_err("alloc decompresser failed\n");
		goto err0;
	}
	strcpy(decomp->name , name);
	decomp->cid_type = cid_type;
	decomp->max_cid = max_cid;
	rohc_rb_root_init(&decomp->decomp_rb);
	if(setup)
		setup(decomp);
	return decomp;
err1:
	kfree(decomp);
err0:
	decomp = ERR_PTR(-ENOMEM);
	return decomp;
}



extern struct rohc_decomp_profile uncomp_profile;
extern struct rohc_decomp_profile profile_decomp_udp;
extern struct rohc_decomp_profile decomp_profile_tcp;
extern struct rohc_decomp_profile decomp_profile_udp_v2;
extern struct rohc_decomp_profile decomp_profile_rtp_v2;
extern struct rohc_decomp_profile decomp_profile_ip_v2;
static int __init rohc_decomp_init(void)
{
	int i;
	for(i = 0 ; i < ROHC_PROFILE_MAX ;i++)
		INIT_LIST_HEAD(&decomp_profile_list[i]);
	INIT_LIST_HEAD(&uncomp_profile.list);
	rohc_decomp_register_profile(&uncomp_profile);
	//rohc_decomp_register_profile(&profile_decomp_udp);
	rohc_decomp_register_profile(&decomp_profile_tcp);
	rohc_decomp_register_profile(&decomp_profile_udp_v2);
	rohc_decomp_register_profile(&decomp_profile_rtp_v2);
	rohc_decomp_register_profile(&decomp_profile_ip_v2);
	return 0;
}
module_init(rohc_decomp_init);
