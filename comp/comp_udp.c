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
#include <linux/skbuff.h>
#include <linux/err.h>
#include <linux/slab.h>

#include "../rohc_packet.h"
#include "../rohc_packet_field.h"
#include "../rohc_cid.h"
#include "../rohc_common.h"
#include "../rohc_profile.h"
#include "../rohc_feedback.h"
#include "../rohc_packet_field_bh.h"

#include "rohc_comp_profile_v1.h"
#include "rohc_comp.h"
#include "rohc_comp_v1_packet.h"
#include "dynamic_field_bh.h"
#include "rohc_comp_wlsb.h"
#include "rohc_comp_packet.h"
#include "comp_udp.h"
struct rohc_comp_context *s_ctxt = NULL;
void comp_udp_output_info(struct comp_win_lsb *wlsb,char *func,int line)
{
	struct comp_profile_v1_context *v1_context;
	//v1_context = context->prof_context;
	pr_err("%s :line =%d : wlen = %d,win_size = %d,vaddr = %p,ksize=%d\n",func,line,wlsb->w_len,wlsb->win_size,wlsb,ksize(wlsb));
}
void comp_udp_print_wlsb(struct comp_profile_v1_context *v1_context,char *func,int line)
{

	comp_udp_output_info(v1_context->msn_wlsb,func,line);
	comp_udp_output_info(v1_context->ip_context.ip_id_wlsb[0],func,line);
	comp_udp_output_info(v1_context->ip_context.ip_id_wlsb[1],func,line);

}
void comp_udp_ex_print_info(struct rohc_comp_context *context,char *fun,int line)
{
	return;
//	if(!s_ctxt && context){
		comp_udp_print_wlsb(context->prof_context,fun,line);
		s_ctxt = context;
//	}else if(s_ctxt)
	//	comp_udp_print_wlsb(s_ctxt->prof_context,fun,line);
}
static int comp_udp_feedback_rcv(struct rohc_comp_context *context,int ack_type,u32 msn,u32 msn_bit_width,bool sn_valid)
{
	struct comp_profile_v1_context *v1_context;
	struct comp_udp_context *udp_context;
	struct ip_context *ip_context;
	struct iph_save_info *last_iph_info;
	struct iph_oa_send_info *oa_send_info;
	int i;
	int retval = 0;
	v1_context = context->prof_context;
	ip_context = &v1_context->ip_context;
	udp_context = v1_context->prof_context;
	last_iph_info = &ip_context->last_context_info.iph_info;
	switch(ack_type){
		case ROHC_FEEDBACK_ACK:
			udp_context->oa_send_pkts.check_send_pkts = v1_context->oa_upward_pkts;
			for(i = 0 ; i < last_iph_info->iph_num ; i++){
				oa_send_info = &ip_context->oa_send_pkts[i];
				update_iph_oa_send_info_ack(oa_send_info,v1_context->oa_upward_pkts);
			}
			break;
		case ROHC_FEEDBACK_NACK:
		case ROHC_FEEDBACK_STATIC_NACK:
			udp_context->oa_send_pkts.check_send_pkts = 0;
			for(i = 0 ; i < last_iph_info->iph_num ; i++){
				oa_send_info = &ip_context->oa_send_pkts[i];
				update_iph_oa_send_info_nack(oa_send_info);
			}
			break;
		default:
			pr_err("profile udp context-%d rcv unsupport ack type:%d\n",context->cid,ack_type);
	}
	return retval;
}
static int comp_udp_bulid_extension(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct comp_profile_v1_context *v1_context;
	enum rohc_ext_type ext_type;
	enum rohc_packet_type packet_type;
	int retval = 0;
	v1_context = context->prof_context;
	packet_type = v1_context->packet_info.packet_type;
	ext_type = v1_context->packet_info.ext_type;
	BUG_ON(packet_type != ROHC_PACKET_TYPE_URO_2);
	if(ext_type == EXT_TYPE_NONE)
		goto out;
	rohc_pr(ROHC_DEBUG,"%s: ext_type=%d\n",__func__,ext_type);
	switch(ext_type){
		case EXT_TYPE_0:
			retval = rohc_comp_build_ext0(context,pkt_info);
			if(retval)
				pr_err("profile-udp build ext0 failed\n");
			break;
		case EXT_TYPE_1:
			retval = rohc_comp_build_ext1(context,pkt_info);
			if(retval)
				pr_err("profile-udp build ext1 failed\n");
			break;
		case EXT_TYPE_2:
			retval = rohc_comp_build_ext2(context,pkt_info);
			if(retval)
				pr_err("profile-udp build ext2 failed\n");
			break;
		case EXT_TYPE_3:
			retval = rohc_comp_build_ext3(context,pkt_info);
			if(retval)
				pr_err("profile-udp build ext3 failed\n");
			break;
		default:
			pr_err("prfile-udp error extension type:%d\n",ext_type);
			break;
	}
out:
	return retval;
}
int comp_udp_update_probe(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct udphdr *new_udph,*old_udph;
	struct comp_profile_v1_context *v1_context;
	struct comp_udp_context *udp_context;
	struct udph_update *update_by_packet;
	u16 msn;
	v1_context = context->prof_context;
	udp_context = v1_context->prof_context;
	update_by_packet = &udp_context->update_by_packet;
	memset(update_by_packet,0,sizeof(struct udph_update));
	new_udph = &pkt_info->udph;
	old_udph = &udp_context->last_context_info.udph;
	update_by_packet->checksum = new_udph->check;
	msn = context->co_fields.msn;
	/*If the UDP checksum is zero,the sender has 
	 * not caculated the checksum
	 */
	if(new_udph->check != 0)
		update_by_packet->check_behavior = UDP_HAS_CHECKSUM;
	else
		update_by_packet->check_behavior = UDP_NO_CHECKSUM;

	if(update_by_packet->check_behavior != udp_context->last_context_info.check_behavior){
		update_by_packet->check_update = true;
		udp_context->oa_send_pkts.check_send_pkts = 0;
	}else if(udp_context->oa_send_pkts.check_send_pkts < v1_context->oa_upward_pkts)
		update_by_packet->check_update = true;
	else
		update_by_packet->check_update = false;
	/*detect the msn can decode bits
	 */
	msn_udp_bits_probe(v1_context->msn_wlsb,&v1_context->msn_k_bits,msn);
	rohc_pr(ROHC_DEBUG,"4=%d,8=%d,5=%d,13=%d,check_bh=%d\n",v1_context->msn_k_bits.can_encode_by_4_bit,v1_context->msn_k_bits.can_encode_by_8_bit,v1_context->msn_k_bits.can_encode_by_5_bit,v1_context->msn_k_bits.can_encode_by_13_bit,update_by_packet->check_behavior);
	/*probe the ip header changes
	 */
	rohc_comp_iph_update_probe(context,pkt_info);
	return 0;
}


static inline enum rohc_packet_type comp_udp_adjust_packet_type_so(struct comp_profile_v1_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct iphdr *outer_iph,*inner_iph;
	struct iph_behavior_info *outer_iph_bh,*inner_iph_bh;
	struct iph_update_info *outer_iph_update,*inner_iph_update;
	struct comp_udp_context *udp_context;
	struct  msn_encode_bits *msn_k_bits;

	enum rohc_packet_type packet_type;
	outer_iph_update = &context->ip_context.update_by_packet.iph_updates[ROHC_OUTER_IPH];
	inner_iph_update = &context->ip_context.update_by_packet.iph_updates[ROHC_INNER_IPH];
	outer_iph_bh = &context->ip_context.update_by_packet.iph_behavior[ROHC_OUTER_IPH];
	outer_iph = &pkt_info->iph;
	udp_context = context->prof_context;
	msn_k_bits = &context->msn_k_bits;
	if(udp_context->update_by_packet.check_update)
		packet_type = ROHC_PACKET_TYPE_IR_DYN;
	else if(outer_iph_update->constant_update)
		packet_type = ROHC_PACKET_TYPE_IR_DYN;
	else if(pkt_info->has_inner_iph && inner_iph_update->constant_update)
		packet_type = ROHC_PACKET_TYPE_IR_DYN;
	else if(!msn_k_bits->can_encode_by_4_bit && !msn_k_bits->can_encode_by_5_bit && !msn_k_bits->can_encode_by_8_bit && !msn_k_bits->can_encode_by_13_bit)
		packet_type = ROHC_PACKET_TYPE_IR_DYN;
	else{
		if(iph_dynamic_fields_update(outer_iph_update) || iph_dynamic_fields_update(inner_iph_update))
			packet_type = ROHC_PACKET_TYPE_URO_2;
		else{
			if(pkt_info->has_inner_iph){
				inner_iph_bh = &context->ip_context.update_by_packet.iph_behavior[ROHC_INNER_IPH];
				inner_iph = &pkt_info->inner_iph;
				if(!ip_id_offset_need_trans(inner_iph->version,inner_iph_bh,inner_iph_update) && !ip_id_offset_need_trans(outer_iph->version,outer_iph_bh,outer_iph_update) && msn_k_bits->can_encode_by_4_bit)
					packet_type = ROHC_PACKET_TYPE_UO_0;
				else if(rohc_comp_only_need_trans_one_ip_id_by_uo1(context,pkt_info) && msn_k_bits->can_encode_by_5_bit)
					packet_type = ROHC_PACKET_TYPE_UO_1;
				else
					packet_type = ROHC_PACKET_TYPE_URO_2;
			}else {
				if(!ip_id_offset_need_trans(outer_iph->version,outer_iph_bh,outer_iph_update) && msn_k_bits->can_encode_by_4_bit)
					packet_type = ROHC_PACKET_TYPE_UO_0;
				else if(rohc_comp_only_need_trans_one_ip_id_by_uo1(context,pkt_info) && msn_k_bits->can_encode_by_5_bit)
					packet_type = ROHC_PACKET_TYPE_UO_1;
				else
					packet_type = ROHC_PACKET_TYPE_URO_2;
	
			}
		}

	}
	rohc_pr(ROHC_DEBUG,"%s : packet_type = %d\n",__func__,packet_type);
	return packet_type;

}
static int comp_udp_adjust_extension(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct comp_profile_v1_context *v1_context;	
	struct  packet_type_info *type_info;
	int retval = 0;
	v1_context = context->prof_context;
	type_info = &v1_context->packet_info;
	rohc_pr(ROHC_DEBUG ,"%s : strat to adjust ext type,packet = %d\n",__func__,type_info->packet_type);
	if(type_info->packet_type == ROHC_PACKET_TYPE_URO_2)
		retval = rohc_comp_uro_2_adjust_extension(v1_context,pkt_info);
	else
		type_info->ext_type = EXT_TYPE_NONE;
	return retval;
}
static enum rohc_packet_type comp_udp_adjust_packet_type(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct comp_profile_v1_context *v1_context;
	struct comp_udp_context *udp_context;
	enum rohc_packet_type  packet_type;

	v1_context = context->prof_context;
	udp_context = v1_context->prof_context;

	/**
	 *probe update
	 */
	comp_udp_update_probe(context,pkt_info);
	switch(context->context_state){
		case COMP_STATE_IR:
			packet_type = ROHC_PACKET_TYPE_IR;
			break;
		case COMP_STATE_FO:
			packet_type = ROHC_PACKET_TYPE_IR_DYN;
			break;
		case COMP_STATE_SO:
			packet_type = comp_udp_adjust_packet_type_so(v1_context,pkt_info);
			break;
		default:
			packet_type = ROHC_PACKET_TYPE_UNDECIDE;
			break;
	}
	v1_context->packet_info.packet_type = packet_type;
	pkt_info->packet_type = packet_type;
	if(packet_type == ROHC_PACKET_TYPE_URO_2)
		rohc_comp_adjust_extension(context,pkt_info);
	else
		v1_context->packet_info.ext_type = EXT_TYPE_NONE;
	rohc_pr(ROHC_DEBUG,"%s :context-%d  packet_type=%d,ext_type = %d\n",__func__,context->cid,v1_context->packet_info.packet_type,v1_context->packet_info.ext_type);
	return packet_type;
}

static u32 comp_udp_new_msn(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u32 msn = context->co_fields.msn;
	msn = (u16)(msn + 1);
	return msn;
}
static int comp_udp_build_profile_header(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	u8 *comp_hdr;
	struct sk_buff *comp_skb;
	struct udphdr *udph;
	struct comp_profile_v1_context *v1_context;
	struct comp_udp_context *udp_context;
	v1_context = context->prof_context;
	udp_context = v1_context->prof_context;
	comp_skb = context->comp_skb;
	comp_hdr = skb_tail_pointer(comp_skb);
	udph = &pkt_info->udph;
	/*add udp checksum in the compressed header tail
	 * if the udp header checksum is not zero.
	 */
	if(udp_context->update_by_packet.check_behavior != UDP_NO_CHECKSUM){
		memcpy(comp_hdr,&udph->check,sizeof(u16));
		skb_put(comp_skb,sizeof(u16));
		pkt_info->comp_hdr_len += sizeof(u16);
	}
	return 0;
}

static int comp_udp_build_static_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	int retval = 0;
	/*The static chain consists of one item for each header of the chain
	*of protocol headers to be compressed, starting from the outermost
	*IP header and ending with a UDP header
	*/
	retval = rohc_comp_build_ip_static_chain(context,skb,pkt_info);
	if(retval){
		pr_err("profile-udp build ip static chain failed\n");
		goto out;
	}
	retval = rohc_comp_build_udp_static_chain(context,skb,pkt_info);
	if(retval)
		pr_err("profile-udp build udp static chain failed");
out:
	return retval;
}

static int comp_udp_build_dynamic_chain(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	int retval = 0;
	struct comp_profile_v1_context *v1_context;
	struct comp_udp_context *udp_context;
	v1_context = context->prof_context;
	udp_context = v1_context->prof_context;
	/*
	*The dynamic chain consists of one item for each header of the
	*chain of protocol headers to be compressed, starting from the
	*outermost IP header and ending with a UDP header
	*/

	retval = rohc_comp_build_ip_dynamic_chain(context,skb,pkt_info);
	if(retval){
		pr_err("profile-udp build ip dynamic chain failed\n");
		goto out;
	}
	retval = rohc_comp_build_udp_dynamic_chain(context,skb,pkt_info);
	if(retval)
		pr_err("profie-udp build udp dynamic chain failed");
	else
		udp_context->oa_send_pkts.check_send_pkts++;
out:
	return retval;
}


static int comp_udp_build_comp_header(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info,enum rohc_packet_type type)
{
	struct comp_profile_v1_context *v1_context;
	struct comp_udp_context *udp_context;
	enum rohc_packet_type packet_type;
	enum rohc_ext_type	ext_type;
	int retval = 0;
	v1_context = context->prof_context;
	packet_type = v1_context->packet_info.packet_type;
	ext_type = v1_context->packet_info.ext_type;
	switch(packet_type){
		case ROHC_PACKET_TYPE_IR:
			retval = rohc_comp_build_ir(context , skb ,pkt_info);
			if(retval)
				pr_err("profile-udp build ir packet failed\n");
			break;
		case ROHC_PACKET_TYPE_IR_DYN:
			retval = rohc_comp_build_ir_dyn(context,skb,pkt_info);
			if(retval)
				pr_err("profile-udp build ir dyn packet failed\n");
			break;
		case ROHC_PACKET_TYPE_UO_0:
			retval = rohc_comp_build_uo0(context,skb,pkt_info);
			if(retval)
				pr_err("profile-udp build uo_0 packet failed\n");
			break;
		case ROHC_PACKET_TYPE_UO_1:
			retval = rohc_comp_build_uo1(context,skb,pkt_info);
			if(retval)
				pr_err("profile-udp build uo_1 packet failed\n");
			break;
		case ROHC_PACKET_TYPE_URO_2:
			retval = rohc_comp_build_uor2(context,skb,pkt_info);
			if(retval)
				pr_err("profile-udp build uro_2 packet failed\n");
			break;
		default:
			pr_err("UDP don't  the packet_type:%d\n",packet_type);
			break;
	}
	return retval;
}


void net_header_dump(struct sk_buff *skb,int cid,u32 msn)
{
	struct iphdr *iph;
	struct udphdr *udph;
	u8 *addr;
	iph = ip_hdr(skb);
	rohc_pr(ROHC_DUMP,"cid : %d msn:%d\n",cid,msn);
	rohc_pr(ROHC_DUMP,"ipid=%d,id_off_msn=%u,tos=%d,ttl=%d,iphl=%d,tot_len=%d,fragof=%x,check=%x\n",ntohs(iph->id),ntohs(iph->id) - msn,iph->tos,iph->ttl,iph->ihl,iph->tot_len,iph->frag_off,iph->check);
	addr = (u8 *)&iph->saddr;
	rohc_pr(ROHC_DUMP,"ipsrc:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	addr = (u8 *)&iph->daddr;
	rohc_pr(ROHC_DUMP,"ipdst:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	udph = udp_hdr(skb);
	rohc_pr(ROHC_DUMP,"dport=%d,sport=%d,len=%d,udpcheck=%x\n",udph->source,udph->dest,udph->len,udph->check);

}
static int comp_udp_compress(struct rohc_comp_context *context,struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct comp_profile_v1_context *v1_context;
	struct comp_udp_context *udp_context;
	struct comp_profile_ops *prof_ops; 
	v1_context = context->prof_context;
	udp_context = v1_context->prof_context;
	prof_ops = context->comp_profile->pro_ops;
	enum rohc_packet_type packet_type;
	int retval = 0;
	/*update the MSN
	 */

	context->co_fields.msn = prof_ops->new_msn(context,pkt_info);
	/*decide the packet type to send
	 */

	//comp_udp_print_wlsb(v1_context,__func__,__LINE__);
	packet_type = prof_ops->adjust_packet_type(context,skb,pkt_info);
	/*build the compressed packet
	 */
	retval = prof_ops->build_comp_header(context,skb,pkt_info,packet_type);
	if(retval){
		pr_err("profile udp build compressed packet: %d  failed,context state:%d\n",packet_type,context->context_state);
		goto out;
	}
	if(prof_ops->update_context)
		prof_ops->update_context(context,pkt_info);
	rohc_pr(ROHC_DEBUG ,"context-%d,skb origlen=%d\n",context->cid,skb->len);
	if(context->cid == 2){
		rohc_pr(ROHC_DUMP,"packet_type=%d,ext_type = %d,orig_hlen=%d,comped_len=%d\n",pkt_info->packet_type,v1_context->packet_info.ext_type,pkt_info->to_comp_pkt_hdr_len - 14,pkt_info->comp_hdr_len - 14);
		net_header_dump(skb,context->cid,context->co_fields.msn);
	}
out:
	return retval;

}

static void comp_udp_update_context(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct udphdr *udph;
	struct comp_udp_context *udp_context;
	struct udp_context_info *last_udp_info;
	struct comp_profile_v1_context *v1_context;
	struct comp_win_lsb *wlsb;
	v1_context = context->prof_context;
	udp_context = v1_context->prof_context;
	udph = &pkt_info->udph;
	last_udp_info = &udp_context->last_context_info;
	last_udp_info->check_behavior = udp_context->update_by_packet.check_behavior;
	memcpy(&last_udp_info->udph,udph,sizeof(struct udphdr));
	comp_wlsb_add(v1_context->msn_wlsb,NULL,context->co_fields.msn,context->co_fields.msn);
	/*update iph
	 */
	iph_update_context(&v1_context->ip_context,pkt_info,context->co_fields.msn);
	//comp_udp_print_wlsb(v1_context,__func__,__LINE__);
}

struct comp_profile_v1_ops comp_udp_prof_v1_ops = {
	.adjust_extension = comp_udp_adjust_extension,
	.bulid_extension = comp_udp_bulid_extension,
	.feedback_input = comp_udp_feedback_rcv,
};
int comp_udp_init_context(struct rohc_comp_context *context,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct iphdr *iph;
	struct udphdr *udph;
	struct comp_profile_v1_context *v1_context;
	struct comp_udp_context *udp_context;
	u16 msn;
	int retval;
	unsigned long oa_limit;
	oa_limit = 3;//context->compresser->refresh_thresholds.oa_upward_pkts;

	v1_context = kzalloc(sizeof(struct comp_profile_v1_context),GFP_ATOMIC);
	if(!v1_context){
		pr_err("profile-udp context-%d alloc profile_v1_context failed\n",context->cid);
		retval = -ENOMEM;
		goto out;
	}

	udp_context = kzalloc(sizeof(struct comp_udp_context),GFP_ATOMIC);
	if(!udp_context){
		pr_err("profile-udp context-%d alloc udp context failed\n",context->cid);
		retval = -ENOMEM;
		goto err1;
	}
	context->prof_context = v1_context;
	retval = rohc_comp_profile_v1_init_context(v1_context,pkt_info,&comp_udp_prof_v1_ops,oa_limit);
	if(retval){
		pr_err("profile udp init v1 context failed\n");
		goto err2;
	}
	v1_context->prof_context = udp_context;
	if(pkt_info->has_inner_iph)
		iph = &pkt_info->inner_iph;
	else
		iph = &pkt_info->iph;
	/*init the msn 
	 *rf3095 5.11.1 
	 *At the compressor, UDP SN is initialized to a random
	 *value when the IR packet is sent
	 *But i think it is best to initialize to ipid.
	 */
	msn = ntohs(iph->id);
	context->co_fields.msn = msn;
	printk(KERN_DEBUG "%s : msn = %d\n",__func__,msn);
	return retval;
err2:
	kfree(udp_context);
err1:
	kfree(v1_context);
out:
	return retval;
}


struct comp_profile_ops comp_udp_prof_ops  = {
	.adjust_packet_type = comp_udp_adjust_packet_type,
	.new_msn = comp_udp_new_msn,
	.build_static_chain = comp_udp_build_static_chain,
	.build_dynamic_chain = comp_udp_build_dynamic_chain,
	.build_profile_header = comp_udp_build_profile_header,
	.build_comp_header = comp_udp_build_comp_header,
	.compress = comp_udp_compress,
	.update_context = comp_udp_update_context,
	.init_context = comp_udp_init_context,
	.feedback_input = rohc_comp_feedback_input,
};
struct rohc_comp_profile profile_comp_udp = {
	.profile = ROHC_V1_PROFILE_UDP,
	.pro_ops = &comp_udp_prof_ops,
};
