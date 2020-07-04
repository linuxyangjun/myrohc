
/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	date: 2019/10/9
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */


#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <net/ip.h>

#include "../rohc_rb.h"
#include "../rohc_profile.h"
#include "../rohc_common.h"
#include "../rohc_cid.h"
#include "../rohc_feedback.h"
#include "rohc_comp.h"
#include "rohc_comp_hash.h"
static	struct list_head comp_profile_list[ROHC_PROFILE_MAX];
static	DEFINE_SPINLOCK(comp_profile_lock);
#define	DOWNWARD_PERIOD_MS		(1000 * 5)
static void context_downward_timer(unsigned long data)
{
	struct rohc_comp_context *context;
	unsigned long next_time,new_time;
	context = (struct rohc_comp_context *)data;
	next_time = jiffies + msecs_to_jiffies(DOWNWARD_PERIOD_MS);
	new_time = context->update_jiffies + msecs_to_jiffies(DOWNWARD_PERIOD_MS);
	//if(time_before_eq(new_time,jiffies))
		context->context_state = COMP_STATE_IR;
	mod_timer(&context->downward_timer,next_time);

}
int rohc_comp_register_profile(struct rohc_comp_profile *profile)
{
	int retval;
	enum rohc_profile prof;
	int hash;
	struct list_head *head;
	struct rohc_comp_profile *prof_find;
	prof = profile->profile;
	hash = ROHC_PROFILE_HASH(prof);
	head = &comp_profile_list[hash];
	spin_lock(&comp_profile_lock);
	list_for_each_entry(prof_find,head,list){
		if(prof_find->profile == prof){
			pr_err("%s : profile-%x is exsit\n",__func__,prof);
			retval = -EEXIST;
			goto out;
		}	
	}
	list_add_rcu(&profile->list,head);
	spin_unlock(&comp_profile_lock);
	retval = 0;
out:
	return retval;
}

static struct rohc_comp_profile *rohc_comp_find_profile(enum rohc_profile prof)
{
	int hash;
	bool found = false;
	struct list_head *head;
	struct rohc_comp_profile *comp_prof;
	hash = ROHC_PROFILE_HASH(prof);
	printk(KERN_DEBUG "prof = %x,hash=%d\n",prof,hash);
	rohc_pr(ROHC_DEBUG,"2prof=%d\n",prof);
	pr_debug("3prof=%d\n",prof);
	head = &comp_profile_list[hash];
	rcu_read_lock();
	list_for_each_entry_rcu(comp_prof,head,list){
		if(comp_prof->profile == prof){
			found = true;
			break;
		}
	}
	rcu_read_unlock();
	if(!found)
		comp_prof = NULL;
	return comp_prof;
}

int rohc_comp_cid_alloc(struct rohc_compresser *rohc_comp,u16 *cid)
{
	int ret = 0;
	u16 new_cid;
	new_cid = find_first_zero_bit(rohc_comp->context_bitmap,rohc_comp->max_cid + 1);
	if(new_cid > rohc_comp->max_cid){
		pr_err("%s : alloc new cid failed ,err cid : %d\n",__func__,new_cid);
		ret = -ENOSPC;
	}else
		set_bit(new_cid,rohc_comp->context_bitmap);
	*cid = new_cid;
	return ret;
}



void rohc_comp_cid_free(struct rohc_compresser *rohc_comp,u16 cid)
{
	BUG_ON(cid > rohc_comp->max_cid);
	clear_bit(cid,rohc_comp->context_bitmap);
}



int rohc_comp_context_rb_insert(struct rohc_compresser *comp,struct rohc_comp_context *new_context)
{	
	return rohc_rb_insert(&comp->comp_rb,&new_context->context_rb);

}



void rohc_comp_context_change_mode(struct rohc_comp_context *context,int mode)
{

}

void rohc_comp_context_change_state(struct rohc_comp_context *context,int state)
{
	struct rohc_comp_period_update *update = &context->period_update;
	if(context->context_state != state)
		update->oa_upward_sent = 0;
	context->context_state = state;

}
void rohc_comp_set_refresh_param(struct rohc_compresser *comp,struct rohc_comp_refresh_threshold *set)
{
	memcpy(&comp->refresh_thresholds,set,sizeof(struct rohc_comp_refresh_threshold));
}

void rohc_comp_context_optimistic_upstate(struct rohc_compresser *comp,struct rohc_comp_context *context)
{
	int new_state;
	struct rohc_comp_period_update *update = &context->period_update;
	update->oa_upward_sent++;
	switch(context->context_state){
		case COMP_STATE_SO:
			new_state = COMP_STATE_SO;
			break;
		case COMP_STATE_IR:
		case COMP_STATE_FO:
			if(update->oa_upward_sent < comp->refresh_thresholds.oa_upward_pkts)
				new_state = context->context_state;
			else
				new_state = COMP_STATE_SO;
			break;
	}

	rohc_comp_context_change_state(context,new_state);
}

void rohc_comp_context_optimistic_downstate(struct rohc_compresser *comp,struct rohc_comp_context *context)
{
	int new_state;
	struct rohc_comp_period_update *update = &context->period_update;
	switch(context->context_state){
		case COMP_STATE_SO:
			update->oa_downward_timeout_so_sent++;
			if(update->oa_downward_timeout_so_sent > comp->refresh_thresholds.oa_upward_pkts  + 5){
				new_state = COMP_STATE_FO;
				update->oa_downward_timeout_fo_sent = 0;
				update->oa_downward_timeout_so_sent = 0;
			}
			break;
		case COMP_STATE_FO:
			update->oa_downward_timeout_fo_sent++;
			if(update->oa_downward_timeout_so_sent > (comp->refresh_thresholds.oa_upward_pkts / 2)){
				new_state = COMP_STATE_IR;
				update->oa_downward_timeout_fo_sent = 0;
				update->oa_downward_timeout_so_sent = 0;
			}
			break;
	}
	rohc_comp_context_change_state(context,new_state);
}
struct rohc_comp_context *rohc_comp_context_rb_find(struct rohc_compresser *comp,u16 cid)
{
	struct rohc_comp_context *context;
	struct rohc_rb_node *rohc_node;
	rohc_node = rohc_rb_find(&comp->comp_rb,cid);
	if(!rohc_node)
		context = NULL;
	else
		context = container_of(rohc_node,struct rohc_comp_context,context_rb);
	return context;
}

void rohc_comp_context_rb_del(struct rohc_compresser *comp,struct rohc_comp_context *context)
{
	rohc_rb_del(&comp->comp_rb,&context->context_rb);
}

int rohc_comp_deliver_feedback(struct rohc_compresser *comp,struct sk_buff *feedback_skb)
{
	int retval;
	int cid_len;
	int cid;
	int code_size;
	int hdr_len;
	unsigned char *start;
	struct rohc_comp_context *context;
	struct rohc_comp_profile *profile;
	start = feedback_skb->data;

	while((feedback_skb->len > 0) && rohc_packet_is_feedback(start)){
		retval = rohc_feedback_parse_header(feedback_skb,comp->cid_type,&hdr_len,&code_size,&cid,&cid_len);
		if(retval){
			pr_err("%s : parse feeback head failed\n",__func__);
			goto out;
		}
		context = rohc_comp_context_rb_find(comp,cid);
		if(!context){
			pr_err("%s : can't find the context for cid = %d with recving feedback\n",__func__,cid);
			retval = -EFAULT;
			goto out;
		}
		profile = context->comp_profile;
		/**
		 *deliver feedback.
		 */
		retval = profile->pro_ops->feedback_input(context,feedback_skb,cid_len,code_size);
		if(retval)
			goto out;
		start = feedback_skb->data;
	}

out:
	return retval;
}
extern int rohc_comp_tcp_options_analyze(const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
extern bool rohc_comp_packet_is_rtp(const struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info);
enum rohc_profile rohc_comp_adjust_profile(struct rohc_compresser *rohc_comp, struct sk_buff *skb,struct rohc_comp_packet_hdr_info *pkt_info)
{
	enum rohc_profile prof;
	int proto;
	int frag_off;
	int old_to_comp_len;
	int off;
	struct iphdr *iph;
	struct ipv6hdr *ipv6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct ethhdr *eth;
	prof = ROHC_V1_PROFILE_UNCOMP;
	pkt_info->skb = skb;
	
	iph = ip_hdr(skb);
	/*
	 *rohc not support compress eth hdr.
	 */
	if(rohc_comp->comp_eth_hdr){
		eth = eth_hdr(skb);
		memcpy(&pkt_info->eth,eth,sizeof(struct ethhdr));
		pkt_info->to_comp_pkt_hdr_len += sizeof(struct ethhdr);
		/**
		 *rohc only support ip protocol and not support ip options
		 *
		 */
		if(eth->h_proto != htons(ETH_P_IP) || (iph->ihl << 2) >  20)
			goto out;
	}
	old_to_comp_len = pkt_info->to_comp_pkt_hdr_len;
	//iph = (struct iphdr *)(eth + 1);
	//debugging uncomp profile.

//	return ROHC_V1_PROFILE_UNCOMP;
retry:
	if(iph->version == 4 ){ //ipv4
		prof = ROHC_V2_PROFILE_IP;
		pkt_info->has_iph = true;
		pkt_info->iph_num++;
		if(pkt_info->iph_num > 1)
			memcpy(&pkt_info->inner_iph,iph,sizeof(*iph));
		else
			memcpy(&pkt_info->iph,iph,sizeof(*iph));
		/***
		 *
		 * rohc not support ip fragment
		*/
		frag_off = ntohs(iph->frag_off);
		if(frag_off & IP_MF){
			prof = ROHC_V1_PROFILE_UNCOMP;
			goto out;
		}
		if(ntohs(iph->tot_len) < 46){
			prof = ROHC_V1_PROFILE_UNCOMP;
			goto out;
		}

		pkt_info->to_comp_pkt_hdr_len += iph->ihl << 2; // words
		proto = iph->protocol;
		switch(proto){
			case IPPROTO_TCP:
				//goto debug;
				prof = ROHC_V1_PROFILE_TCP;
				tcph = (struct tcphdr *)(iph + 1);//tcp_hdr(skb);
				off = (unsigned long)tcph - (unsigned long)skb->data;
				skb_set_transport_header(skb,off);
				pkt_info->to_comp_pkt_hdr_len += sizeof(struct tcphdr);
				memcpy(&pkt_info->tcph,tcph,sizeof(*tcph));
				rohc_pr(ROHC_DCORE,"off=%d,iph tot_len=%d\n",off,ntohs(iph->tot_len));
				if(rohc_comp_tcp_options_analyze(skb,pkt_info))
					goto debug;
				break;
			case IPPROTO_UDP:
				//goto debug;
				prof = ROHC_V2_PROFILE_UDP;
				udph = (struct udphdr *)(iph + 1);
				off = (unsigned long)udph - (unsigned long)skb->data;
				skb_set_transport_header(skb,off);
				/*
				 *udp header length is 8 bytes
				 */
				pkt_info->to_comp_pkt_hdr_len += 8; 
				memcpy(&pkt_info->udph,udph,sizeof(*udph));
				/**
				 *CONTINUE ADJUST IS OR NOT RTP
				 */
				if(rohc_comp_packet_is_rtp(skb,pkt_info)){
					prof = ROHC_V2_PROFILE_RTP;
				}

				break;
			case IPPROTO_IPIP:
				pkt_info->has_inner_iph = true;
				if(pkt_info->iph_num > 1){
					pr_err("%s : too many ip header \n",__func__);
					prof = ROHC_V1_PROFILE_UNCOMP;
					goto out;
				}
				iph = inner_ip_hdr(skb);
				goto retry;
			case IPPROTO_IPV6: //IPv6-in-IPv4 tunnelling
				// TODO IPV6
				pkt_info->has_inner_iph = true;
				if(pkt_info->iph_num > 1){
					pr_err("%s : too many ip header\n",__func__);
					prof = ROHC_V1_PROFILE_UNCOMP;
					goto out;
				}
				ipv6h = inner_ipv6_hdr(skb);
				iph = (struct iphdr *)ipv6h;
				goto retry;
			default:
				//goto debug;
				break;
		}
	}else if(iph->version == 6){ //IPV6 Parse 
		pkt_info->iph_num++;
		if(pkt_info->iph_num > 1)
			memcpy(&pkt_info->inner_ipv6h,ipv6h,sizeof(struct ipv6hdr));
		else
			memcpy(&pkt_info->ipv6h,ipv6h,sizeof(struct ipv6hdr));
		pkt_info->has_iph = true;
		//
		//TODO 
		//
	
	}else{ //ohter 
	
	}

out:
	printk(KERN_DEBUG "detect profile = %d\n",prof); 
	//debug
	
	return prof;
debug:
	pkt_info->to_comp_pkt_hdr_len = old_to_comp_len;
	prof = ROHC_V1_PROFILE_UNCOMP;
	return prof;
}

struct rohc_comp_context *rohc_comp_context_find(struct rohc_compresser *comp,enum rohc_profile prof,struct rohc_comp_packet_hdr_info *pkt_info)
{
	struct rohc_comp_context *context;
	struct rohc_comp_context_hnode *new_hnode;
	struct iphdr *iph;
	struct ethhdr *eth;
	struct sk_buff *skb;
	new_hnode = NULL;
	if(prof == ROHC_V1_PROFILE_UNCOMP)
		context = comp->uncomp_context;
	else{
		skb = pkt_info->skb;
		eth = eth_hdr(skb);
		BUG_ON(eth->h_proto != htons(ETH_P_IP));
		if(pkt_info->has_inner_iph)
			iph = &pkt_info->inner_iph;
		else 
			iph = &pkt_info->iph;
		if(iph->version == 4){
			new_hnode = rohc_comp_context_hash_find(&comp->ipv4_hash,skb);
		}else{
			//
			//IPV6
			//
			new_hnode = rohc_comp_context_hash_find(&comp->ipv6_hash,skb);
		}
		if(new_hnode){
			context = container_of(new_hnode,struct rohc_comp_context,hash_node);
		}else
			context = NULL;
	}
	if(context){
		list_del_init(&context->list);
		list_add_tail(&context->list,&comp->context_list);
		if(context->comp_profile->profile != prof)
			pr_err("%s : new prof is %d,last prof is %d\n",__func__,prof,context->comp_profile->profile);
	}
	return context;
}
struct rohc_comp_context *rohc_comp_context_alloc(struct rohc_compresser *comp,struct rohc_comp_profile *profile,struct rohc_comp_packet_hdr_info *pkt_info,gfp_t flags)
{
	u16 new_cid;
	struct sk_buff *skb;
	struct iphdr *iph;

	struct rohc_comp_context_hnode *hnode;
	struct rohc_comp_context *new_context ;
	BUG_ON(!pkt_info->skb);
	skb = pkt_info->skb;
	if(profile->profile != ROHC_V1_PROFILE_UNCOMP){
		if(pkt_info->has_inner_iph)
			iph = &pkt_info->inner_iph;
		else
			iph = &pkt_info->iph;
		if(rohc_comp_cid_alloc(comp,&new_cid)){
			pr_err("can't alloc new context id from compresser %s\n ",comp->name);
			new_context = ERR_PTR(-ENOSPC);
			goto err0;
		}
	}else{
		new_context = comp->uncomp_context;
		if(new_context)
			goto out;
		new_cid = 11;
	}

	new_context = kzalloc(sizeof(struct rohc_comp_context),flags);
	if(!new_context){
		pr_err("%s : alloc comp context failed\n",__func__);
		new_context =  ERR_PTR(-ENOMEM);
		goto err1;
	}
	
	/**
	 *init context,
	 *
	 */
	new_context->comp_skb = alloc_skb(PAGE_SIZE,flags);
	if(!new_context->comp_skb){
		pr_err("can.t alloc compresser skb for new context:%d\n",new_cid);
		goto err1;
	}
	new_context->context_state = COMP_STATE_IR;
	new_context->mode = ROHC_MODE_U;
	new_context->cid = new_cid;
	new_context->comp_profile = profile;
	new_context->hdr_len_resv = comp->hdr_len_resv;
	new_context->comp_eth_hdr = comp->comp_eth_hdr;
	new_context->compresser = comp;
	hnode = &new_context->hash_node;
	//hnode->context = new_context;
	INIT_HLIST_NODE(&hnode->list);
	if(profile->pro_ops->init_context && profile->pro_ops->init_context(new_context,pkt_info))
		goto err2;

	if(profile->profile != ROHC_V1_PROFILE_UNCOMP){
		if(iph->version == 4){
			if(rohc_comp_context_hash_insert(&comp->ipv4_hash,&new_context->hash_node,skb))
				goto err2;

		}else{
			//
			//
			//ipv6
			//if(rohc_comp_context_hash_insert(&comp->ipv6_hash,new_context,skb))
			//	goto err2;
		}	
	}else
		comp->uncomp_context = new_context;
	new_context->context_rb.key = new_cid;
	printk(KERN_DEBUG "new_cid = %d\n",new_cid);
	rohc_comp_context_rb_insert(comp,new_context);
	INIT_LIST_HEAD(&new_context->list);
	list_add_tail(&new_context->list,&comp->context_list);
	if(profile->profile == ROHC_V2_PROFILE_RTP){
		setup_timer(&new_context->downward_timer,context_downward_timer,new_context);
		mod_timer(&new_context->downward_timer,jiffies + msecs_to_jiffies(DOWNWARD_PERIOD_MS));
	}
out:
	return new_context;
	
err2:
	dev_kfree_skb_any(new_context->comp_skb);
err1:
	if(!IS_ERR(new_context))
		kfree(new_context);
	rohc_comp_cid_free(comp,new_cid);
err0:
	return new_context;
}

int rohc_comp_compress(struct rohc_compresser *comp,struct sk_buff *skb,gfp_t flags)
{
	int retval;
	//bool	skb_nonlinear = false;
	u8 pro_high,pro_low;
	struct rohc_comp_profile *comp_profile;
	struct rohc_comp_context *context;
	enum rohc_profile prof;
	struct rohc_comp_packet_hdr_info pkt_info = {0};
	if(skb_is_nonlinear(skb)){
		pr_warn("compresser %s will compress a non linear skb packet\n",comp->name);
		//skb_nonlinear = true;
	}
	prof = rohc_comp_adjust_profile(comp,skb,&pkt_info);
	pro_high = (prof >> 8) & 0xff;
	pro_low = prof & 0xff;
	context = rohc_comp_context_find(comp,prof,&pkt_info);
	if(!context){
		comp_profile = rohc_comp_find_profile(prof);
		//BUG_ON(!comp_profile);
		if(!comp_profile){
			/*if can't find the packet corresponding profile,
			 * use default profile_uncomp
			 */
			prof = ROHC_V1_PROFILE_UNCOMP;
			comp_profile = rohc_comp_find_profile(prof);
			BUG_ON(!comp_profile);
		}
		context = rohc_comp_context_alloc(comp,comp_profile,&pkt_info,flags);
	}
	if(!context){
		retval =  -EFAULT;
		goto out;
	}
	//if(context->comp_profile->profile == ROHC_V1_PROFILE_TCP)
	context->comp_profile->pro_ops->compress(context,skb,&pkt_info);
	printk(KERN_DEBUG "profile-%d context-%d context_state = %d,packet = %d,has_inner_iph:%d\n",context->comp_profile->profile,context->cid,context->context_state,pkt_info.packet_type,pkt_info.has_inner_iph);

	/**
	 *pull the data pointer to payload start.
	 */
	if(!pskb_pull(skb,pkt_info.to_comp_pkt_hdr_len)){
		printk(KERN_DEBUG "profile-%d pull header failed,orignal length=%d\n",context->comp_profile->profile,skb->len);
		retval = -EFAULT;
		goto out;
	}else
		;//printk(KERN_DEBUG "profile-%d pull header ok,orignal length=%d,headroom=%d\n",context->comp_profile->profile,skb->len,skb_headroom(skb));
	printk(KERN_DEBUG "%s : cid_type:%d context-%d to_comp_pkt_hdr_len=%d,comp_hdr_len=%d,comp_skb length =%d\n",comp->name,comp->cid_type,context->cid,pkt_info.to_comp_pkt_hdr_len,pkt_info.comp_hdr_len,context->comp_skb->len);
	if(context->comp_profile->profile == ROHC_V1_PROFILE_TCP || context->comp_profile->profile == ROHC_V1_PROFILE_UDP ||\
		context->comp_profile->profile == ROHC_V2_PROFILE_UDP ||
		context->comp_profile->profile == ROHC_V2_PROFILE_RTP ||
		context->comp_profile->profile == ROHC_V2_PROFILE_IP){
		//printk(KERN_DEBUG "%s : context-%d to_comp_pkt_hdr_len=%d,comp_hdr_len=%d,comp_skb length =%d\n",comp->name,context->cid,pkt_info.to_comp_pkt_hdr_len,pkt_info.comp_hdr_len,context->comp_skb->len);
		printk(KERN_DEBUG "%s orignal header len:%d,co header len:%d,header compress rate :%%%d \n",rohc_profile_to_protocol(context->comp_profile->profile),pkt_info.to_comp_pkt_hdr_len - 14,pkt_info.comp_hdr_len - 14,(pkt_info.to_comp_pkt_hdr_len - pkt_info.comp_hdr_len) * 100 / (pkt_info.to_comp_pkt_hdr_len - 14));

	}
	/**
	 *reserved the room for comppress header.
	 */
	if(skb_headroom(skb) < ( pkt_info.comp_hdr_len + comp->hdr_len_resv))
		pskb_expand_head(skb,(pkt_info.comp_hdr_len + comp->hdr_len_resv - skb_headroom(skb)),0,flags);

	/**
	 *copy the compress header to skb from com_skb
	 */
	skb_push(skb,pkt_info.comp_hdr_len);
	if(skb_copy_bits(context->comp_skb,0,skb->data,pkt_info.comp_hdr_len)){
		printk(KERN_DEBUG "profile-%d copy data from comp skb to skb failed\n",context->comp_profile->profile);
		retval = -EFAULT;
		goto out;
	}

	rohc_comp_context_optimistic_upstate(comp,context);
	/*reset compress skb
	 */
	skb_reset_tail_pointer(context->comp_skb);
	context->comp_skb->len = 0;
	if(/*context->comp_profile->profile == ROHC_V2_PROFILE_RTP*/1)
		context->update_jiffies = jiffies;
#if 0
	/*
	 *copy uncompress skb payload to compress skb
	 *
	 */
	skb_copy_bits(skb,pkt_info.to_comp_pkt_hdr_len,skb_tail_pointer(context->comp_skb),skb->len - pkt_info.to_comp_pkt_hdr_len);
	skb_put(context->comp_skb,skb->len - pkt_info.to_comp_pkt_hdr_len);
	/**
	 *reset skb tail pointer and skb len.
	 */
	skb_reset_taile_pointer(skb);
	skb->len = 0;
	/**
	 *copy the compressed data to the orignal skb from comp skb
	 *
	 */
	
	skb_copy_bits(context->comp_skb,0,skb->data,context->comp_skb->len);
	skb_put(skb,context->comp_skb->len);
	skb_reset_taile_pointer(context->comp_skb);
	context->comp_skb->len = 0;
#endif
	retval = 0;
out:
	/*reset compress skb
	 */
	skb_reset_tail_pointer(context->comp_skb);
	context->comp_skb->len = 0;
	return retval;
}

struct rohc_compresser *rohc_comp_alloc(enum rohc_cid_type cid_type,u32 max_cids,void (*setup)(struct rohc_compresser *comp),char *name)
{
	struct rohc_compresser *new_comp;
	BUG_ON(strlen(name) > ROHC_NAME_LEN);
	
	if(cid_type == CID_TYPE_SMALL){
		if(max_cids > MAX_SMALL_CIDS)
			max_cids = MAX_SMALL_CIDS;
	}else{
		if(max_cids > MAX_LARGE_CIDS)
			max_cids = MAX_LARGE_CIDS;
	}
	new_comp = kzalloc(sizeof(struct rohc_compresser),GFP_KERNEL);
	if(!new_comp){
		pr_err("alloc new compresser failed\n");
		goto err0;
	}
	new_comp->cid_type = cid_type;
	new_comp->max_cid = max_cids;
	strcpy(new_comp->name,name);
	new_comp->context_bitmap = kcalloc(BITS_TO_LONGS(max_cids + 1),sizeof(unsigned long),GFP_KERNEL);
	if(!new_comp->context_bitmap){
		pr_err("alloc context bitmap failed\n");
		goto err1;
	}
	/**
	 *reserver cid 1 for uncompress profile
	 */
	set_bit(11,new_comp->context_bitmap);
	INIT_LIST_HEAD(&new_comp->context_list);
	spin_lock_init(&new_comp->ctxt_lock);
	rohc_rb_root_init(&new_comp->comp_rb);	
	rohc_comp_context_hash_init(new_comp);
/*
	new_comp->comp_skb = alloc_skb(PAGE_SIZE,GFP_KERNEL);
	if(!new_comp->comp_skb){
		pr_err("alloc compresser skb failed\n");
		goto err2;
	}
*/
	if(setup)
		setup(new_comp);
	return new_comp;
err2:
	kfree(new_comp->context_bitmap);
err1:
	kfree(new_comp);
err0:
	new_comp = ERR_PTR(-ENOMEM);
	return new_comp;
}


extern struct rohc_comp_profile profile_uncomp;
extern struct rohc_comp_profile profile_comp_udp;
extern struct rohc_comp_profile comp_profile_tcp;
extern struct rohc_comp_profile comp_profile_v2_udp;
extern struct rohc_comp_profile comp_profile_v2_rtp;
extern struct rohc_comp_profile comp_profile_v2_ip;
static int __init rohc_comp_init(void)
{
	int i;
	for(i = 0 ; i < ROHC_PROFILE_MAX ;i++)
		INIT_LIST_HEAD(&comp_profile_list[i]);
	INIT_LIST_HEAD(&profile_uncomp.list);
	rohc_comp_register_profile(&profile_uncomp);
	//rohc_comp_register_profile(&profile_comp_udp);
	rohc_comp_register_profile(&comp_profile_tcp);
	rohc_comp_register_profile(&comp_profile_v2_udp);
	rohc_comp_register_profile(&comp_profile_v2_rtp);
	rohc_comp_register_profile(&comp_profile_v2_ip);
	return 0;
}
module_init(rohc_comp_init);
