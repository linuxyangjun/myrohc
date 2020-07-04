/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	date: 2020/02/10
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
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

#include "../rohc_common.h"
#include "../rohc_cid.h"
#include "../rohc_packet.h"
#include "../rohc_profile.h"
#include "../rohc_ipid.h"
#include "../rohc_packet_field.h"

#include "rohc_decomp.h"
//#include "decomp_ip.h"
#include "rohc_decomp_wlsb.h"
#include "rohc_decomp_profile_v1.h"
//#include "rohc_decomp_v1_packet.h"


int rohc_decomp_analyze_after_extensions(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct iphdr *outer_iph,*inner_iph;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_ip_context *ip_ctxt;
	struct iph_decomp_update *iph_decompd;
	struct iph_decomp_fields  *outer_iph_fields,*inner_iph_fields;
	struct iph_decomp_dynamic_part *ipv4_dynamic_part;
	struct wlsb_analyze_field *ip_id;
	struct decomp_iph_context_info *last_context_info;
	struct analyze_field *new_ipid_bh;
	enum ip_id_behavior ipid_bh;
	u16 ipid_value;
	int retval = 0;
	int decomp_len = 0;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	v1_context = (struct decomp_profile_v1_context *)context->inherit_context;

	ip_ctxt = &v1_context->ip_context;
	iph_decompd = &ip_ctxt->update_by_packet;
	last_context_info = &ip_ctxt->last_context_info;
	outer_iph_fields = &iph_decompd->iph_fields;
	//ipid_bh = last_context_info->ip_id_bh[ROHC_OUTER_IPH];
	/*field 1,IP-ID of outer ipv4 header if(rand2) = 1
	 *
	 */
	if(rohc_decomp_has_inner_iph(last_context_info,iph_decompd)){
		new_ipid_bh = &iph_decompd->ipid_bh;
		if(analyze_field_is_carryed(new_ipid_bh))
			ipid_bh = (enum ip_id_behavior)new_ipid_bh->value;
		else 
			ipid_bh = last_context_info->ip_id_bh[ROHC_OUTER_IPH];
		if(rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_decompd,false)) && ip_id_is_random(ipid_bh)){
			ipv4_dynamic_part = &outer_iph_fields->iph.iph_dynamic_part;
			ip_id = &ipv4_dynamic_part->ip_id;
			memcpy(&ipid_value,analyze_data,sizeof(u16));
			decomp_len += 2;
			analyze_data += 2;
			decomp_wlsb_fill_analyze_field(ip_id,ipid_value,16,false);
		}
	}
	/*field 2 and 3,ah data and gre checksum not support
	 *
	 */
	/*field 4 IP-ID of inner ipv4 header if rand1 = 1
	 */
	if(rohc_decomp_has_inner_iph(last_context_info,iph_decompd)){
		inner_iph_fields = &iph_decompd->inner_iph_fields;
		new_ipid_bh = &iph_decompd->inner_ipid_bh;
		if(analyze_field_is_carryed(new_ipid_bh))
			ipid_bh = (enum ip_id_behavior)new_ipid_bh->value;
		else 
			ipid_bh = last_context_info->ip_id_bh[ROHC_INNER_IPH];

		if(rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_decompd,true)) && ip_id_is_random(ipid_bh)){
			ipv4_dynamic_part = &inner_iph_fields->iph.iph_dynamic_part;
			ip_id = &ipv4_dynamic_part->ip_id;
			memcpy(&ipid_value,analyze_data,sizeof(u16));
			decomp_len += 2;
			analyze_data += 2;
			decomp_wlsb_fill_analyze_field(ip_id,ipid_value,16,false);
		}
	}else{
		new_ipid_bh = &iph_decompd->ipid_bh;
		if(analyze_field_is_carryed(new_ipid_bh))
			ipid_bh = (enum ip_id_behavior)new_ipid_bh->value;
		else 
			ipid_bh = last_context_info->ip_id_bh[ROHC_OUTER_IPH];
		if(rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_decompd,false)) && ip_id_is_random(ipid_bh)){
			ipv4_dynamic_part = &outer_iph_fields->iph.iph_dynamic_part;
			ip_id = &ipv4_dynamic_part->ip_id;
			memcpy(&ipid_value,analyze_data,sizeof(u16));
			decomp_len += 2;
			analyze_data += 2;
			decomp_wlsb_fill_analyze_field(ip_id,ipid_value,16,false);
		}
	}
	/*field 5
	 * AH data for inner list
	 */

	/*field 6 GRE checksum 
	 */
	/*field 5 and 6 is not support now
	 *
	 */
	rohc_pr(ROHC_DEBUG,"%s : decomp_len=%d,inner:%d,ipid_bh=%d\n",__func__,decomp_len,rohc_decomp_has_inner_iph(last_context_info,iph_decompd),ipid_bh);
	pkt_info->decomped_hdr_len += decomp_len;
	if(context->decomp_profile->pro_ops->analyze_profile_header){
		retval = context->decomp_profile->pro_ops->analyze_profile_header(context,skb,pkt_info);
		if(retval)
			pr_err("profile-%x analyze private profile header failed\n",context->decomp_profile->profile);
	}
	return retval;
}
#if 1
int rohc_decomp_analyze_ext0(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct wlsb_analyze_field *msn;
	struct wlsb_analyze_field *outer_ip_id_field,*inner_ip_id_field;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_ip_context *ip_context;
	struct iph_decomp_update *iph_update;
	struct iph_decomp_fields *outer_iph_fields,*inner_iph_fields;
	struct analyze_field *new_outer_ipid_bh,*new_inner_ipid_bh;
	enum ip_id_behavior outer_ipid_bh,inner_ipid_bh;
	u16 ipid_value,msn_value;
	int ipid_bits,msn_bits;
	int retval = 0;
	int analyze_len = 0;
	v1_context = context->inherit_context;
	ip_context = &v1_context->ip_context;
	iph_update = &ip_context->update_by_packet;

	msn = &v1_context->msn_update;
	msn_value = msn->encode_v;
	msn_bits = msn->encode_bits;
	new_outer_ipid_bh = &iph_update->ipid_bh;
	outer_ipid_bh = ip_context->last_context_info.ip_id_bh[ROHC_OUTER_IPH];
	outer_iph_fields = &iph_update->iph_fields;
	if(analyze_field_is_carryed(new_outer_ipid_bh))
		outer_ipid_bh = (enum ip_id_behavior)new_inner_ipid_bh->value;
	/*extension 0 only one byte : 2 bits type ,3 bits sn and 3 bits ipid
	 */
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	msn_value = (msn_value << 3) | BYTE_BITS_3(*analyze_data,3);
	msn_bits += 3;
	decomp_wlsb_fill_analyze_field(msn,msn_value,msn_bits,true);
	if(ip_context->last_context_info.has_inner_iph){
		inner_iph_fields = &iph_update->inner_iph_fields;
		new_inner_ipid_bh = &iph_update->inner_ipid_bh;
		inner_ipid_bh = ip_context->last_context_info.ip_id_bh[ROHC_INNER_IPH];
		if(analyze_field_is_carryed(new_inner_ipid_bh))
			inner_ipid_bh = (enum ip_id_behavior)new_inner_ipid_bh->value;
		if(rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,iph_update,true)) && !ip_id_is_random_or_constant(inner_ipid_bh)){
			inner_ip_id_field = &inner_iph_fields->iph.iph_dynamic_part.ip_id;
			decomp_wlsb_analyze_field_append_bits(inner_ip_id_field,BYTE_BITS_3(*analyze_data,0),3,true);
		}else if(rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,iph_update,false)) && !ip_id_is_random_or_constant(outer_ipid_bh)){
			outer_ip_id_field = &outer_iph_fields->iph.iph_dynamic_part.ip_id;
			decomp_wlsb_analyze_field_append_bits(outer_ip_id_field,BYTE_BITS_3(*analyze_data,0),3,true);
		}else{
			pr_err("profile -%x  and cid -%d analyze ext0: non ip header is ipv4 and is not random and constant of two ip header\n",context->decomp_profile->profile,context->cid);
			retval = -EFAULT;
			goto out;
		}
	}else{
		if(rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,iph_update,false)) && !ip_id_is_random_or_constant(outer_ipid_bh)){
			outer_ip_id_field = &outer_iph_fields->iph.iph_dynamic_part.ip_id;
			decomp_wlsb_analyze_field_append_bits(outer_ip_id_field,BYTE_BITS_3(*analyze_data,0),3,true);
		}else{
			pr_err("profile -%x  and cid -%d analyze ext0: non ip header is ipv4 and is not random and constant of one ip header\n",context->decomp_profile->profile,context->cid);
			retval = -EFAULT;
			goto out;
		}
	}
	analyze_data++;
	analyze_len++;
	pkt_info->decomped_hdr_len += analyze_len;
out:
	return retval;
}

int rohc_decomp_analyze_ext1(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct wlsb_analyze_field *msn;
	struct wlsb_analyze_field *outer_ip_id_field,*inner_ip_id_field;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_ip_context *ip_context;
	struct iph_decomp_update *iph_update;
	struct iph_decomp_fields *outer_iph_fields,*inner_iph_fields;
	struct analyze_field *new_outer_ipid_bh,*new_inner_ipid_bh;
	enum ip_id_behavior outer_ipid_bh,inner_ipid_bh;
	u16 ipid_value,msn_value;
	u8 msn_bits;
	int retval = 0;
	int analyze_len = 0;
	v1_context = context->inherit_context;
	ip_context = &v1_context->ip_context;
	iph_update = &ip_context->update_by_packet;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	msn = &v1_context->msn_update;
	msn_value = msn->encode_v;
	msn_bits = msn->encode_bits;
	new_outer_ipid_bh = &iph_update->ipid_bh;
	outer_ipid_bh = ip_context->last_context_info.ip_id_bh[ROHC_OUTER_IPH];
	outer_iph_fields = &iph_update->iph_fields;
	outer_ip_id_field = &outer_iph_fields->iph.iph_dynamic_part.ip_id;
	if(analyze_field_is_carryed(new_outer_ipid_bh))
		outer_ipid_bh = (enum ip_id_behavior)new_inner_ipid_bh->value;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	/*field 1 : 2bits type and 3 bits SN ,and 3 bits ipid
	 */
	msn_value = (msn_value << 3) | BYTE_BITS_3(*analyze_data,3);
	msn_bits += 3;
	decomp_wlsb_fill_analyze_field(msn,msn_value,msn_bits,true);
	if(ip_context->last_context_info.has_inner_iph){
		inner_iph_fields = &iph_update->inner_iph_fields;
		new_inner_ipid_bh = &iph_update->inner_ipid_bh;
		inner_ipid_bh = ip_context->last_context_info.ip_id_bh[ROHC_INNER_IPH];
		if(analyze_field_is_carryed(new_inner_ipid_bh))
			inner_ipid_bh = (enum ip_id_behavior)new_inner_ipid_bh->value;
		if(rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,iph_update,true)) && !ip_id_is_random_or_constant(inner_ipid_bh)){
			inner_ip_id_field= &inner_iph_fields->iph.iph_dynamic_part.ip_id;

			decomp_wlsb_analyze_field_append_bits(inner_ip_id_field,BYTE_BITS_3(*analyze_data,0),3,true);
			analyze_data++;
			analyze_len++;
			/*field 2: 8bits IP ID
			 */
			decomp_wlsb_analyze_field_append_bits(inner_ip_id_field,*analyze_data,8,true);
			analyze_data++;
			analyze_len++;
		}else if(rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,iph_update,false)) && !ip_id_is_random_or_constant(outer_ipid_bh)){
			outer_ip_id_field = &outer_iph_fields->iph.iph_dynamic_part.ip_id;
			decomp_wlsb_analyze_field_append_bits(outer_ip_id_field,BYTE_BITS_3(*analyze_data,0),3,true);
			analyze_data++;
			analyze_len++;
			/*field 2: 8bits IP ID
			 */
			decomp_wlsb_analyze_field_append_bits(outer_ip_id_field,*analyze_data,8,true);
			analyze_data++;
			analyze_len++;
		}else{
			pr_err("profile -%x  and cid -%d analyze ext0: non ip header is ipv4 and is not random and constant of two ip header\n",context->decomp_profile->profile,context->cid);
			retval = -EFAULT;
			goto out;
		}
	}else{
		if(rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,iph_update,false)) && !ip_id_is_random_or_constant(outer_ipid_bh)){
			outer_ip_id_field = &outer_iph_fields->iph.iph_dynamic_part.ip_id;
			decomp_wlsb_analyze_field_append_bits(outer_ip_id_field,BYTE_BITS_3(*analyze_data,0),3,true);
			/*field 2: 8bits IP ID
			 */
			decomp_wlsb_analyze_field_append_bits(outer_ip_id_field,*analyze_data,8,true);
			analyze_data++;
			analyze_len++;
		}else{
			pr_err("profile -%x  and cid -%d analyze ext0: non ip header is ipv4 and is not random and constant of one ip header\n",context->decomp_profile->profile,context->cid);
			retval = -EFAULT;
			goto out;
		}
	}
	pkt_info->decomped_hdr_len += analyze_len;
out:
	return retval;
}

rohc_decomp_analyze_ext2(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct wlsb_analyze_field *msn;
	struct wlsb_analyze_field *outer_ip_id_field,*inner_ip_id_field;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_ip_context *ip_context;
	struct iph_decomp_update *iph_update;
	struct iph_decomp_fields *outer_iph_fields,*inner_iph_fields;
	struct analyze_field *new_outer_ipid_bh,*new_inner_ipid_bh;
	enum ip_id_behavior outer_ipid_bh,inner_ipid_bh;
	int retval = 0;
	int analyze_len = 0;
	v1_context = context->inherit_context;
	ip_context = &v1_context->ip_context;
	iph_update = &ip_context->update_by_packet;
	outer_iph_fields = &iph_update->iph_fields;
	msn = &v1_context->msn_update;
	if(!ip_context->last_context_info.has_inner_iph){
		pr_err("profile-%x cid-%d only support one ip heade when analyze extension 2\n",context->decomp_profile->profile,context->cid);
		retval = -EFAULT;
		goto out;
	}
	outer_ipid_bh = ip_context->last_context_info.ip_id_bh[ROHC_OUTER_IPH];
	new_outer_ipid_bh = &iph_update->ipid_bh;
	if(analyze_field_is_carryed(new_outer_ipid_bh))
		outer_ipid_bh = (enum ip_id_behavior)new_outer_ipid_bh->value;
	inner_iph_fields = &iph_update->inner_iph_fields;
	if(analyze_field_is_carryed(new_inner_ipid_bh))
		inner_ipid_bh = (enum ip_id_behavior)new_inner_ipid_bh->value;
	else
		inner_ipid_bh = ip_context->last_context_info.ip_id_bh[ROHC_INNER_IPH];
	if(!rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,iph_update,false)) || ip_id_is_random_or_constant(outer_ipid_bh) || !rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,iph_update,true)) || ip_id_is_random_or_constant(inner_ipid_bh)){
		pr_err("profile-%x cid-%d  extension 2 can't be used if the context contains at least one ip header with non ipv4 or random or constant\n",context->decomp_profile->profile,context->cid);
		retval = -EFAULT;
		goto out;
	}
	outer_ip_id_field = &outer_iph_fields->iph.iph_dynamic_part.ip_id;
	inner_ip_id_field = &inner_iph_fields->iph.iph_dynamic_part.ip_id;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	/*field 1 : 2 bits type and 3 bits SN and 3 bits IPID2
	 */
	decomp_wlsb_analyze_field_append_bits(msn,BYTE_BITS_3(*analyze_data,3),3,true);
	decomp_wlsb_analyze_field_append_bits(outer_ip_id_field,BYTE_BITS_3(*analyze_data,0),3,true);
	analyze_data++;
	analyze_len++;
	/*field 2 : 8 bits IPID2
	 */
	decomp_wlsb_analyze_field_append_bits(outer_ip_id_field,*analyze_data,8,true);
	analyze_data++;
	analyze_len++;
	/*field 3 : 8 bits IPID(innner ip header  ipid)
	 */
	decomp_wlsb_analyze_field_append_bits(inner_ip_id_field,*analyze_data,8,true);
	analyze_data++;
	analyze_len++;
	pkt_info->decomped_hdr_len += analyze_len;
out:
	return retval;
}
static inline void rohc_decomp_analyze_ext3_iph_flags(struct iph_decomp_dynamic_part *iph_dynamic_part,const u8 *analyze_data,bool *tos,bool *ttl,bool *pr,bool *ipx,bool *nbo,bool *rnd,bool *i,bool pick_i,bool is_ipv4)
{
	*tos = !!(BYTE_BIT_7(*analyze_data));
	*ttl = !!(BYTE_BIT_6(*analyze_data));
	if(is_ipv4){
		//iph_dynamic_part->df = !!(BYTE_BIT_5(*analyze_data));
		decomp_fill_analyze_field(&iph_dynamic_part->df,!!BYTE_BIT_5(*analyze_data));
		*nbo = !!(BYTE_BIT_2(*analyze_data));
		*rnd = !!(BYTE_BIT_1(*analyze_data));
	}
	*pr = !!(BYTE_BIT_4(*analyze_data));
	*ipx = !!(BYTE_BIT_3(*analyze_data));
	if(pick_i)
		*i = !!(BYTE_BIT_0(*analyze_data));
}
static inline int rohc_decomp_analyze_ext3_iph_fields(struct iph_decomp_dynamic_part *iph_dynamic_part,const u8 *analyze_data,bool tos,bool ttl,bool pr,bool ipx)
{	
	struct analyze_field	*tos_tc;
	struct analyze_field	*ttl_hl;
	struct analyze_field	*pr_nh;
	int analyze_len = 0;

	/*field 1: tos_tc
	 */
	if(tos){
		tos_tc = &iph_dynamic_part->tos_tc;
		decomp_fill_analyze_field(tos_tc,*analyze_data);
		analyze_data++;
		analyze_len++;
	}
	/*field 2: ttl/hl
	 */
	if(ttl){
		ttl_hl = &iph_dynamic_part->ttl_hl;
		decomp_fill_analyze_field(ttl_hl,*analyze_data);
		analyze_data++;
		analyze_len++;
	}
	/*field 4 : protocol /Next header
	 */
	if(pr){
		pr_nh = &iph_dynamic_part->pr_nh;
		decomp_fill_analyze_field(pr_nh,*analyze_data);
		analyze_data++;
		analyze_len++;
	}
	/*field 5 : ip extension headers ,now not support
	 */
	return analyze_len;
}
int rohc_decomp_analyze_ext3(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct wlsb_analyze_field *msn;
	struct wlsb_analyze_field *outer_ip_id_field,*inner_ip_id_field;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_ip_context *ip_context;
	struct decomp_iph_context_info	*last_context_info;
	struct iph_decomp_update *iph_update;
	struct iph_decomp_fields *outer_iph_fields,*inner_iph_fields;
	struct iph_decomp_dynamic_part *outer_iph_dynamic_part,*inner_iph_dynamic_part;
	struct analyze_field *new_outer_ipid_bh,*new_inner_ipid_bh;
	enum ip_id_behavior outer_ipid_bh,inner_ipid_bh;
	bool s;
	bool i1;
	bool i2;
	bool ip1;
	bool ip2;
	bool ttl1;
	bool tos1;
	bool ipx1;
	bool pr1;
	bool nbo1;
	bool rnd1;
	bool ttl2;
	bool tos2;
	bool ipx2;
	bool pr2;
	bool nbo2;
	bool rnd2;
	int mode;
	u16 *new_ipid;
	int retval = 0;
	int analyze_len = 0;
	int analyze_part_len = 0;
	v1_context = context->inherit_context;
	ip_context = &v1_context->ip_context;
	iph_update = &ip_context->update_by_packet;
	last_context_info = &ip_context->last_context_info;
	outer_iph_fields = &iph_update->iph_fields;
	inner_iph_fields = &iph_update->inner_iph_fields;
	new_outer_ipid_bh = &iph_update->ipid_bh;
	new_inner_ipid_bh = &iph_update->inner_ipid_bh;
	msn = &v1_context->msn_update;
	outer_ipid_bh = last_context_info->ip_id_bh[ROHC_OUTER_IPH];
	inner_ipid_bh = last_context_info->ip_id_bh[ROHC_INNER_IPH];
	outer_iph_dynamic_part = &outer_iph_fields->iph.iph_dynamic_part;
	inner_iph_dynamic_part = &inner_iph_fields->iph.iph_dynamic_part;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	
	/*field 1 : 2bits type and extension flags
	 */
	s = BYTE_BIT_5(*analyze_data);
	mode = BYTE_BITS_2(*analyze_data,3);
	if(mode != context->mode)
		pr_warn("profile-%x,context-%d  mode %d is different mode from compresser-mode  %d\n",context->decomp_profile->profile,context->cid,mode,context->mode);
	i1 = !!BYTE_BIT_2(*analyze_data);
	ip1 = !!BYTE_BIT_1(*analyze_data);
	ip2 = !!BYTE_BIT_0(*analyze_data);
	analyze_data++;
	analyze_len++;
	/*field 2: ip header flags
	 */
	if(ip1){
		if(rohc_decomp_has_inner_iph(last_context_info,iph_update)){
			rohc_decomp_analyze_ext3_iph_flags(inner_iph_dynamic_part,analyze_data,&tos1,&ttl1,&pr1,&ipx1,&nbo1,&rnd1,NULL,false,rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_update,true)));
			/*const ip id flags can't be carrryed by extension 3,only by ir_dyn
			 */
			if(rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_update,true)) && !ip_id_is_constant(inner_ipid_bh)){
				if(rnd1)
					decomp_fill_analyze_field(new_inner_ipid_bh,IP_ID_BEHAVIOR_RANDOM);
				else{
					if(nbo1)
						decomp_fill_analyze_field(new_inner_ipid_bh,IP_ID_BEHAVIOR_SEQ_NBO);
					else
						decomp_fill_analyze_field(new_inner_ipid_bh,IP_ID_BEHAVIOR_SEQ_SWAP);
				}
			}	
		}else{
			rohc_decomp_analyze_ext3_iph_flags(outer_iph_dynamic_part,analyze_data,&tos1,&ttl1,&pr1,&ipx1,&nbo1,&rnd1,NULL,false,rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_update,false)));
			/*const ip id flags can't be carrryed by extension 3,only by ir_dyn
			 */
			if(context->cid == 2)
				rohc_pr(ROHC_DUMP,"ext3 parse: s= %d,tos1=%d,ttl1=%d,pr1=%d,ipx1=%d,nbo1=%d,rnd1=%d,i1=%d\n",s,tos1,ttl1,pr1,ipx1,nbo1,rnd1,i1);
			if(rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_update,false)) && !ip_id_is_constant(outer_ipid_bh)){
				if(rnd1)
					decomp_fill_analyze_field(new_outer_ipid_bh,IP_ID_BEHAVIOR_RANDOM);
				else{
					if(nbo1)
						decomp_fill_analyze_field(new_outer_ipid_bh,IP_ID_BEHAVIOR_SEQ_NBO);
					else
						decomp_fill_analyze_field(new_outer_ipid_bh,IP_ID_BEHAVIOR_SEQ_SWAP);
				}
			}
		}
		analyze_data++;
		analyze_len++;
	}
	/*field 3 ip header flags,if present
	 */
	if(ip2){
		rohc_decomp_analyze_ext3_iph_flags(outer_iph_dynamic_part,analyze_data,&tos2,&ttl2,&pr2,&ipx2,&nbo2,&rnd2,&i2,true,rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_update,false)));
			/*const ip id flags can't be carrryed by extension 3,only by ir_dyn
			 */
			if(rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_update,false)) && !ip_id_is_constant(outer_ipid_bh)){
				if(rnd2)
					decomp_fill_analyze_field(new_outer_ipid_bh,IP_ID_BEHAVIOR_RANDOM);
				else{
					if(nbo2)
						decomp_fill_analyze_field(new_outer_ipid_bh,IP_ID_BEHAVIOR_SEQ_NBO);
					else
						decomp_fill_analyze_field(new_outer_ipid_bh,IP_ID_BEHAVIOR_SEQ_SWAP);
				}
			}

		analyze_data++;
		analyze_len++;
	}
	/*field 4 : SN
	 */
	if(s){
		decomp_wlsb_analyze_field_append_bits(msn,*analyze_data,8,true);
		analyze_data++;
		analyze_len++;
	}
	/*field 5: inner ip header fields
	 *
	 */
	if(ip1){
		if(rohc_decomp_has_inner_iph(last_context_info,iph_update)){
			analyze_part_len = rohc_decomp_analyze_ext3_iph_fields(inner_iph_dynamic_part,analyze_data,tos1,ttl1,pr1,ipx1);
		}else
			analyze_part_len = rohc_decomp_analyze_ext3_iph_fields(outer_iph_dynamic_part,analyze_data,tos1,ttl1,pr1,ipx1);
		analyze_data += analyze_part_len;
		analyze_len += analyze_part_len;
	}
	/*field 6: IP-ID
	 */
	if(i1){
		if(rohc_decomp_has_inner_iph(last_context_info,iph_update)){
			if(analyze_field_is_carryed(new_inner_ipid_bh))
				inner_ipid_bh = (enum ip_id_behavior)new_inner_ipid_bh->value;
			if(analyze_field_is_carryed(new_outer_ipid_bh))
				outer_ipid_bh = (enum ip_id_behavior)new_outer_ipid_bh->value;
			if(rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,iph_update,true)) && !ip_id_is_random_or_constant(inner_ipid_bh)){
				new_ipid = (u16 *)analyze_data;
				decomp_wlsb_fill_analyze_field(&inner_iph_dynamic_part->ip_id,*new_ipid,16,true);
				analyze_data += 2;
				analyze_len += 2;
			}else if(rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,iph_update,false)) && !ip_id_is_random_or_constant(outer_ipid_bh)){
				new_ipid = (u16 *)analyze_data;
				decomp_wlsb_fill_analyze_field(&outer_iph_dynamic_part->ip_id,*new_ipid,16,true);
				analyze_data += 2;
				analyze_len += 2;
			}
		}else {
			if(analyze_field_is_carryed(new_outer_ipid_bh))
				outer_ipid_bh = (enum ip_id_behavior)new_outer_ipid_bh->value;
			if(rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,iph_update,false)) && !ip_id_is_random_or_constant(outer_ipid_bh)){
			new_ipid = (u16 *)analyze_data;
			decomp_wlsb_fill_analyze_field(&outer_iph_dynamic_part->ip_id,*new_ipid,16,true);
			analyze_data += 2;
			analyze_len += 2;
			}
		}
	}
	/*field 7 ; outer ip header fields
	 */
	if(ip2){
		analyze_part_len = rohc_decomp_analyze_ext3_iph_fields(outer_iph_dynamic_part,analyze_data,tos2,ttl2,pr2,ipx2);
		analyze_data += analyze_part_len;
		analyze_len += analyze_part_len;
		if(i2){
			new_ipid = (u16 *)analyze_data;
			decomp_wlsb_fill_analyze_field(&outer_iph_dynamic_part->ip_id,*new_ipid,16,true);
			analyze_data += 2;
			analyze_len += 2;
		}
	}
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}


int rohc_decomp_analyze_uo0(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct sk_buff *decomp_skb;
	struct decomp_profile_v1_context *v1_context;
	struct wlsb_analyze_field *msn;
	enum rohc_cid_type cid_type;
	u8 crc;
	int retval = 0;
	v1_context = context->inherit_context;
	msn = &v1_context->msn_update;
	decomp_skb = context->decomp_skb;
	cid_type = context->decompresser->cid_type;
	BUG_ON(decomp_skb->len);
	/*copy the ethernet header.
	 */
	if(context->decomp_eth_hdr){
		memcpy(decomp_skb->data,skb->data,sizeof(struct ethhdr));
		pkt_info->rebuild_hdr_len = sizeof(struct ethhdr);
		skb_put(decomp_skb,sizeof(struct ethhdr));
	}
	if(cid_type == CID_TYPE_SMALL){
		pkt_info->decomped_hdr_len += pkt_info->cid_len;
		analyze_data = skb->data + pkt_info->decomped_hdr_len;
		pkt_info->decomped_hdr_len++;
		rohc_pr(ROHC_DEBUG,"%s : an=%x,msn=%d\n",__func__,*analyze_data,BYTE_BITS_4(*analyze_data,3));
	}else{
		analyze_data = skb->data + pkt_info->decomped_hdr_len;
		pkt_info->decomped_hdr_len += pkt_info->cid_len + 1;
	}
	/*byte0 1bit type ,4bits SN and 3 bits crc
	 */
	decomp_wlsb_fill_analyze_field(msn,BYTE_BITS_4(*analyze_data,3),4,true);
	crc = BYTE_BITS_3(*analyze_data,0);
	analyze_data++;
	rohc_pr(ROHC_DEBUG,"decomp_len_before_prof=%d\n",pkt_info->decomped_hdr_len);
	retval = rohc_decomp_analyze_after_extensions(context,skb,pkt_info);
	rohc_pr(ROHC_DEBUG,"%s : decomp_len=%d\n",__func__,pkt_info->decomped_hdr_len);
	return retval;
}

int rohc_decomp_analyze_uo1(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct sk_buff *decomp_skb;

	struct decomp_profile_v1_context *v1_context;
	struct wlsb_analyze_field *msn;
	struct wlsb_analyze_field *outer_ip_id_field,*inner_ip_id_field;
	struct analyze_field *new_outer_ipid_bh,*new_inner_ipid_bh;
	struct decomp_ip_context *ip_context;
	struct iph_decomp_update *iph_decompd;
	struct decomp_iph_context_info *last_context_info;
	struct iph_decomp_fields *outer_iph_fields,*inner_iph_fields;
	enum ip_id_behavior outer_ipid_bh,inner_ipid_bh;
	enum rohc_cid_type cid_type;
	u16 ipid_value;
	u8 ipid_bits;
	u8 crc;
	int retval = 0;
	int analyze_len = 0;
	v1_context = context->inherit_context;
	ip_context = &v1_context->ip_context;
	iph_decompd = &ip_context->update_by_packet;
	last_context_info = &ip_context->last_context_info;
	msn = &v1_context->msn_update;
	decomp_skb = context->decomp_skb;
	cid_type = context->decompresser->cid_type;
	outer_iph_fields = &iph_decompd->iph_fields;
	new_outer_ipid_bh = &iph_decompd->ipid_bh;
	outer_ipid_bh = last_context_info->ip_id_bh[ROHC_OUTER_IPH];
	if(analyze_field_is_carryed(new_outer_ipid_bh))
		outer_ipid_bh = (enum ip_id_behavior)new_outer_ipid_bh->value;
	BUG_ON(decomp_skb->len);
	/*copy the ethernet header.
	 */
	if(context->decomp_eth_hdr){
		memcpy(decomp_skb->data,skb->data,sizeof(struct ethhdr));
		pkt_info->rebuild_hdr_len = sizeof(struct ethhdr);
		skb_put(decomp_skb,sizeof(struct ethhdr));
	}
	if(cid_type == CID_TYPE_SMALL){
		pkt_info->decomped_hdr_len += pkt_info->cid_len;
		analyze_data = skb->data + pkt_info->decomped_hdr_len;
		/* field 1 after cid : 2 bits type and 5 bit ip-id 
		 */
		ipid_value = BYTE_BITS_5(*analyze_data,0);
		ipid_bits = 5;
		analyze_len++;
		analyze_data++;
		/*field 2 : 5 bits SN and 3 bits crc
		 */
		decomp_wlsb_fill_analyze_field(msn,BYTE_BITS_5(*analyze_data,3),5,true);
		crc = BYTE_BITS_3(*analyze_data,0);
		analyze_data++;
		analyze_len++;

	}else{
		/*field 1 before the cid bytes : 2 bits type and 5 bit ip id;
		 */
		analyze_data = skb->data + pkt_info->decomped_hdr_len;
		ipid_value = BYTE_BITS_5(*analyze_data,0);
		ipid_bits = 5;
		analyze_len = pkt_info->cid_len + 1;
		/*field 2 after cid bytes : 5 bits SN and 3 bits crc
		 */
		analyze_data += analyze_len;
		decomp_wlsb_fill_analyze_field(msn,BYTE_BITS_5(*analyze_data,3),5,true);
		crc = BYTE_BITS_3(*analyze_data,0);
		analyze_data++;
		analyze_len++;
	}
	pkt_info->decomped_hdr_len += analyze_len;
	/* TOTO crc caculate and check. not support now
	 *
	 */
	if(rohc_decomp_has_inner_iph(last_context_info,iph_decompd)){
		inner_iph_fields = &iph_decompd->inner_iph_fields;
		new_inner_ipid_bh = &iph_decompd->inner_ipid_bh;
		inner_ipid_bh = last_context_info->ip_id_bh[ROHC_INNER_IPH];
		if(analyze_field_is_carryed(new_inner_ipid_bh))
			inner_ipid_bh = (enum ip_id_behavior)new_inner_ipid_bh->value;
		if(rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_decompd,true)) && !ip_id_is_random_or_constant(inner_ipid_bh))
			decomp_wlsb_fill_analyze_field(&inner_iph_fields->iph.iph_dynamic_part.ip_id,ipid_value,ipid_bits,true);
		else if(rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_decompd,false) && !ip_id_is_random_or_constant(outer_ipid_bh))){
			decomp_wlsb_fill_analyze_field(&outer_iph_fields->iph.iph_dynamic_part.ip_id,ipid_value,ipid_bits,true);
		}else{
			pr_err("profile -%x  and cid -%d analyze uo-1: non ip header is ipv4 and is not random and constant of two ip header\n",context->decomp_profile->profile,context->cid);
			retval = -EFAULT;
			goto out;
		}
	}else{
		if(rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_decompd,false)) && !ip_id_is_random_or_constant(outer_ipid_bh)){
			decomp_wlsb_fill_analyze_field(&outer_iph_fields->iph.iph_dynamic_part.ip_id,ipid_value,ipid_bits,true);
		}else{
			pr_err("profile -%x  and cid -%d analyze uo-1: non ip header is ipv4 and is not random and constant of one ip header\n",context->decomp_profile->profile,context->cid);
			retval = -EFAULT;
			goto out;
		}
	}
	retval = rohc_decomp_analyze_after_extensions(context,skb,pkt_info);
	if(retval)
		pr_err("profile-%x,cid-%d analyze profile header after extension when analyze uo-1 failed\n",context->decomp_profile->profile,context->cid);
out:
	return retval;
}

int rohc_decomp_analyze_uro2(struct rohc_decomp_context *context,struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct sk_buff *decomp_skb;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_profile_v1_ops *prof_v1_ops;
	struct wlsb_analyze_field *msn;
	enum rohc_cid_type cid_type;
	bool	is_carrry_ext;
	u8 crc;
	int retval = 0;
	int analyze_len = 0;
	v1_context = context->inherit_context;
	prof_v1_ops = v1_context->prof_v1_ops;
	cid_type = context->decompresser->cid_type;
	msn = &v1_context->msn_update;
	decomp_skb = context->decomp_skb;
	BUG_ON(decomp_skb->len);
	/*copy the ethernet header.
	 */
	if(context->decomp_eth_hdr){
		memcpy(decomp_skb->data,skb->data,sizeof(struct ethhdr));
		pkt_info->rebuild_hdr_len = sizeof(struct ethhdr);
		skb_put(decomp_skb,sizeof(struct ethhdr));
	}
	if(cid_type == CID_TYPE_SMALL){
		pkt_info->decomped_hdr_len += pkt_info->cid_len;
		/*field 1 after cid info : 3 bits type and 5 bits sn
		 */
		analyze_data = skb->data + pkt_info->decomped_hdr_len;
		decomp_wlsb_fill_analyze_field(msn,BYTE_BITS_5(*analyze_data,0),5,true);
		analyze_len++;
		analyze_data++;
		/*field 2 ,1bit extension present indicate and 7 bits crc;
		 */
		is_carrry_ext = !!(BYTE_BIT_7(*analyze_data));
		crc = BYTE_BITS_7(*analyze_data,0);
		analyze_data++;
		analyze_len++;
	}else{
		/*field 1,before cid info : 3 bits type and 5 bits sn
		 */
		analyze_data = skb->data + pkt_info->decomped_hdr_len;
		decomp_wlsb_fill_analyze_field(msn,BYTE_BITS_5(*analyze_data,0),5,true);
		analyze_len += 1 + pkt_info->cid_len;
		analyze_data += analyze_len;
		/*field 2,after cid info: 1 bit extension present indicate and 7 bits crc
		 */
		is_carrry_ext = !!(BYTE_BIT_7(*analyze_data));
		analyze_len++;
		analyze_data++;
	}
	pkt_info->decomped_hdr_len += analyze_len;
	rohc_pr(ROHC_DEBUG,"%s:analyze_len=%d,is_carrry_ext=%d,next_byte=%x\n",__func__,analyze_len,is_carrry_ext,\
			*(skb->data + pkt_info->decomped_hdr_len));
	if(is_carrry_ext){
		BUG_ON(!prof_v1_ops->adjust_extension_type);
		retval = prof_v1_ops->adjust_extension_type(context,skb,pkt_info);
		if(retval){
			pr_err("profile-%x cid-%d adjust extension type failed when analyze uro2 packet\n",context->decomp_profile->profile,context->cid);
			retval = -EFAULT;
			goto out;
		}
		BUG_ON(!prof_v1_ops->analyze_extension);
		retval = prof_v1_ops->analyze_extension(context,skb,pkt_info);
		if(retval){
			pr_err("profile-%x cid-%d analyze extension  failed when analyze uro2 packet\n",context->decomp_profile->profile,context->cid);
			retval = -EFAULT;
			goto out;
		}
	}
	retval = rohc_decomp_analyze_after_extensions(context,skb,pkt_info);
	if(retval)
		pr_err("profile-%x,cid-%d analyze profile header after extension when analyze uro2 failed\n",context->decomp_profile->profile,context->cid);
	if(context->cid == 2)
		rohc_pr(ROHC_DUMP,"%s : cid:%d ,decomp_len=%d\n",__func__,context->cid,pkt_info->decomped_hdr_len);
out:
	return retval;
}

static inline int rohc_decomp_analyze_ip_static_fields(u8 *analyze_data,struct iph_decomp_fields *iph_fields,u8 *pr_nh)
{
	int analyze_len;
	struct ip_static_fields *iph_v4_fields;
	struct ipv6_static_fields *iph_v6_fields;
	if(rohc_iph_is_v4(BYTE_BITS_4(*analyze_data,4))){
		iph_v4_fields = &iph_fields->iph.iph_static_part;
		memcpy(iph_v4_fields,analyze_data,sizeof(struct ip_static_fields));
		iph_fields->iph.ip_static_fields_update = true;
		iph_fields->ip_version = BYTE_BITS_4(*analyze_data,4);
		iph_fields->ip_version_update = true;
		*pr_nh = iph_v4_fields->protocol;
		analyze_len = sizeof(struct ip_static_fields);
		rohc_packet_dump_ipv4_static(iph_v4_fields);
	}else{
		//ipv6 header analyze.now not support
		printk(KERN_DEBUG "%s : not support ipv6 now,ana_data=%x\n",__func__,*analyze_data);
		analyze_len = sizeof(struct ipv6_static_fields);
	}
	return analyze_len;
}
int rohc_decomp_analyze_ip_static_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;

	struct decomp_profile_v1_context *v1_context;
	struct decomp_ip_context *ip_context;
	struct iph_decomp_update *ip_update;
	struct iph_decomp_fields *outer_iph_fields,*inner_iph_fields;
	u8 pr_nh;
	int retval = 0;
	int analyze_len = 0;
	v1_context = context->inherit_context;
	ip_context = &v1_context->ip_context;
	ip_update = &ip_context->update_by_packet;
	outer_iph_fields = &ip_update->iph_fields;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	analyze_len += rohc_decomp_analyze_ip_static_fields(analyze_data,outer_iph_fields,&pr_nh);
	analyze_data += analyze_len;
	ip_update->iph_num++;
	if(pr_nh == IPPROTO_IPIP || pr_nh == IPPROTO_IPV6){
		inner_iph_fields = &ip_update->inner_iph_fields;
		analyze_len += rohc_decomp_analyze_ip_static_fields(analyze_data,inner_iph_fields,&pr_nh);
		analyze_data += analyze_len;
		ip_update->has_inner_iph = true;
		ip_update->iph_num++;
		if(pr_nh == IPPROTO_IPIP || pr_nh == IPPROTO_IPV6){
			pr_err("profile-%x,cid-%d has too many ip header when analyze ip static chain\n",context->decomp_profile->profile,context->cid);
			retval = -EPERM;
			goto out;
		}
	}
	pkt_info->decomped_hdr_len += analyze_len;
out:
	return retval;
}


static inline int rohc_decomp_analyze_ip_dynamic_fields(u8 *analyze_data,struct iph_decomp_fields *iph_fields,struct analyze_field *ipid_bh,bool is_ipv4)
{
	struct ip_dynamic_fields *ipv4_fields;
	struct iph_decomp_dynamic_part *iph_dynamic_part;
	int analyze_len = 0;
	if(is_ipv4){
		ipv4_fields = (struct ip_dynamic_fields *)analyze_data;
		iph_dynamic_part = &iph_fields->iph.iph_dynamic_part;
		decomp_fill_analyze_field(&iph_dynamic_part->tos_tc,ipv4_fields->tos);
		decomp_fill_analyze_field(&iph_dynamic_part->ttl_hl,ipv4_fields->ttl);
		decomp_fill_analyze_field(&iph_dynamic_part->df,!!ipv4_fields->df);
		rohc_pr(ROHC_DUMP," %s :update  df = %d\n",__func__,iph_dynamic_part->df.value);
		decomp_wlsb_fill_analyze_field(&iph_dynamic_part->ip_id,ipv4_fields->ip_id,16,false);
		//iph_decomp_dynamic_part->df = ipv4_fields->df;
		if(ipv4_fields->constant)
			decomp_fill_analyze_field(ipid_bh,IP_ID_BEHAVIOR_CONSTANT);
		else if(ipv4_fields->rnd)
			decomp_fill_analyze_field(ipid_bh,IP_ID_BEHAVIOR_RANDOM);
		else{
			if(ipv4_fields->nbo)
				decomp_fill_analyze_field(ipid_bh,IP_ID_BEHAVIOR_SEQ_NBO);
			else
				decomp_fill_analyze_field(ipid_bh,IP_ID_BEHAVIOR_SEQ_SWAP);
		}
		analyze_len += sizeof(struct ip_dynamic_fields);

	}else{
		pr_err("%s : not support ipv6 now\n",__func__);
	}
	return analyze_len;
}
int rohc_decomp_analyze_ip_dynamic_chain(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_ip_context *ip_context;
	struct iph_decomp_update *iph_update;
	struct iph_decomp_fields *outer_iph_fields,*inner_iph_fields;
	struct analyze_field *outer_ipid_bh,*inner_ipid_bh;
	int retval = 0;
	int analyze_len = 0;
	v1_context = context->inherit_context;
	ip_context = &v1_context->ip_context;
	iph_update = &ip_context->update_by_packet;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	outer_iph_fields = &iph_update->iph_fields;
	outer_ipid_bh = &iph_update->ipid_bh;
	analyze_len += rohc_decomp_analyze_ip_dynamic_fields(analyze_data,outer_iph_fields,outer_ipid_bh,rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,iph_update,false)));
	analyze_data += analyze_len;
	if(rohc_decomp_has_inner_iph(&ip_context->last_context_info,iph_update)){
		inner_iph_fields = &iph_update->inner_iph_fields;
		inner_ipid_bh = &iph_update->inner_ipid_bh;
		analyze_len += rohc_decomp_analyze_ip_dynamic_fields(analyze_data,inner_iph_fields,inner_ipid_bh,rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,iph_update,true)));
	}
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int rohc_decomp_adjust_extension_type(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct decomp_profile_v1_context *v1_context;
	enum rohc_ext_type ext_type;
	int retval = 0;
	v1_context = context->inherit_context;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	switch(rohc_packet_pick_ext_type(analyze_data)){
		case ROHC_EXT_0:
			ext_type = EXT_TYPE_0;
			break;
		case ROHC_EXT_1:
			ext_type = EXT_TYPE_1;
			break;
		case ROHC_EXT_2:
			ext_type = EXT_TYPE_2;
			break;
		case ROHC_EXT_3:
			ext_type = EXT_TYPE_3;
			break;
		default:
			pr_err("profile-%x cid-%d can't pick the extension type\n",context->decomp_profile->profile,context->cid);
			retval = -EFAULT;
			goto out;
	}
	rohc_pr(ROHC_DEBUG,"ext_type = %d\n",ext_type);
	v1_context->ext_type = ext_type;
out:
	return retval;

}

int rohc_decomp_analyze_extension(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct decomp_profile_v1_context *v1_context;
	enum rohc_ext_type ext_type;
	v1_context = context->inherit_context;
	ext_type = v1_context->ext_type;
	int retval;
	switch(ext_type){
		case EXT_TYPE_0:
			retval = rohc_decomp_analyze_ext0(context,skb,pkt_info);
			break;
		case EXT_TYPE_1:
			retval = rohc_decomp_analyze_ext1(context,skb,pkt_info);
			break;
		case EXT_TYPE_2:
			retval = rohc_decomp_analyze_ext2(context,skb,pkt_info);
			break;
		case EXT_TYPE_3:
			retval = rohc_decomp_analyze_ext3(context,skb,pkt_info);
			break;
		default:
			pr_err("profile-%x cid-%d can't analyze the %d extension type\n",context->decomp_profile->profile,context->cid,ext_type);
			retval = -EFAULT;
			break;
	}

	return retval;
}
enum rohc_packet_type rohc_decomp_adjust_packet_type(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	enum rohc_cid_type cid_type;
	enum rohc_packet_type packet_type;
	cid_type = context->decompresser->cid_type;
	if(cid_type == CID_TYPE_SMALL)
		analyze_data = skb->data + pkt_info->decomped_hdr_len + pkt_info->cid_len;
	else
		analyze_data = skb->data + pkt_info->decomped_hdr_len;
	if(rohc_packet_is_uo0(analyze_data))
		packet_type = ROHC_PACKET_TYPE_UO_0;
	else if(rohc_packet_is_uo1(analyze_data))
		packet_type = ROHC_PACKET_TYPE_UO_1;
	else if(rohc_packet_is_uro2(analyze_data))
		packet_type = ROHC_PACKET_TYPE_URO_2;
	else{
		pr_err("profile-%x ,cid-%d can't adjust the packet type ,data:%x\n",context->decomp_profile->profile,context->cid,*analyze_data);
		packet_type = ROHC_PACKET_TYPE_UNDECIDE;
	}
	return packet_type;
}
#endif
