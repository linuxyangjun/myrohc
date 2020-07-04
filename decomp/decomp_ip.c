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

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/swab.h>
//#include <linux/ip.h>

#include <net/ip.h>
#include "../rohc_common.h"
#include "../rohc_ipid.h"
#include "../rohc_packet.h"

#include "../lsb.h"
#include "rohc_decomp_wlsb.h"
#include "decomp_ip.h"
#include "rohc_decomp.h"

int rohc_decode_ip_id_offset(struct rohc_decomp_wlsb *wlsb,struct wlsb_analyze_field *ip_id,u16 *ip_id_offset)
{
	u32 decode_v;
	int retval = 0;
	if(!decomp_wlsb_analyze_field_is_carryed(ip_id)){
		*ip_id_offset = rohc_decomp_lsb_pick_ref(wlsb,false) & 0xffff;
	}else{
		if(rohc_decomp_lsb_decode(wlsb,ip_id->encode_bits,ROHC_LSB_IPID_P,ip_id->encode_v,&decode_v,false)){
			rohc_pr(ROHC_DUMP,"decode the ip id offset by wlsb failed\n");
			retval = -EFAULT;
			goto out;
		}else{
			*ip_id_offset = decode_v & 0xffff;
		}
	}
out:
	return retval;
}

static inline int rohc_decode_ipv4_packet_header(struct iphdr *decode_iph,struct iphdr *last_iph,struct ipv4_decomp_fields *iph_fields,struct rohc_decomp_wlsb	*ipid_wlsb,enum ip_id_behavior ipid_bh,u32 msn)
{
	struct ip_static_fields  *static_fields;
	struct iph_decomp_dynamic_part *dynamic_fields;
	struct wlsb_analyze_field *ip_id;
	u16 frag_off;
	u16 ip_id_offset,ip_id_v;
	int retval = 0;
	dynamic_fields = &iph_fields->iph_dynamic_part;

	/*decode static part
	 */
	if(iph_fields->ip_static_fields_update){
		static_fields = &iph_fields->iph_static_part;
		decode_iph->version = static_fields->version;
		decode_iph->protocol = static_fields->protocol;
		memcpy(&decode_iph->saddr,&static_fields->saddr,4);
		memcpy(&decode_iph->daddr,&static_fields->daddr,4);
		rohc_pr(ROHC_DEBUG,"%s : update the ip static\n",__func__);
	}else{
		decode_iph->version = last_iph->version;
		decode_iph->protocol = last_iph->protocol;
		memcpy(&decode_iph->saddr,&last_iph->saddr,4);
		memcpy(&decode_iph->daddr,&last_iph->daddr,4);
	}
	/*decode dynamic part
	 */
	if(analyze_field_is_carryed(&dynamic_fields->tos_tc))
		decode_iph->tos = dynamic_fields->tos_tc.value & 0xff;
	else
		decode_iph->tos = last_iph->tos;
	if(analyze_field_is_carryed(&dynamic_fields->ttl_hl))
		decode_iph->ttl = dynamic_fields->ttl_hl.value & 0xff;
	else
		decode_iph->ttl = last_iph->ttl;
	if(analyze_field_is_carryed(&dynamic_fields->df)){
		rohc_pr(ROHC_DUMP,"%s : df = %d\n",__func__,dynamic_fields->df.value);
		if(dynamic_fields->df.value)
			frag_off = IP_DF;
		else
			frag_off = 0;
		decode_iph->frag_off = htons(frag_off);
	}else
		decode_iph->frag_off = last_iph->frag_off;
	
	/*decode ip id
	 */
	ip_id = &dynamic_fields->ip_id;
	if(ip_id_is_constant(ipid_bh)){
		if(decomp_wlsb_analyze_field_is_carryed(ip_id)){
			decode_iph->id = ip_id->encode_v & 0xffff;
		}else
			decode_iph->id = last_iph->id;
	}else if(ip_id_is_random(ipid_bh)){
		if(!decomp_wlsb_analyze_field_is_carryed(ip_id) || ip_id->is_comp){
			pr_err( "the random ipv4 header  ipid carred-%d,is_comp-%d\n",decomp_wlsb_analyze_field_is_carryed(ip_id),ip_id->is_comp);
			retval = -EFAULT;
			goto out;
		}
		decode_iph->id = ip_id->encode_v & 0xffff;
	}else{
		if(decomp_wlsb_analyze_field_is_carryed(ip_id) && !ip_id->is_comp){
			decode_iph->id = ip_id->encode_v & 0xffff;
		}else{
			if(rohc_decode_ip_id_offset(ipid_wlsb,ip_id,&ip_id_offset)){
				rohc_pr(ROHC_DUMP,"%s decode ip id offset failed\n",__func__);
				retval = -EFAULT;
			}else{
				ip_id_v = msn + ip_id_offset;
				if(ip_id_is_nbo(ipid_bh)){
					decode_iph->id = htons(ip_id_v);
				}else{
					decode_iph->id = htons(__swab16(ip_id_v));
				}
			}
		}
		rohc_pr(ROHC_DUMP,"decode_iph ipid=%d\n",ntohs(decode_iph->id));

	}
out:
	return retval;

}

static inline int rohc_decode_ipv6_packet_header(struct ipv6hdr *decode_iph,struct ipv6hdr *last_iph,struct iph_decomp_fields *iph_fields,enum ip_id_behavior ipid_bh)
{
	return 0;
}
int rohc_decode_ip_packet_header(struct decomp_ip_context *ip_context,struct rohc_decomp_pkt_hdr_info *pkt_info,u32 msn)
{
	struct iphdr *outer_decode_iph,*inner_decode_iph;
	struct ipv6hdr *outer_decode_ipv6h,*inner_decode_ipv6h;
	struct iphdr *outer_old_iph,*inner_old_iph;

	struct iph_decomp_update *iph_update;
	struct decomp_iph_context_info *last_context_info;
	struct decoded_iph_hdr *decode_iph;
	struct iph_decomp_fields *outer_iph_fields,*inner_iph_fields;
	struct analyze_field *new_outer_ipid_bh,*new_inner_ipid_bh;
	enum ip_id_behavior outer_ipid_bh,inner_ipid_bh; 
	int retval = 0;
	iph_update = &ip_context->update_by_packet;
	last_context_info = &ip_context->last_context_info;
	outer_iph_fields = &iph_update->iph_fields;
	inner_iph_fields = &iph_update->inner_iph_fields;
	new_outer_ipid_bh = &iph_update->ipid_bh;
	new_inner_ipid_bh = &iph_update->inner_ipid_bh;
	decode_iph = &iph_update->decoded_iphdr;
	outer_old_iph = &last_context_info->iph_save_info.iph;

	if(rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_update,false))){
		if(analyze_field_is_carryed(new_outer_ipid_bh))
			outer_ipid_bh = (enum ip_id_behavior)new_outer_ipid_bh->value;
		else
			outer_ipid_bh = last_context_info->ip_id_bh[ROHC_OUTER_IPH];
		outer_decode_iph = &decode_iph->iph;
		retval = rohc_decode_ipv4_packet_header(outer_decode_iph,outer_old_iph,&outer_iph_fields->iph,ip_context->ipid_wlsb[ROHC_OUTER_IPH],outer_ipid_bh,msn);
		if(retval)
			goto out;
	}else{
		//IPV6 
	}
	if(rohc_decomp_has_inner_iph(last_context_info,iph_update)){
		if(rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_update,true))){
			if(analyze_field_is_carryed(new_inner_ipid_bh))
				inner_ipid_bh = (enum ip_id_behavior)new_inner_ipid_bh->value;
			else
				inner_ipid_bh = last_context_info->ip_id_bh[ROHC_INNER_IPH];
			inner_decode_iph = &decode_iph->inner_iph;
			inner_old_iph = &last_context_info->iph_save_info.inner_iph;
			retval = rohc_decode_ipv4_packet_header(inner_decode_iph,inner_old_iph,&inner_iph_fields->iph,ip_context->ipid_wlsb[ROHC_INNER_IPH],inner_ipid_bh,msn);
			if(retval)
				goto out;
		}else{
			//IPV6
		}
	}
out:
	return retval;
}

static inline int rohc_rebuild_ipv4_header(struct iphdr *decoded_iph,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool is_inner_iph)
{
	struct iphdr *iph;
	if(!is_inner_iph)
		skb_set_network_header(decomp_skb,decomp_skb->len);
	else
		skb_set_inner_network_header(decomp_skb,decomp_skb->len);
	iph = (struct iphdr *)skb_tail_pointer(decomp_skb);
	memcpy(iph,decoded_iph,sizeof(struct iphdr));
	iphdr_dump(iph,__func__);

	/*
	 *not support ip options.
	 */
	iph->ihl = 5;
	pkt_info->rebuild_hdr_len += sizeof(struct iphdr);
	skb_put(decomp_skb,sizeof(struct iphdr));
	return 0;
}
int rohc_rebuild_ip_header(struct decomp_ip_context *ip_context,struct sk_buff *decomp_skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	struct iphdr *outer_decode_iph,*inner_decode_iph;
	struct ipv6hdr *outer_decode_ipv6h,*inner_decode_ipv6h;
	struct iph_decomp_update *iph_update;
	struct decomp_iph_context_info	*last_context_info;
	struct decoded_iph_hdr *decode_iph;
	iph_update = &ip_context->update_by_packet;
	decode_iph = &iph_update->decoded_iphdr;
	last_context_info = &ip_context->last_context_info;
	if(rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_update,false))){
		outer_decode_iph = &decode_iph->iph;
		rohc_rebuild_ipv4_header(outer_decode_iph,decomp_skb,pkt_info,false);
	}else{
		//IPV6 rebuild header.
	}
	if(rohc_decomp_has_inner_iph(&ip_context->last_context_info,iph_update)){
		if(rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_update,true))){
			inner_decode_iph = &decode_iph->inner_iph;
			rohc_rebuild_ipv4_header(inner_decode_iph,decomp_skb,pkt_info,true);
		}else{
			//IPV6 rebuild header.
		}
	}
	return 0;
}


static inline void rohc_update_ipv4_context(struct iphdr *save_iph,struct iphdr *new_iph,struct rohc_decomp_wlsb *ipid_wlsb,enum ip_id_behavior ipid_bh,u32 msn)
{
	u16 ip_id_offset,ip_id;
	ip_id = ntohs(new_iph->id);
	iphdr_dump(new_iph,__func__);
	memcpy(save_iph,new_iph,sizeof(struct iphdr));
	if(ip_id_is_nbo(ipid_bh))
		ip_id_offset = ip_id - msn;
	else
		ip_id_offset = __swab16(ip_id) - msn;
	rohc_pr(ROHC_DUMP,"update ipid_off = %d,msn=%d,ipid=%d,ipid_bh=%d\n",ip_id_offset,msn,ip_id,ipid_bh);
	rohc_decomp_lsb_setup_ref(ipid_wlsb,ip_id_offset);
}
int rohc_update_ip_context(struct decomp_ip_context *ip_context,struct rohc_decomp_pkt_hdr_info *pkt_info,u32 msn)
{
	struct iph_decomp_update *iph_update;
	struct decomp_iph_context_info *last_context_info;
	struct last_iph_info *old_iph_info;
	struct rohc_decomp_wlsb *outer_ipid_wlsb,*inner_ipid_wlsb;
	struct analyze_field *new_outer_ipid_bh,*new_inner_ipid_bh;
	struct decoded_iph_hdr *decoded_iph;
	int retval = 0;
	iph_update = &ip_context->update_by_packet;
	last_context_info = &ip_context->last_context_info;
	old_iph_info = &last_context_info->iph_save_info;
	decoded_iph = &iph_update->decoded_iphdr;
	new_outer_ipid_bh = &iph_update->ipid_bh;
	if(analyze_field_is_carryed(new_outer_ipid_bh))
		last_context_info->ip_id_bh[ROHC_OUTER_IPH] = (enum ip_id_behavior)new_outer_ipid_bh->value;
	if(iph_update->has_inner_iph)
		last_context_info->has_inner_iph = iph_update->has_inner_iph;
	old_iph_info->iph_num++;
	if(rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_update,false))){
			outer_ipid_wlsb = ip_context->ipid_wlsb[ROHC_OUTER_IPH];
			rohc_update_ipv4_context(&old_iph_info->iph,&decoded_iph->iph,outer_ipid_wlsb,last_context_info->ip_id_bh[ROHC_OUTER_IPH],msn);
	}else{
		//IPV6
	}
	
	if(rohc_decomp_has_inner_iph(last_context_info,iph_update)){
		new_inner_ipid_bh = &iph_update->inner_ipid_bh;
		old_iph_info->has_inner_iph = true;
		old_iph_info->iph_num++;
		if(analyze_field_is_carryed(new_inner_ipid_bh))
			last_context_info->ip_id_bh[ROHC_INNER_IPH] = (enum ip_id_behavior)new_inner_ipid_bh->value;
		if(rohc_iph_is_v4(decomp_ip_obain_vesion(last_context_info,iph_update,true))){
			inner_ipid_wlsb = ip_context->ipid_wlsb[ROHC_INNER_IPH];
			rohc_update_ipv4_context(&old_iph_info->inner_iph,&decoded_iph->inner_iph,inner_ipid_wlsb,last_context_info->ip_id_bh[ROHC_INNER_IPH],msn);
		}else{
			//IPV6
		}
	}
	return retval;
}
