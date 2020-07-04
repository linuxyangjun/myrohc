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
#include "../rohc_packet.h"

#include "../rohc_common.h"
#include "rohc_comp_wlsb.h"
#include "rohc_comp_profile_v1.h"
#include "dynamic_field_bh.h"
int rohc_comp_profile_v1_init_iph_context(struct ip_context *context,struct rohc_comp_packet_hdr_info *pkt_info,int oa_max)
{
	struct iphdr *iph;
	struct ipv6hdr *ipv6h;
	struct comp_win_lsb *wlsb;
	int i;
	int retval = 0;
	for(i = 0; i < pkt_info->iph_num ;i++){
		wlsb = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_USHORT,GFP_ATOMIC);
		if(IS_ERR(wlsb)){
			pr_err("alloc ipid wlsb for ip context faild\n");
			retval = -ENOMEM;
			if(i == ROHC_INNER_IPH){
				kfree(context->ip_id_wlsb[i - 1]);
			}
			goto out;
		}
		context->ip_id_wlsb[i] = wlsb;
		if(i == ROHC_OUTER_IPH)
			iph = &pkt_info->iph;
		else
			iph = &pkt_info->inner_iph;
		if(iph->version == 4){
			
		}else{
			
		}
	}
out:
	return retval;
}
int rohc_comp_profile_v1_init_context(struct comp_profile_v1_context *context,struct rohc_comp_packet_hdr_info *pkt_info,struct comp_profile_v1_ops *prof_v1_ops,int oa_max)
{
	int retval;
	struct ip_context *ip_txt;
	ip_txt = &context->ip_context;
	context->msn_wlsb = comp_wlsb_alloc(oa_max,TYPE_USHORT,TYPE_USHORT,GFP_ATOMIC);
	comp_wlsb_init(context->msn_wlsb,oa_max,TYPE_USHORT,TYPE_USHORT);
	if(IS_ERR(context->msn_wlsb)){
		pr_err("alloc msn wlsb for v1 context faild\n");
		retval = -ENOMEM;
		goto out;
	}
	context->oa_upward_pkts = oa_max;
	context->is_first_packet = true;
	context->prof_v1_ops = prof_v1_ops;
	retval = rohc_comp_profile_v1_init_iph_context(ip_txt,pkt_info,oa_max);
	if(retval){
		pr_err("init iph context faild\n");
		goto err;
	}
	ip_txt->is_first_packet = true;
	return 0;
err:
	kfree(context->msn_wlsb);
out:
	return retval;
}




