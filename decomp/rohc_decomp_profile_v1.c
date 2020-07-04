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
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/err.h>

#include "rohc_decomp_wlsb.h"

#include "rohc_decomp_profile_v1.h"
int rohc_decomp_profile_v1_init_context(struct decomp_profile_v1_context *context,struct decomp_profile_v1_ops *v1_ops)
{
	struct decomp_ip_context *ip_context;
	int retval,i;
	context->prof_v1_ops = v1_ops;
	ip_context = &context->ip_context;
	context->msn_wlsb = rohc_decomp_lsb_alloc(TYPE_USHORT,GFP_ATOMIC);
	if(IS_ERR(context->msn_wlsb)){
		retval = -ENOMEM;
		goto out;
	}
	for(i = 0 ; i < ROHC_MAX_IP_HDR ; i++){
		ip_context->ipid_wlsb[i] = rohc_decomp_lsb_alloc(TYPE_USHORT,GFP_ATOMIC);
		if(IS_ERR(ip_context->ipid_wlsb)){
			if(i > 0)
				rohc_decomp_lsb_free(ip_context->ipid_wlsb[0]);
			retval = -ENOMEM;
			goto err;
		}
	}
	return 0;
err:
	rohc_decomp_lsb_free(context->msn_wlsb);
out:
	return retval;
}
