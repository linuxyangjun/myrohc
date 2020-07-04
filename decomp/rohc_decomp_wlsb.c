/*
 * author : yangjun
 * date : 2019-11-25
 *
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/err.h>

#include "../rohc_common.h"

#include "rohc_decomp_wlsb.h"
struct rohc_decomp_wlsb *rohc_decomp_lsb_alloc(u8 type_size,gfp_t flags)
{
	struct rohc_decomp_wlsb *wlsb;
	wlsb = kzalloc(sizeof(struct rohc_decomp_wlsb),flags);
	if(!wlsb){
		pr_err("%s : alloc decomp lsb window failed\n",__func__);
		goto err;
	}
	wlsb->type_size = type_size;
	return wlsb;
err:
	wlsb = ERR_PTR(-ENOMEM);
	return wlsb;
}
void rohc_decomp_lsb_free(struct rohc_decomp_wlsb *wlsb)
{
	if(!wlsb)
		return;
	kfree(wlsb);
}

int rohc_decomp_lsb_decode(struct rohc_decomp_wlsb *lsb,u32 k,u32 p,u32 encode_v,u32 *decode_v,bool repair)
{
	
	u32 v_ref;
	u32 value;
	u32 interval;
	u32 mask;
	u32 v_ref_min;
	u32 v_ref_max;
	int retval = 0;
	if(k == 32)
		mask = -1;
	else
		mask = (1 << k) - 1;

	if(!repair)
		v_ref = lsb->v_ref_zero;
	else
		v_ref = lsb->v_ref_before_zero;
	v_ref_min = v_ref  - p;
	if(k == lsb->type_size)
		v_ref_max = encode_v + 1;
	else
		v_ref_max = v_ref + mask - p;
	value = encode_v + (v_ref_min & ~mask);
	printk(KERN_DEBUG "%s :type_size=%d,encode_v = %d,ref_v=%d,k=%d,p=%d,value=%d,mask_min = %d,min=%d,max=%d\n",__func__,lsb->type_size,encode_v,v_ref,k,p,value,(v_ref_min & ~mask),v_ref_min,v_ref_max);
	/*if encode value wrap around.
	 */
	if(encode_v < (v_ref_min & mask))
		value = value + mask + 1;
	switch(lsb->type_size){
		case TYPE_UCHAR:
			if(before8_eq(v_ref_min,value) && before8_eq(value,v_ref_max)){
				*decode_v = value & 0xff;
			}else
				retval = -EFAULT;
			break;
		case TYPE_USHORT:
			if(before16_eq(v_ref_min,value) && before16_eq(value,v_ref_max)){
				*decode_v = value & 0xffff;
			}else
				retval = -EFAULT;
			break;
		case TYPE_UINT:
			if(before32_eq(v_ref_min,value) && before32_eq(value,v_ref_max)){
				*decode_v = value;
			}else
				retval = -EFAULT;
			break;
	}
	return retval;
}

