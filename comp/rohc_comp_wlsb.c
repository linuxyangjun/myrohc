
/*
 *	rohc
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	Date   :	2019-11-16
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

#include "rohc_comp_wlsb.h"
#include "../rohc_common.h"
struct kmem_cache *wlsb_cache;
struct kmem_cache *wentry_cache;
struct comp_win_lsb *comp_wlsb_alloc(int win_size,u8 sn_type_size ,u8 val_type_size,gfp_t flags)
{
	int i;
	struct comp_win_lsb *wlsb;
	struct win_entry *wentry;

	wlsb = kzalloc(sizeof(struct comp_win_lsb),flags);
	if(!wlsb){
		pr_err("%s : create lsb window failed\n",__func__);
		goto err0;
	}

	wlsb->w_entrys = kcalloc(win_size,sizeof(struct win_entry),flags);
	if(!wlsb->w_entrys){
		pr_err("%s : create window entry failed\n",__func__);
		goto err1;
	}
	wlsb->win_size = win_size;
	wlsb->last_irdyn_index = 0;
	wlsb->win_index = 0;
	wlsb->w_len = 0;
	wlsb->sn_type_size = sn_type_size;
	wlsb->val_type_size = val_type_size;
	for(i = 0 ; i < win_size ; i++){
		wentry = &wlsb->w_entrys[i];
		//set_bit(ENTRY_STATE_FREE,&wentry->state);
		spin_lock_init(&wentry->lock);
	}
	spin_lock_init(&wlsb->lock);
	return wlsb;

err1:
	kfree(wlsb);

err0:
	wlsb = ERR_PTR(-ENOMEM);
	return wlsb;
}

void comp_wlsb_destroy(struct comp_win_lsb *wlsb)
{
	kfree(wlsb->w_entrys);
	kfree(wlsb);
}
int comp_wlsb_init(struct comp_win_lsb *wlsb,int win_size,u8 sn_type_size ,u8 val_type_size)
{
	int i;
	struct win_entry *wentry;
	wlsb->w_entrys = kcalloc(win_size,sizeof(struct win_entry),GFP_ATOMIC);
	if(!wlsb->w_entrys){
		pr_err("%s : create window entry failed\n",__func__);
		goto err;
	}
	wlsb->win_size = win_size;
	wlsb->last_irdyn_index = 0;
	wlsb->win_index = 0;
	wlsb->w_len = 0;
	wlsb->sn_type_size = sn_type_size;
	wlsb->val_type_size = val_type_size;
	for(i = 0 ; i < win_size ; i++){
		wentry = &wlsb->w_entrys[i];
		//set_bit(ENTRY_STATE_FREE,&wentry->state);
		spin_lock_init(&wentry->lock);
	}
	spin_lock_init(&wlsb->lock);
	return 0;
err:
	return -EFAULT;
}
int comp_wlsb_add(struct comp_win_lsb *wlsb,struct sk_buff *skb ,u32 sn,u32 val)
{
	struct win_entry *w_entry;
	struct sk_buff *free_skb;
	u16 index = wlsb->win_index;
	w_entry = &wlsb->w_entrys[index];
	w_entry->sn = sn;
	w_entry->val = val;
	spin_lock(&wlsb->lock);
	if(wlsb->w_len >= wlsb->win_size){
		//spin_lock();
		clear_bit(ENTRY_STATE_BUSY , &w_entry->state);
		if(w_entry->skb){
			dev_kfree_skb_any(w_entry->skb);
			w_entry->skb = NULL;
		}
		wlsb->w_len--;
	}
	if(skb)
		w_entry->skb = skb;
	set_bit(ENTRY_STATE_BUSY , &w_entry->state);
	wlsb->w_len++;
	spin_unlock(&wlsb->lock);
	//printk(KERN_DEBUG "%s : w_len=%d\n",__func__,wlsb->w_len);
	if(wlsb->win_size)
		wlsb->win_index = (wlsb->win_index + 1) % wlsb->win_size;
	else
		printk(KERN_DEBUG "wlsb win_size = %d,msn=%d\n",wlsb->win_size,sn);
	return 0;
}

static inline void comp_wlsb_free_entry(struct win_entry *wentry)
{
	if(wentry->skb)
		dev_kfree_skb_any(wentry->skb);
	wentry->skb = NULL;
	clear_bit(ENTRY_STATE_BUSY,&wentry->state);
}
int comp_wlsb_ack(struct comp_win_lsb *wlsb,u32 sn_bits,u32 sn_val)
{
	u32 sn_mask,sn_ack,sn;
	int i,j;
	int acked_num;
	bool acked = false;
	bool acked_end = false;
	int index;
	struct win_entry *w_entry;
	struct sk_buff *skb;
	if(sn_bits < 32)
		sn_mask = 1 << sn_bits - 1;
	else
		sn_mask = -1;
	acked_num = 0;
	spin_lock(&wlsb->lock);
	index = COMP_WLSB_NEXT_ENTRY_DOWN(wlsb->win_index,wlsb);
	for(i = 0 ; i < wlsb->w_len ; i++){
		w_entry = &wlsb->w_entrys[index];
		if(((w_entry->sn & sn_mask) == sn_val) && test_bit(ENTRY_STATE_BUSY,&w_entry->state)){
			sn_ack = w_entry->sn;
			acked = true;
			acked_num++;
			comp_wlsb_free_entry(w_entry);
			wlsb->w_len--;
			index = COMP_WLSB_NEXT_ENTRY_DOWN(index,wlsb);
			break;
		}
		index = COMP_WLSB_NEXT_ENTRY_DOWN(index,wlsb);
	}
	if(acked){
		for(i = 0 ; i < wlsb->w_len ; i++){
			w_entry = &wlsb->w_entrys[index];
			if(test_bit(ENTRY_STATE_BUSY , &w_entry->state)){
				sn = w_entry->sn;
				switch(wlsb->sn_type_size){
					case TYPE_UCHAR:
						if(before8(sn,sn_ack)){
							comp_wlsb_free_entry(w_entry);
							wlsb->w_len--;
							acked_num++;
						}else
							acked_end = true;
						break;
					case TYPE_USHORT:
						if(before16(sn,sn_ack)){
							comp_wlsb_free_entry(w_entry);
							wlsb->w_len--;
							acked_num++;
						}else
							acked_end = true;
						break;
					case TYPE_UINT:
						if(before32(sn,sn_ack)){
							comp_wlsb_free_entry(w_entry);
							wlsb->w_len--;
							acked_num++;
						}else
							acked_end = true;
						break;
				}
			}
			if(acked_end)
				break;
			index = COMP_WLSB_NEXT_ENTRY_DOWN(index,wlsb);
		}
	}
	spin_unlock(&wlsb->lock);
	return acked_num; 
}


int comp_wlsb_find_min_and_max(struct comp_win_lsb *wlsb,u8 *v_min,u8 *v_max)
{
	int retval;
	int index;
	int i;
	u32 min,max;
	struct win_entry *wentry;
	if(!wlsb->w_len){
		retval = -ENOENT;
		goto out;
	}
	index = COMP_WLSB_NEXT_ENTRY_DOWN(wlsb->win_index,wlsb);
	wentry = &wlsb->w_entrys[index];
	min = max = wentry->val;
	for(i = 0 ; i < wlsb->w_len;i++){
		wentry = &wlsb->w_entrys[index];
		if(min > wentry->val)
			min = wentry->val;
		if(max  < wentry->val)
			max = wentry->val;
		index = COMP_WLSB_NEXT_ENTRY_DOWN(index,wlsb);
	}
	retval = 0;
	memcpy(v_min , &min,wlsb->val_type_size);
	memcpy(v_max,&max,wlsb->val_type_size);
out:
	return retval;
}

int comp_wlsb_cal_k(struct comp_win_lsb *wlsb,u32 val)
{
	u16 val_type_size;
	u32 ref_max,ref_min;
	int retval;
	int high_bits,i;
	u32 high_bit;
	int k_min;
	int k_max;
	u32 mask,shift_v;
	struct win_entry *last_update_val;
	u32 wrap_around_diff;
	int val_type_bits;
	k_min = 0;
	k_max = 0;
	if(!wlsb->w_len){
		retval = -ENOENT;
		goto out;
	}
	comp_wlsb_find_min_and_max(wlsb,&ref_min,&ref_max);
	last_update_val = &wlsb->w_entrys[COMP_WLSB_NEXT_ENTRY_DOWN(wlsb->win_index,wlsb)];
	switch(wlsb->val_type_size){
		case TYPE_UCHAR:
			high_bit = 1 << 7;
			if(before8(val,ref_min) || after8(val,ref_max)){
				retval = EFAULT;
			}else{
				/*adjust ref_min wrap around  ref_max
				 *
				 */
				if(before8(ref_max,ref_min)){
					/*here is wrap around.ref_min = 0.
					 */
					if((val < ref_max) && before8(ref_max,val)){//val wrap around
						for(i = 0 ,mask = 1 << i; i < 8 ; i++,mask |= 1 << i){
							k_min++;
							if((ref_min & ~mask) == (val & ~mask))
								break;
						}
						if(!val)
							k_max = 1;
						else{
							wrap_around_diff = (unsigned char)(val - ref_max);
							//k_max = 1;
							for(i = 0,mask = 1 << i;i < 8 ;i++,mask |= 1 << i){
								k_max++;
								shift_v = val >> k_max;
								if(shift_v && ((unsigned char)(ref_max & mask + mask + 1) >= val))
										break;
							}
						}
					}else {
						high_bits = 0;
						for(i = 7,mask = 1 << i;i >= 0; i++,mask |= 1 << i ){
							if((val & mask) != (ref_max & mask))
								break;
							else
								high_bits++;
						}
						k_max = 8 - high_bits;
					}
				}else{
					for(i = 0 ,mask = 1 << i; i < 8 ; i++,mask |= 1 << i){
						k_min++;
						if((val & mask) == (ref_min & mask))
							break;
					}
					for(i = 0 ,mask = 1 << i ;i < 8 ; i++ ,mask |= 1 << i){
						k_max++;
						if(val & mask == ref_max & mask)
							break;
					}

				}
			}
			break;
		case TYPE_USHORT:
			break;
		case TYPE_UINT:
			break;
	}
out:
	return retval;
}

bool comp_wlsb_can_encode_type_uchar(struct comp_win_lsb *wlsb,int k,int p,u32 val)
{
	int i,index,win_len;
	u32 ref,ref_min,ref_max;
	u8 mask;

	struct win_entry *entry;
	bool can_encode = true;
	mask = (1 << k) - 1;
	win_len = wlsb->w_len;
	if(!wlsb->w_len){
		/**
		 *don't have reference in the windows
		 */
		can_encode = false;
		goto out;
	}
	index = COMP_WLSB_NEXT_ENTRY_DOWN(wlsb->win_index,wlsb);

	for(i = 0 ; i < wlsb->w_len ;i++){
		entry = &wlsb->w_entrys[index];
		ref = entry->val;
		ref_max = ref + mask - p;
		ref_min = ref - p;
		if(before8(val,ref_min) || after8(val,ref_max)){
			can_encode = false;
			break;
		}
		index = COMP_WLSB_NEXT_ENTRY_DOWN(index,wlsb);
	}
out:
	return can_encode;
}
bool comp_wlsb_can_encode_type_ushort(struct comp_win_lsb *wlsb,int k,int p,u32 val)
{
	int i,index,win_len;
	u32 ref,ref_min,ref_max;
	u16 mask;

	struct win_entry *entry;
	bool can_encode = true;
	mask = (1 << k) - 1;
	win_len = wlsb->w_len;
	if(!wlsb->w_len){
		/**
		 *don't have reference in the windows
		 */
		can_encode = false;
		goto out;
	}
	index = COMP_WLSB_NEXT_ENTRY_DOWN(wlsb->win_index,wlsb);
	//printk(KERN_DEBUG "%s : wlen = %d,win_size = %d\n",__func__,wlsb->w_len,wlsb->win_size);
	for(i = 0 ; i < wlsb->w_len ;i++){
		entry = &wlsb->w_entrys[index];
		ref = entry->val;
		ref_max = ref + mask - p;
		ref_min = ref - p;
		//if(p == 4)
		//	rohc_pr(ROHC_DTCP,"i=%d,val=%d,ref=%d,ref_max=%d,ref_min=%d\n",i,val,ref,ref_max,ref_min);
		if(before16(val,ref_min) || after16(val,ref_max)){
			can_encode = false;
			break;
		}
		index = COMP_WLSB_NEXT_ENTRY_DOWN(index,wlsb);
	}
out:
	return can_encode;
}

bool comp_wlsb_can_encode_type_uint(struct comp_win_lsb *wlsb,int k,int p,u32 val)
{
	int i,index,win_len;
	u32 ref,ref_min,ref_max;
	u32 mask;

	struct win_entry *entry;
	bool can_encode = true;
	mask = (1 << k) - 1;
	win_len = wlsb->w_len;
	if(!wlsb->w_len){
		/**
		 *don't have reference in the windows
		 */
		can_encode = false;
		goto out;
	}
	index = COMP_WLSB_NEXT_ENTRY_DOWN(wlsb->win_index,wlsb);

	for(i = 0 ; i < wlsb->w_len ;i++){
		entry = &wlsb->w_entrys[index];
		ref = entry->val;
		ref_max = ref + mask - p;
		ref_min = ref - p;
		if(before32(val,ref_min) || after32(val,ref_max)){
			can_encode = false;
			break;
		}
		index = COMP_WLSB_NEXT_ENTRY_DOWN(index,wlsb);
	}
out:
	return can_encode;
}

int comp_wlsb_cal_appear_rate(struct comp_win_lsb *wlsb,u32 val)
{
	struct win_entry *entry;
	int i,wlen,rate,index;
	int appear_num = 0;
	wlen = wlsb->w_len;
	if(!wlen){
		rate = 100;
		goto out;
	}
	index = COMP_WLSB_NEXT_ENTRY_DOWN(wlsb->win_index,wlsb);
	for(i = 0 ; i < wlen ;i++){
		entry = &wlsb->w_entrys[index];
		if(entry->val == val)
			appear_num++;
		index = COMP_WLSB_NEXT_ENTRY_DOWN(index,wlsb);
	}
	rate = (appear_num * 100) / wlsb->win_size;
out:
	return rate;
}
static int __init rohc_comp_wlsb_init(void)
{
	wlsb_cache = kmem_cache_create("rohc_comp_wlsb_cache",sizeof(struct comp_win_lsb),0,SLAB_HWCACHE_ALIGN,NULL);
	wentry_cache = kmem_cache_create("rohc_comp_wlsb_entry_cache",sizeof(struct win_entry),0,SLAB_HWCACHE_ALIGN,NULL);
}
module_init(rohc_comp_wlsb_init);

