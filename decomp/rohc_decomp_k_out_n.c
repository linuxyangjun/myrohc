/**
 *author : yangjun
 *date : 17/10/19
 */

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include "../rohc_common.h"
#include "rohc_decomp_k_out_n.h"

int rohc_decomp_downward_kn_init(struct downward_kn *kn ,u32 k, int n)
{
	int retval = 0;
	kn->sn = 0;
	kn->dk.max_k = k;
	kn->dn.n = n;
	kn->dk.sn_cache = kcalloc(k,sizeof(struct sn_cache),GFP_ATOMIC);
	if(!kn->dk.sn_cache){
		pr_err("%s : alloc sn cache fail\n",__func__);
		retval = -ENOMEM;
	}
	kn->dk.idx = 0;
	return retval;
}


void rohc_decomp_downward_kn_reset(struct downward_kn *kn)
{
	kn->sn = 0;
	memset(kn->dk.sn_cache,0,sizeof(struct sn_cache) * kn->dk.max_k);

}

void rohc_decomp_downward_kn_set(struct downward_kn *kn,u32 sn_set)
{
	struct downward_k *dk;
	struct sn_cache *sn_cache;
	dk = &kn->dk;
	sn_cache = &dk->sn_cache[dk->idx];
	sn_cache->sn = sn_set;
	sn_cache->not_stale = true;
	dk->idx = (dk->idx + 1) % dk->max_k;

}

/**
 *
 *
 * thie function can get the number of eligible in any range of monotonically increasing
 *
 *
 *
 */
bool rohc_decomp_downward_is_k_out_n(struct downward_kn *kn)
{
	int i;
	int num ;
	u32 low_sn,sn;
	struct sn_cache *sn_cached;
	struct downward_k *dk;
	dk = &kn->dk;
	bool retval = false;
	num = 0;
	low_sn =  kn->sn - kn->dn.n;
	for(i = 0 ; i < kn->dn.n ;i++){
		sn_cached = &dk->sn_cache[i];
		if(sn_cached->not_stale){
			sn = sn_cached->sn;
			if(after32(sn,low_sn) && before32_eq(sn,kn->sn))
				num++;
			else{
				sn_cached->not_stale = false;
				sn_cached->sn = 0;
			}
		}
	}
	if(num >= dk->max_k)
		retval = true;
	return retval;
}

int rohc_decomp_upward_kn_init(struct upward_kn *kn ,int k,int n)
{
	int retval = 0;
	kn->sn = 0;
	kn->uk.max_k = k;
	kn->un.n = n;
	kn->uk.sn_cache = kcalloc(k,sizeof(struct sn_cache),GFP_KERNEL);
	if(!kn->uk.sn_cache){
		pr_err("%s : alloc sn cache fail\n",__func__);
		retval = -ENOMEM;
	}
	kn->uk.idx = 0;
}

void rohc_decomp_upward_kn_set(struct upward_kn *kn ,u32 sn)
{
	struct sn_cache *sn_cached;
	struct upward_k *uk;
	uk = &kn->uk;
	sn_cached = &uk->sn_cache[uk->idx];
	uk->idx = (uk->idx + 1) % uk->max_k;
	sn_cached->sn = sn;
	sn_cached->not_stale = true;
}
void rohc_decomp_upward_kn_reset(struct upward_kn *kn)
{
	kn->sn = 0;
	memset(kn->uk.sn_cache,0,sizeof(struct sn_cache) * kn->uk.max_k);
}

bool rohc_decomp_upward_is_k_out_n(struct upward_kn *kn)
{
	bool retval = false;
	int i;
	int num;
	u32 high_sn,sn;
	struct upward_k *uk;
	struct sn_cache *sn_cached;
	num = 0;
	high_sn = kn->un.base_sn + kn->un.n;
	if(after32(high_sn,kn->sn))
		high_sn = kn->sn;
	else 
		rohc_decomp_upward_kn_reset(kn);
	for(i = 0 ; i < kn->un.n;i++){
		sn_cached = &kn->uk.sn_cache[i];
		if(sn_cached->not_stale){
			sn = sn_cached->sn;
			if(after32_eq(sn,kn->un.base_sn) && before32(sn,high_sn)){
				num++;
			}else{
				sn_cached->sn = 0;
				sn_cached->not_stale = false;
			}
		}
	}
	if(num >= kn->uk.max_k)
		retval = true;
	return retval;
}
