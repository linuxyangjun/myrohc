#ifndef	D__ROHC_DECOMP_K_OUT_N__H
#define	D__ROHC_DECOMP_K_OUT_N__H
#include <linux/types.h>

struct sn_cache{
	bool not_stale;
	u32 sn;
};
struct	downward_k{
	u16	max_k;
	u16	idx;
	struct sn_cache *sn_cache;;

};

struct upward_k{
	u16	max_k;
	u16	idx;

	struct sn_cache *sn_cache;
};

struct downward_n{
	u32 n;
};

struct upward_n{
	u16 n;
	u32 base_sn;
};

struct downward_kn{
	u32 sn;
	struct downward_k dk;
	struct downward_n dn;
};

struct upward_kn{
	u32 sn;
	struct upward_k uk;
	struct upward_n un;
};
int rohc_decomp_downward_kn_init(struct downward_kn *kn ,u32 k, int n);
void rohc_decomp_downward_kn_reset(struct downward_kn *kn);
void rohc_decomp_downward_kn_set(struct downward_kn *kn,u32 sn_set);
bool rohc_decomp_downward_is_k_out_n(struct downward_kn *kn);

void rohc_decomp_upward_kn_reset(struct upward_kn *kn);
#endif
