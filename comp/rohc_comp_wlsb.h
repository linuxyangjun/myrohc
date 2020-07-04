#ifndef	D__COMP_WLSB_H
#define	D__COMP_WLSB_H
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/types.h>
struct win_entry{
	u32 sn;
	u32 val;
	struct sk_buff *skb;
	unsigned long	state;
#define	ENTRY_STATE_FREE	0
#define	ENTRY_STATE_BUSY	1
	spinlock_t	lock;
};
struct comp_win_lsb{
	u16 win_size;
	u16  win_index;
	int w_len;
	u16 last_irdyn_index;
	u16 sn_type_size;
	u16 val_type_size;
	//struct sk_buff_head win_queue;
	spinlock_t	lock;
	struct win_entry *w_entrys;
};

struct skb_win_entry_info{
	u32 sn;
	u16 index;
};

#define	COMP_WLSB_NEXT_ENTRY_DOWN(i,wlsb)	((i) > 0 ? (i - 1) : ((wlsb)->win_size - 1))
#define	SKB_WIN_ENTRY_INFO(skb) ((struct skb_win_entry_info *)skb->cb)


static inline int rohc_comp_wlsb_peek_last_val(struct comp_win_lsb *wlsb,u32 *val)
{
	struct win_entry *entry;
	u32 ref;
	int idx;
	int retval = 0;
	if(!wlsb->w_len){
		retval = -ENODEV;
		goto out;
	}
	idx = COMP_WLSB_NEXT_ENTRY_DOWN(wlsb->win_index,wlsb);
	entry = &wlsb->w_entrys[idx];
	ref = entry->val;
	*val = ref;
out:
	return retval;
}

int comp_wlsb_ack(struct comp_win_lsb *wlsb,u32 sn_bits,u32 sn_val);
int comp_wlsb_add(struct comp_win_lsb *wlsb,struct sk_buff *skb ,u32 sn,u32 val);
struct comp_win_lsb *comp_wlsb_alloc(int win_size,u8 sn_type_size ,u8 val_type_size,gfp_t flags);

bool comp_wlsb_can_encode_type_ushort(struct comp_win_lsb *wlsb,int k,int p,u32 val);
bool comp_wlsb_can_encode_type_uchar(struct comp_win_lsb *wlsb,int k,int p,u32 val);
bool comp_wlsb_can_encode_type_uint(struct comp_win_lsb *wlsb,int k,int p,u32 val);


int comp_wlsb_init(struct comp_win_lsb *wlsb,int win_size,u8 sn_type_size ,u8 val_type_size);
void comp_wlsb_destroy(struct comp_win_lsb *wlsb);
int comp_wlsb_cal_appear_rate(struct comp_win_lsb *wlsb,u32 val);
#endif
