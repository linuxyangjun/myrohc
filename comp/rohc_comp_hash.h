#ifndef	D__ROHC_COMP_HASH_H
#define	D__ROHC_COMP_HASH_H

#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/spinlock.h>

//#include "rohc_comp_ipv4_hash.h"
struct rohc_compresser;
struct rohc_comp_context;


struct rohc_comp_context_hnode{
	struct hlist_node list;

	void  *match_data;
	//union{
	//	struct ipv4_hash_match match_data;
	//};
};

struct rohc_comp_context_chain{
	struct hlist_head	list_head;
	spinlock_t		lock;
};
struct	rohc_comp_context_hash{
#define		MAX_HASH_CTEXTS			64
	struct rohc_comp_context_chain	hashs[MAX_HASH_CTEXTS];
	u32	hash_rnd;
	int	(*init)(struct rohc_comp_context_hash *c_hash,struct rohc_comp_context_hnode *hnode,struct sk_buff *skb);
	u32	(*hash_key)(struct rohc_comp_context_hash *c_hash,struct rohc_comp_context_hnode *hnode);
	bool	(*match)(struct rohc_comp_context_hash *c_hash,struct rohc_comp_context_hnode *hnode,void *arg);
	struct rohc_comp_context_hnode *(*context_find)(struct rohc_comp_context_hash *c_hash,struct sk_buff *skb);

};



int rohc_comp_context_hash_init(struct rohc_compresser *comp);
struct rohc_comp_context_hnode *rohc_comp_context_hash_find(struct rohc_comp_context_hash *c_hash,const struct sk_buff *skb);
struct rohc_comp_context_hnode *rohc_comp_hnode_find(struct rohc_comp_context_hash *c_hash,u32 hash_key,void *match_data);
int rohc_comp_context_hash_insert(struct rohc_comp_context_hash *c_hash,struct rohc_comp_context_hnode *new_hnode,struct sk_buff *skb);
#endif
