
/**
 *author : yangjun
 *date : 
 *
 */
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include "rohc_comp_ipv4_hash.h"
#include "rohc_comp_hash.h"

#include "rohc_comp.h"
struct rohc_comp_context_hnode *rohc_comp_hnode_find(struct rohc_comp_context_hash *c_hash,u32 hash_key,void *match_data)
{
	bool	found = false;
	struct rohc_comp_context_chain *h_head;
	struct rohc_comp_context_hnode *tmp_node,*hnode = NULL;
	struct hlist_node *n;
	h_head = &c_hash->hashs[hash_key & (MAX_HASH_CTEXTS - 1)];
	spin_lock(&h_head->lock);
	hlist_for_each_entry(tmp_node,&h_head->list_head,list){
		if(c_hash->match(c_hash,tmp_node,match_data)){
			found = true;
			break;
		}
	}

	if(found)
		hnode = tmp_node;
	else 
		hnode = NULL;
	spin_unlock(&h_head->lock);
	return hnode;
}



struct rohc_comp_context_hnode *rohc_comp_context_hash_find(struct rohc_comp_context_hash *c_hash,const struct sk_buff *skb)
{
	struct rohc_comp_context_hnode *new_hnode;
	new_hnode = c_hash->context_find(c_hash,skb);
	return new_hnode;
}
int rohc_comp_context_hash_insert(struct rohc_comp_context_hash *c_hash,struct rohc_comp_context_hnode *hnode,struct sk_buff *skb)
{
	u32 hash_key;
	struct rohc_comp_context_hnode *tmp_node;
	struct rohc_comp_context_chain *h_head;
	c_hash->init(c_hash,hnode,skb);
	hash_key = c_hash->hash_key(c_hash,hnode);
	h_head = &c_hash->hashs[hash_key];
	spin_lock(&h_head->lock);
	hlist_for_each_entry(tmp_node,&h_head->list_head,list){
		if(c_hash->match(c_hash,tmp_node,hnode->match_data)){
			pr_err("%s : error to insert because exit");
			spin_unlock(&h_head->lock);
			return -EEXIST;
		}
	}
	hlist_add_head(&hnode->list,&h_head->list_head);
	spin_unlock(&h_head->lock);
	return 0;
}

void rohc_comp_context_hash_del(struct rohc_comp_context_hash *c_hash,struct rohc_comp_context_hnode *hash_node)
{
	u32 hash_key;
	struct rohc_comp_context_chain *h_head;
	hash_key = c_hash->hash_key(c_hash,hash_node);
	h_head = &c_hash->hashs[hash_key];
	spin_lock(&h_head->lock);
	hlist_del_init(&hash_node->list);
	spin_unlock(&h_head->lock);
}

int rohc_comp_context_hash_init(struct rohc_compresser *comp)
{
	/*
	 *
	 *TODO INIT (IPV4 and IPV6 hashs)
	 *
	 */
	rohc_comp_context_hash_ipv4_init(&comp->ipv4_hash);
}
