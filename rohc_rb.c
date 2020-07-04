/**
 *author : yangjun
 *date : 
 *
 */

#include <linux/spinlock.h>
#include "rohc_rb.h"

int rohc_rb_insert(struct rohc_rb_root *rb_root,struct rohc_rb_node *rb_node)
{
	int retval;
	u16 key;
	struct rb_node *parent,**child;
	struct rohc_rb_node *rohc_node;
	child = &rb_root->root.rb_node;
	key = rb_node->key;
	parent = NULL;
	spin_lock(&rb_root->lock);
	while(*child){
		parent = *child;
		rohc_node = rb_entry(parent,struct rohc_rb_node,rohc_rb);
		if(key < rohc_node->key)
			child = &parent->rb_left;
		else if(key > rohc_node->key)
			child = &parent->rb_right;
		else{
			pr_err("rb node has be exit int rb root %s\n",rb_root->name);
			BUG();
		}
	}
	rb_link_node(&rb_node->rohc_rb,parent,child);
	rb_insert_color(&rb_node->rohc_rb,&rb_root->root);
	spin_unlock(&rb_root->lock);
}


struct rohc_rb_node *rohc_rb_find(struct rohc_rb_root *rb_root,u16 key)
{
	struct rb_node *child;
	struct rohc_rb_node *rohc_node;
	child = rb_root->root.rb_node;
	while(child){
		rohc_node = rb_entry(child,struct rohc_rb_node,rohc_rb);
		if(key < rohc_node->key)
			child = child->rb_left;
		else if(key > rohc_node->key)
			child = child->rb_right;
		else
			break;
	}
	if(child)
		rohc_node = rb_entry(child,struct rohc_rb_node,rohc_rb);
	else 
		rohc_node = NULL;
	return rohc_node;
}

void rohc_rb_del(struct rohc_rb_root *rb_root,struct rohc_rb_node *rohc_node)
{
	rb_erase(&rohc_node->rohc_rb,&rb_root->root);
}


void rohc_rb_root_init(struct rohc_rb_root *root)
{
	root->root = RB_ROOT;
	spin_lock_init(&root->lock);
}
