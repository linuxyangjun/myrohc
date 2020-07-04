#ifndef	D__ROHC_RB_H
#define	D__ROHC_RB_H

#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include "rohc_common.h"
struct rohc_rb_root{
	char name[ROHC_NAME_LEN];
	struct rb_root  root;
	spinlock_t	lock;
};

struct rohc_rb_node{
	u16 key;
	struct rb_node rohc_rb;
};

void rohc_rb_root_init(struct rohc_rb_root *root);
int rohc_rb_insert(struct rohc_rb_root *rb_root,struct rohc_rb_node *rb_node);
struct rohc_rb_node *rohc_rb_find(struct rohc_rb_root *rb_root,u16 key);
void rohc_rb_del(struct rohc_rb_root *rb_root,struct rohc_rb_node *rohc_node);

#endif
