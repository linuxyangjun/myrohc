/**
 *author : yangjun
 *date   : 2019/10/9
 *
 *
 */
#include <linux/jhash.h>
#include "rohc_comp.h"
#include "rohc_comp_hash.h"
#include "rohc_comp_ipv4_hash.h"

#define	IPV4_HASH_KEY_LEN	5

struct kmem_cache *ipv4_hash_match_cache;
static u32 rohc_comp_ipv4_hash_func(struct rohc_comp_context_hash *c_hash,struct rohc_comp_context_hnode *hnode )
{
	u32 key[IPV4_HASH_KEY_LEN];
	struct ipv4_hash_match *match = (struct ipv4_hash_match *)hnode->match_data;
	key[0] = match->saddr;
	key[1] = match->daddr;
	key[2] = match->protocol;
	key[3] = match->src_port;
	key[4] = match->dst_port;
	return jhash2(key,IPV4_HASH_KEY_LEN,c_hash->hash_rnd) & (MAX_HASH_CTEXTS - 1 ); 
}

static int rohc_comp_ipv4_hash_init(struct rohc_comp_context_hash *c_hash,struct rohc_comp_context_hnode *hnode,struct sk_buff *skb)
{
	int protocol;
	int dst_port;
	int src_port;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct ipv4_hash_match *match;

	iph = ip_hdr(skb);
	//BUG_ON(!hnode->context);

	match= kmem_cache_alloc(ipv4_hash_match_cache,GFP_ATOMIC);//kmalloc(/*128*/sizeof(struct ipv4_hash_match),GFP_ATOMIC);
	if(!match){
		pr_err("%s : can't alloc ipv4_hash_match data \n",__func__);
		return -ENOMEM;
	}

	hnode->match_data = match;

retry:
	protocol = iph->protocol;
	
	switch(protocol){
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)(iph + 1);
			dst_port = tcph->dest;
			src_port = tcph->source;
			break;
	
		case IPPROTO_UDP:
			udph = (struct udphdr *)(iph + 1);
			dst_port = udph->dest;
			src_port = udph->source;
			break;
		case IPPROTO_IPIP:
			iph = (struct iphdr *)(iph + 1);
			goto retry;
			break;
		default:
			src_port = 0;
			dst_port = 0;
			break;
	}
	match->saddr = iph->saddr;

	match->daddr = iph->daddr;

	match->protocol = protocol;
	match->src_port = src_port;
	match->dst_port = dst_port;
	return 0;
}
static struct rohc_comp_context_hnode *rohc_comp_ipv4_hash_find(struct rohc_comp_context_hash *c_hash,struct sk_buff *skb)
{

	int protocol;
	int dst_port;
	int src_port;
	u32 hash;
	u32 key[IPV4_HASH_KEY_LEN];
	struct ipv4_hash_match match_data;
	struct rohc_comp_context *context;
	struct rohc_comp_context_hnode *hnode;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;
	struct iphdr *iph = ip_hdr(skb);


retry:

	protocol = iph->protocol;
	switch(protocol){
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)(iph + 1);
			dst_port = tcph->dest;
			src_port = tcph->source;
			break;
	
		case IPPROTO_UDP:
			udph = (struct udphdr *)(iph + 1);
			dst_port = udph->dest;
			src_port = udph->source;
			break;
		/*
		case IPPROTO_ICMP:
			icmph = (struct icmphdr *)(iph + 1);

			dst_port = icmph->type;
			src_port = icmph->code;
		*/
		case IPPROTO_IPIP:
			iph = (struct iphdr *)(iph + 1);
			goto retry;
			break;
		default:
			dst_port = 0;
			src_port = 0;
			break;
	}
	memcpy(&key[0],&iph->saddr,4);
	memcpy(&key[1],&iph->daddr,4);
	memcpy(&key[2],&protocol,4);
	memcpy(&key[3],&src_port,4);
	memcpy(&key[4],&dst_port,4);
	match_data.saddr = iph->saddr;
	match_data.daddr = iph->daddr;
	match_data.protocol = protocol;
	match_data.src_port = src_port;
	match_data.dst_port = dst_port;

	hash = jhash2(key,IPV4_HASH_KEY_LEN,c_hash->hash_rnd) & (MAX_HASH_CTEXTS - 1);
	hnode = rohc_comp_hnode_find(c_hash,hash,&match_data);
	return hnode;
}

static bool	rohc_comp_ipv4_hash_match(struct rohc_comp_context_hash *c_hash,struct rohc_comp_context_hnode *hnode,void *arg)
{
	struct ipv4_hash_match *match_arg;
	struct ipv4_hash_match *match_data = hnode->match_data;
	match_arg = (struct ipv4_hash_match *)arg;
	return (match_data->saddr == match_arg->saddr &&
		match_data->daddr == match_arg->daddr &&
		match_data->protocol == match_arg->protocol &&
		match_data->src_port == match_arg->src_port && 
		match_data->dst_port == match_arg->dst_port
			
			);
}

void rohc_comp_context_hash_ipv4_init(struct rohc_comp_context_hash *c_hash)
{
	int i;
	c_hash->init = rohc_comp_ipv4_hash_init;
	c_hash->hash_key = rohc_comp_ipv4_hash_func;
	c_hash->context_find = rohc_comp_ipv4_hash_find;
	c_hash->match = rohc_comp_ipv4_hash_match;
	get_random_bytes(&c_hash->hash_rnd,sizeof(u32));
	for(i = 0 ; i < MAX_HASH_CTEXTS ; i++){
		INIT_HLIST_HEAD(&c_hash->hashs[i].list_head);
		spin_lock_init(&c_hash->hashs[i].lock);
	}
	ipv4_hash_match_cache = kmem_cache_create("rohc_ipv4_hash_priv_data",sizeof(struct ipv4_hash_match),0,SLAB_HWCACHE_ALIGN,NULL);
	if(!ipv4_hash_match_cache)
		pr_err("%s : create ipv4 private match cached faild\n",__func__);

}

