#ifndef D__ROHC_V2_PROFILE_H
#define	D__ROHC_V2_PROFILE_H

#include "rtp_profile.h"
#define	IPH_FIELD_TTL_HL	1
#define	IPH_FIELD_TOS_TC	2
#define	IPH_FIELD_DF		3
#define	IPH_FIELD_IPID_BH	4
#define	IPH_FIELD_IPID_OFF	5

#define	UDP_CHECK_NONE		1
#define	UDP_CHECK_SUM		2


#define	SDVL_LSB_TYPE_0		0x0
#define	SDVL_LSB_TYPE_1		0x2
#define	SDVL_LSB_TYPE_2		0x6
#define	SDVL_LSB_TYPE_3		0xe
#define	SDVL_LSB_TYPE_4		0xff
/*define for reordering offset*/
enum rohc_v2_reordering_ratio{
	REORDER_R_NONE,
	REORDER_R_QUARTER,
	REORDER_R_HALF,
	REORDER_R_THREEQUARTERS,
};


static inline int rohc_v2_msn_k_to_p_under_rr(enum rohc_v2_reordering_ratio rr,int k)
{

	int p;
	switch(rr){
		case REORDER_R_NONE:
			p = 1;
			break;
		case REORDER_R_QUARTER:
			p = (1 << (k - 2)) - 1;
			break;
		case REORDER_R_HALF:
			p = (1 << (k - 1)) - 1;
			break;
		case REORDER_R_THREEQUARTERS:
			p = (((1 << k) * 3) / 4) - 1;
			break;
		default:
			p = 1;

	}
	return p;
}


static inline void rohc_v2_ip_header_dump(struct sk_buff *skb,int cid,u32 msn,bool is_comp)
{
	struct iphdr *iph;
	struct udphdr *udph;
	u8 *addr,*pre_name;
	iph = ip_hdr(skb);
	if(is_comp)
		pre_name = "COMP_IP";
	else
		pre_name = "DECOMP_IP";

	rohc_pr(ROHC_DIP2,"%s : cid : %d msn:%d,data_len=%d\n",pre_name,cid,msn,skb->len);
	rohc_pr(ROHC_DIP2,"ipid=%d,id_off_msn=%u,tos=%d,ttl=%d,iphl=%d,tot_len=%d,fragof=%x,check=%x,procotol=%d\n",ntohs(iph->id),ntohs(iph->id) - msn,iph->tos,iph->ttl,iph->ihl,ntohs(iph->tot_len),iph->frag_off,iph->check,iph->protocol);
	addr = (u8 *)&iph->saddr;
	rohc_pr(ROHC_DIP2,"ipsrc:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	addr = (u8 *)&iph->daddr;
	rohc_pr(ROHC_DIP2,"ipdst:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));

}
static inline void rohc_v2_net_header_dump(struct sk_buff *skb,int cid,u32 msn)
{
	struct iphdr *iph;
	struct udphdr *udph;
	u8 *addr;
	iph = ip_hdr(skb);
	rohc_pr(ROHC_DUDP2,"cid : %d msn:%d,data_len=%d\n",cid,msn,skb->len);
	rohc_pr(ROHC_DUDP2,"ipid=%d,id_off_msn=%u,tos=%d,ttl=%d,iphl=%d,tot_len=%d,fragof=%x,check=%x\n",ntohs(iph->id),ntohs(iph->id) - msn,iph->tos,iph->ttl,iph->ihl,ntohs(iph->tot_len),iph->frag_off,iph->check);
	addr = (u8 *)&iph->saddr;
	rohc_pr(ROHC_DUDP2,"ipsrc:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	addr = (u8 *)&iph->daddr;
	rohc_pr(ROHC_DUDP2,"ipdst:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	udph = (struct udphdr *)(iph + 1);
	rohc_pr(ROHC_DUDP2,"sport=%d,dport=%d,len=%d,udpcheck=%x\n",ntohs(udph->source),ntohs(udph->dest),ntohs(udph->len),udph->check);

}
static inline void rohc_v2_rtp_net_header_dump(struct sk_buff *skb,int cid,u32 msn,bool is_comp)
{
	struct iphdr *iph;
	struct rtphdr *rtph;
	struct udphdr *udph;
	u8 *addr;
	char *pre_name;
	iph = ip_hdr(skb);
	if(is_comp)
		pre_name = "COMP_RTP";
	else
		pre_name = "DECOMP_RTP";
	rohc_pr(ROHC_DRTP2,"[%s]cid : %d msn:%d,data_len=%d\n",pre_name,cid,msn,skb->len);
	rohc_pr(ROHC_DRTP2,"ipid=%d,id_off_msn=%u,tos=%d,ttl=%d,iphl=%d,tot_len=%d,fragof=%x,check=%x\n",ntohs(iph->id),ntohs(iph->id) - msn,iph->tos,iph->ttl,iph->ihl,ntohs(iph->tot_len),iph->frag_off,iph->check);
	addr = (u8 *)&iph->saddr;
	rohc_pr(ROHC_DRTP2,"ipsrc:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	addr = (u8 *)&iph->daddr;
	rohc_pr(ROHC_DRTP2,"ipdst:%d.%d.%d.%d\n",*addr,*(addr + 1),*(addr +2),*(addr+3));
	udph = (struct udphdr *)(iph + 1);
	rohc_pr(ROHC_DRTP2,"sport=%d,dport=%d,len=%d,udpcheck=%x\n",ntohs(udph->source),ntohs(udph->dest),ntohs(udph->len),udph->check);
	rtph = (struct rtphdr *)(udph + 1);
	rohc_pr(ROHC_DRTP2,"rtph_cc:%d,x:%d,p:%d,v:%d,m%d,pt:%d,seq:%d,ts:%lu,ssrc=%08x",rtph->cc,rtph->x,rtph->p,rtph->version,rtph->m,rtph->pt,ntohs(rtph->seq),ntohl(rtph->ts),rtph->ssrc);
	if(rtph->cc){
		u32 *ssrc;
		int i;
		for(i = 0 ; i < rtph->cc;i++){
			ssrc = (u32 *)(rtph+ 1);
			rohc_pr(ROHC_DRTP2,"[%d] : %x\n",i,*ssrc);
			ssrc++;
		}
	}
}
#endif
