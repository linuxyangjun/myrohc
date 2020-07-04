#ifndef	D__ROHC_IPID_H
#define	D__ROHC_IPID_H

enum ip_id_behavior{
	IP_ID_BEHAVIOR_SEQ_NBO,
	IP_ID_BEHAVIOR_SEQ_SWAP,
	IP_ID_BEHAVIOR_RANDOM,
	IP_ID_BEHAVIOR_ZERO,
	IP_ID_BEHAVIOR_CONSTANT,
};

static inline bool ip_id_is_nbo(enum ip_id_behavior bh)
{
	return (bh != IP_ID_BEHAVIOR_SEQ_SWAP);
}
static inline bool ip_id_is_random(enum ip_id_behavior bh)
{
	return bh == IP_ID_BEHAVIOR_RANDOM;
}

static inline bool ip_id_is_constant(enum ip_id_behavior bh)
{
	return bh == IP_ID_BEHAVIOR_CONSTANT;
}

static inline bool ip_id_is_zero(enum ip_id_behavior bh)
{
	return bh == IP_ID_BEHAVIOR_ZERO;
}
static inline bool ip_id_is_random_or_constant(enum ip_id_behavior bh)
{
	return (ip_id_is_random(bh) || ip_id_is_constant(bh));
}

static inline bool ip_id_is_random_or_zero(enum ip_id_behavior bh)
{
	return (ip_id_is_random(bh) || ip_id_is_zero(bh));
}
static inline bool ip_id_mon_increasing(u16 new_id,u16 old_id,u16 dela)
{
	bool retval = false;
	u16 max_id = old_id + dela;
	if(after16(new_id , old_id) && before16(new_id,max_id))
		retval = true;
	return retval;
}

static inline void __ip_id_behavior_probe(u16 new_ipid,u16 old_ipid,enum ip_id_behavior *ipid_bh,bool can_seq)
{
	if(new_ipid == 0 && new_ipid == old_ipid){
		*ipid_bh = IP_ID_BEHAVIOR_ZERO;
	}else if(!can_seq)
		*ipid_bh = IP_ID_BEHAVIOR_RANDOM;
	else if(ip_id_mon_increasing(new_ipid,old_ipid,20))
		*ipid_bh = IP_ID_BEHAVIOR_SEQ_NBO;
	else{
		new_ipid = __swab16(new_ipid);
		old_ipid = __swab16(old_ipid);
		if(ip_id_mon_increasing(new_ipid,old_ipid,20))
			*ipid_bh = IP_ID_BEHAVIOR_SEQ_SWAP;
		else
			*ipid_bh = IP_ID_BEHAVIOR_RANDOM;
	}
}
/*the packet out of order or loss*/
static inline void ip_id_behavior_probe_under_msn_offset(u16 new_ipid,u16 old_ipid,enum ip_id_behavior *ipid_bh,u32 msn_off,bool can_seq)
{

	u16 previous_id;
	previous_id = old_ipid + msn_off - 1;
	if(new_ipid == 0 && new_ipid == old_ipid){
		*ipid_bh = IP_ID_BEHAVIOR_ZERO;
	}else if(!can_seq)
		*ipid_bh = IP_ID_BEHAVIOR_RANDOM;
	else if(ip_id_mon_increasing(new_ipid,previous_id,20))
		*ipid_bh = IP_ID_BEHAVIOR_SEQ_NBO;
	else{
		new_ipid = __swab16(new_ipid);
		previous_id = __swab16(previous_id);
		if(ip_id_mon_increasing(new_ipid,previous_id,20))
			*ipid_bh = IP_ID_BEHAVIOR_SEQ_SWAP;
		else
			*ipid_bh = IP_ID_BEHAVIOR_RANDOM;
	}

}
#endif
