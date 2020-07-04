/*
 *	rohc 
 *
 *
 *	Authors:
 *	yangjun		<1078522080@qq.com>
 *	date: 2020/5/21
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

static inline bool rtp_obtain_tsc(struct decomp_rtph_update *rtph_update,struct last_decomped_rth *rtph_ref)
{
	struct analyze_field *tsc;
	bool tsc_v;
	tsc = &rtph_update->analyze_fields.dynamic_fields.tsc;
	if(analyze_field_is_carryed(tsc))
		tsc_v = tsc.value;
	else
		tsc_v = rtph_ref->tsc;
	return tsc_v;
}

int decomp_rtp_analyze_uo1(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct wlsb_analyze_field *ts;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_rtp_context *d_rtp_context;
	struct decomp_rtph_context *rtp_context;
	struct decomp_rtph_update *rtph_update;
	struct last_decomped_rth *rtph_ref;
	struct rtph_dynamic_fields *new_rtph_dynamic;
	struct wlsb_analyze_field *msn_update;
	struct profile_rtp_uo1 *uo1;

	enum rohc_cid_type cid_type;
	bool analyze_full;
	int analyze_len = 0;
	int retval = 0;
	v1_context = (struct decomp_profile_v1_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_context *)v1_context->inherit_context;
	rtp_context = &d_rtp_context->rtp_context;

	rtph_update = &rtp_context->update_by_packet;
	rtph_ref = &rtp_context->rtph_ref;
	msn_update = &v1_context->msn_update;
	new_rtph_dynamic = &rtph_update->analyze_fields.dynamic_fields;
	if(rtp_obtain_tsc(rtph_update,rtph_ref))
		ts = &new_rtph_dynamic->ts_scaled;
	else
		ts = &new_rtph_dynamic->ts;
	
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	
	cid_type = context->decompresser->cid_type;
	if(cid_type == CID_TYPE_SMALL){
		uo1 = (struct profile_rtp_uo1 *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			uo1 = (struct profile_rtp_uo1 *)analyze_data;
		else
			uo1 = (struct profile_rtp_uo1 *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		/*field.1: 2bits type and 6 bits ts*/
		decomp_wlsb_fill_analyze_field(ts,uo1->ts,6,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	/*filed.2 : 1bit M and 4 bits SN ,3 bits crc*/
	
	decomp_fill_analyze_field(&new_rtph_dynamic->m,uo1->m);

	decomp_wlsb_fill_analyze_field(msn_update,uo1->sn,4,true);

	analyze_len += sizeof(struct profile_rtp_uo1) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int decomp_rtp_analyze_uo1_id(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_ip_context *ip_context;
	struct decomp_rtp_context *d_rtp_context;
	struct profile_rtp_uo1_id *uo1_id;

	struct wlsb_analyze_field *msn_update,*ipid;
	
	enum rohc_cid_type cid_type;

	bool analyze_full,x;
	int analyze_len = 0;
	int retval = 0;
	
	v1_context = (struct decomp_profile_v1_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_context *)v1_context->inherit_context;
	ip_context = &v1_context->ip_context;
	cid_type = context->decompresser->cid_type;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(cid_type == CID_TYPE_SMALL){
		uo1_id = (struct profile_rtp_uo1_id *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			uo1_id = (struct profile_rtp_uo1_id *)analyze_data;
		else
			uo1_id = (struct profile_rtp_uo1_id *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		ipid = ip_pick_high_priority_ipid(&ip_context->last_context_info,&ip_context->update_by_packet);
		decomp_wlsb_fill_analyze_field(ipid,uo1_id->ipid_off,5,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	x = uo1_id->x;

	msn_update = &v1_context->msn_update;

	decomp_wlsb_fill_analyze_field(msn_update,uo1_id->sn,4,true);

	analyze_len += sizeof(struct profile_rtp_uo1_id) - 1;
	if(x){
		pkt_info->decomped_hdr_len += analyze_len;
		analyze_len = 0;
		BUG_ON(!v1_context->prof_v1_ops->adjust_extension_type);
		retval = v1_context->prof_v1_ops->adjust_extension_type(context,skb,pkt_info);
		if(retval){
			rohc_pr(ROHC_DRTP,"profile-%x cid-%d adjust extension type failed when analyze Uo1-id packet\n",context->decomp_profile->profile,context->cid);
			retval = -EFAULT;
			goto out;
		}
		BUG_ON(!v1_context->prof_v1_ops->analyze_extension);
		retval = v1_context->prof_v1_ops->analyze_extension(context,skb,pkt_info);
		if(retval){
			rohc_pr(ROHC_DRTP,"profile-%x cid-%d analyze extension  failed when analyze uo1_id packet\n",context->decomp_profile->profile,context->cid);
			retval = -EFAULT;
			goto out;
		}
	}
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int decomp_rtp_analyze_uo1_ts(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_rtp_context *d_rtp_context;
	struct decomp_rtph_context *rtp_context;
	struct decomp_rtph_update *rtph_update;
	struct last_decomped_rth *rtph_ref;
	struct wlsb_analyze_field *msn_update,*ts;

	struct profile_rtp_uo1_ts *uo1_ts;
	
	enum rohc_cid_type cid_type;
	bool analyze_full,tsc;

	int analyze_len = 0;
	int retval = 0;

	v1_context = (struct decomp_profile_v1_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtph_context *)v1_context->inherit_context;

	rtp_context = &d_rtp_context->rtp_context;
	rtph_update = &rtp_context->update_by_packet;
	rtph_ref = &rtp_context->rtph_ref;
	cid_type = context->decompresser->cid_type;
	
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(cid_type == CID_TYPE_SMALL){
		uo1_ts = (struct profile_rtp_uo1_ts *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			uo1_ts = (struct profile_rtp_uo1_ts *)analyze_data;
		else
			uo1_ts = (struct profile_rtp_uo1_ts *)(analyze_data - 1);
		analyze_len = 1;
	}
	if(analyze_first){
		if(rtp_obtain_tsc(rtph_update,rtph_ref))
			ts = &rtph_update->analyze_fields.dynamic_fields.ts_scaled;
		else
			ts = &rtph_update->analyze_fields.dynamic_fields.ts;
		decomp_wlsb_fill_analyze_field(ts,uo1_ts->ts,5,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;

	decomp_fill_analyze_field(&rtph_update->analyze_fields.dynamic_fields.m,uo1_ts->m);

	msn_update = &v1_context->msn_update;
	decomp_wlsb_fill_analyze_field(msn_update,uo1_ts->sn,4,true);
	analyze_len += sizeof(struct profile_rtp_uo1_ts) - 1;
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;

}


int decomp_rtp_analyze_uor2(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_rtp_context *d_rtp_context;
	struct decomp_rtph_context *rtp_context;

	struct wlsb_analyze_field *ts,*msn_update;
	struct decomp_profile_v1_ops *prof_v1_ops;
	struct profile_rtp_uor2 *uor2;

	enum rohc_cid_type cid_type;
	bool analyze_full,is_carryed_ext;
	int analyze_len = 0;
	int retval = 0;

	v1_context = (struct decomp_profile_v1_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_context *)v1_context->inherit_context;

	rtp_context = &d_rtp_context->rtp_context;

	cid_type = context->decompresser->cid_type;

	analyze_data = skb->data  + pkt_info->decomped_hdr_len;
	if(rtp_obtain_tsc(&rtp_context->update_by_packet,&rtp_context->rtph_ref))
		ts = &rtp_context->update_by_packet.analyze_fields.dynamic_fields.ts_scaled;
	else
		ts = &rtp_context->update_by_packet.analyze_fields.dynamic_fields.ts;

	if(cid_type == CID_TYPE_SMALL){
		uor2 = (struct profile_rtp_uor2 *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			uor2 = (struct profile_rtp_uor2 *)analyze_data;
		else
			uor2 = (struct profile_rtp_uor2 *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		decomp_wlsb_fill_analyze_field(ts,uor2->ts0,5,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_wlsb_analyze_field_append_bits(ts,uor2->ts1,1,true);
	decomp_fill_analyze_field(&rtp_context->update_by_packet.analyze_fields.dynamic_fields.m,uor2->m);

	msn_update = &v1_context->msn_update;
	decomp_wlsb_fill_analyze_field(msn_update,uor2->sn,6,true);

	is_carryed_ext = !!uor2->x;
	analyze_len += sizeof(struct profile_rtp_uor2) - 1;

	if(is_carryed_ext){
		pkt_info->decomped_hdr_len += analyze_len;
		analyze_len = 0;
		prof_v1_ops = v1_context->prof_v1_ops;
		retval = prof_v1_ops->adjust_extension_type(context,skb,pkt_info);
		if(retval){
			rohc_pr(ROHC_DRTP,"profile rtp adjust ext type failed when analyze uor2\n");
			goto out;
		}
		retval = prof_v1_ops->analyze_extension(context,skb,pkt_info);
		if(retval)
			rohc_pr(ROHC_DRTP,"profile rtp analyze extension failed when analyze uor2\n");
	}
out:
	pkt_info->decomped_hdr_len += analyze_len;
}


int decomp_rtp_analyze_uor2_id(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_rtp_context *d_rtp_context;
	struct decomp_rtph_context *rtp_context;
	struct decomp_ip_context *ip_context;
	struct wlsb_analyze_field *msn_update,*ipid;
	struct profile_rtp_uor2_id *uor2_id;

	struct decomp_profile_v1_ops *prof_v1_ops;
	enum rohc_cid_type cid_type;

	bool analyze_full,is_carryed_ext;
	int analyze_len = 0;
	int retval = 0;

	v1_context = (struct decomp_profile_v1_context *)context->inherit_context;
	ip_context = &v1_context->ip_context;
	d_rtp_context = (struct decomp_rtp_context *)v1_context->inherit_context;
	rtp_context = &d_rtp_context->rtp_context;

	cid_type = context->decompresser->cid_type;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(cid_type == CID_TYPE_SMALL){
		uor2_id = (struct profile_rtp_uor2_id *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			uor2_id = (struct profile_rtp_uor2_id *)analyze_data;
		else
			uor2_id = (struct profile_rtp_uor2_id *)(analyze_data - 1);
		analyze_full = false;
	}

	if(analyze_first){
		ipid = ip_pick_high_priority_ipid(&ip_context->last_context_info,&ip_context->update_by_packet);
		decomp_wlsb_fill_analyze_field(ipid,uor2_id->ipid_off,5,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	is_carryed_ext = !!uor2_id->x;
	msn_update = &v1_context->msn_update;
	decomp_wlsb_fill_analyze_field(msn_update,uor2_id->sn,6,true);
	decomp_fill_analyze_field(&rtp_context->update_by_packet.analyze_fields.dynamic_fields.m,uor2_id->m);

	/*crc check*/
	analyze_len += sizeof(struct profile_rtp_uor2_id) - 1;

	if(is_carryed_ext){
		pkt_info->decomped_hdr_len += analyze_len;
		analyze_len = 0;
		prof_v1_ops = v1_context->prof_v1_ops;
		retval = prof_v1_ops->adjust_extension_type(context,skb,pkt_info);
		if(retval){
			rohc_pr(ROHC_DRTP,"profile  rtp cid-%d adjust ext type failed,when analyze uor2-id\n",context->cid);
			goto out;
		}
		retval = prof_v1_ops->analyze_extension(context,skb,pkt_info);
		if(retval)
			rohc_pr(ROHC_DRTP,"profile rtp cid-%d analyze extension failed when analyze uor2-id\n",context->cid);
	}
out:
	pkt_info->decomped_hdr_len += analyze_len;

}

int decomp_rtp_analyze_uor2_ts(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info,bool analyze_first)
{
	u8 *analyze_data;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_profile_v1_ops *prof_v1_ops;
	struct decomp_rtp_context *d_rtp_context;
	struct decomp_rtph_context *rtp_context;
	struct rtph_dynamic_fields *rtph_dynamic_fields;
	struct profile_rtp_uor2_ts *uor2_ts;
	struct wlsb_analyze_field *ts,*msn_update;

	enum rohc_cid_type cid_type;
	bool analyze_full,is_carryed_ext;
	int analyze_len = 0;
	int retval = 0;
	
	v1_context = (struct decomp_profile_v1_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_context *)v1_context->inherit_context;
	rtp_context = &d_rtp_context->rtp_context;

	rtph_dynamic_fields = &rtp_context->update_by_packet.analyze_fields.dynamic_fields;

	cid_type = context->decompresser->cid_type;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;

	if(cid_type == CID_TYPE_SMALL){
		uor2_ts = (struct profile_rtp_uor2_ts *)analyze_data;
		analyze_full = true;
	}else{
		if(analyze_first)
			uor2_ts = (struct profile_rtp_uor2_ts *)analyze_data;
		else
			uor2_ts = (struct profile_rtp_uor2_ts *)(analyze_data - 1);
		analyze_full = false;
	}
	if(analyze_first){
		if(rtp_obtain_tsc(&rtp_context->update_by_packet,&rtp_context->rtph_ref))
			ts = &rtph_dynamic_fields->ts_scaled;
		else
			ts = &rtph_dynamic_fields->ts;
		decomp_wlsb_fill_analyze_field(ts,uor2_ts->ts,5,true);
		analyze_len = 1;
	}
	if(!analyze_full && analyze_first)
		goto out;
	decomp_fill_analyze_field(&rtph_dynamic_fields->m,uor2_ts->m);
	msn_update = &v1_context->msn_update;
	decomp_wlsb_fill_analyze_field(msn_update,uor2_ts->sn,6,true);

	is_carryed_ext = !!uor2_ts->x;
	analyze_len += sizeof(struct profile_rtp_uor2_ts) - 1;

	if(is_carryed_ext){
		pkt_info->decomped_hdr_len += analyze_len;
		analyze_len = 0;
		prof_v1_ops = v1_context->prof_v1_ops;
		retval = prof_v1_ops->adjust_extension_type(context,skb,pkt_info);
		if(retval){
			rohc_pr(ROHC_DRTP,"profile rtp cid-%d adjust extension type failed\n",context->cid);
			goto out;
		}
		retval = prof_v1_ops->analyze_extension(context,skb,pkt_info);
		if(retval)
			rohc_pr(ROHC_DRTP,"profile rtp cid-5d analyze extension failed\n",context->cid);

	}
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}

int decomp_rtp_analyze_ext0(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_ip_context *ip_context;
	struct decomp_rtp_context *d_rtp_context;
	struct decomp_rtph_context *rtp_context;

	struct wlsb_analyze_field *ts,*ipid,*msn_update;
	enum rohc_packet_type packet_type;

	int analyze_len = 0;
	int retval = 0;

	v1_context = (struct decomp_profile_v1_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_context *)v1_context->inherit_context;

	msn_update = &v1_context->msn_update;

	packet_type = pkt_info->packet_type;
	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	/*filed:type,sn,and +T*/
	decomp_wlsb_analyze_field_append_bits(msn_update,BYTE_BITS_3(*analyze_data,3),3,true);
	if(rohc_packet_carryed_rtp_ts(packet_type)){
		rtp_context = &d_rtp_context->rtp_context;
		if(rtp_obtain_tsc(&rtp_context->update_by_packet,&rtp_context->rtph_ref))
			ts = &rtp_context->update_by_packet.analyze_fields.dynamic_fields.ts_scaled;
		else
			ts = &rtp_context->update_by_packet.analyze_fields.dynamic_fields.ts;
		decomp_wlsb_analyze_field_append_bits(ts,BYTE_BITS_3(*analyze_data,0),3,true);
	}else{
		ip_context = &v1_context->ip_context;
		ipid = ip_pick_high_priority_ipid(&ip_context->last_context_info,&ip_context->update_by_packet);
		decomp_wlsb_analyze_field_append_bits(ipid,BYTE_BITS_3(*analyze_data,0),3,true);
	}
	pkt_info->decomped_hdr_len += 1;
	return retval;
}

int decomp_rtp_analyze_ext1(struct rohc_decomp_context *context,const sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_ip_context *ip_context;
	struct decomp_rtp_context *d_rtp_context;
	struct decomp_rtph_context *rtp_context;

	struct wlsb_analyze_field *msn_update,*ts,*ipid;

	enum rohc_packet_type packet_type;
	enum rtp_ext_t positive_t;
	int analyze_len = 0;
	int retval = 0;

	v1_context = (struct decomp_profile_v1_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_context *)v1_context->inherit_context;
	rtp_context = &d_rtp_context->rtp_context;
	ip_context = &v1_context->ip_context;

	packet_type = pkt_info->packet_type;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	
	/*filed.1 : type,sn and +T*/
	msn_update = &v1_context->msn_update;
	decomp_wlsb_analyze_field_append_bits(msn_update,BYTE_BITS_3(*analyze_data,3),3,true);
	if(rohc_packet_carryed_rtp_ts(packet_type))
		positive_t = RTP_EXT_T_TS;
	else
		positive_t = RTP_EXT_T_IPID;
	if(rtp_obtain_tsc(&rtp_context->update_by_packet,&rtp_context->rtph_ref))
		ts = &rtp_context->update_by_packet.analyze_fields.dynamic_fields.ts_scaled;
	else
		ts = &rtp_context->update_by_packet.analyze_fields.dynamic_fields.ts;
	ipid = ip_pick_high_priority_ipid(&ip_context->last_context_info,&ip_context->update_by_packet);
	
	if(positive_t == RTP_EXT_T_TS)
		decomp_wlsb_analyze_field_append_bits(ts,BYTE_BITS_3(*analyze_data,0),3,true);
	else
		decomp_wlsb_analyze_field_append_bits(ipid,BYTE_BITS_3(*analyze_data,0),3,true);
	analyze_data+=;
	analyze_len++;

	if(positive_t == RTP_EXT_T_TS)
		decomp_wlsb_analyze_field_append_bits(ipid,*analyze_data,8,true);
	else
		decomp_wlsb_analyze_field_append_bits(ts,*analyze_data,8,true);
	analyze_len++;
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;

}

int decomp_rtp_analyze_ext2(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_ip_context *ip_context;
	struct decomp_rtp_context *d_rtp_context;
	struct decomp_rtph_context *rtp_context;

	struct wlsb_analyze_field *msn_update,*ts,*ipid;

	enum rohc_packet_type packet_type;
	enum rtp_ext_t positive_t;
	int analyze_len = 0;
	int retval = 0;

	v1_context = (struct decomp_profile_v1_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_context *)v1_context->inherit_context;
	rtp_context = &d_rtp_context->rtp_context;
	ip_context = &v1_context->ip_context;

	packet_type = pkt_info->packet_type;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	
	msn_update = &v1_context->msn_update;

	if(rtp_obtain_tsc(&rtp_context->update_by_packet,&rtp_context->rtph_ref))
		ts = &rtp_context->update_by_packet.analyze_fields.dynamic_fields.ts_scaled;
	else
		ts = &rtp_context->update_by_packet.analyze_fields.dynamic_fields.ts;
	/*filed.1;tyep,sn,and +T*/
	decomp_wlsb_analyze_field_append_bits(msn_update,BYTE_BITS_3(*analyze_data,3),3,true);
	if(rohc_packet_carryed_rtp_ts(packet_type))
		positive_t = RTP_EXT_T_TS;
	else
		positive_t = RTP_EXT_T_IPID;
	if(positive_t == RTP_EXT_T_TS){
		decomp_wlsb_analyze_field_append_bits(ts,BYTE_BITS_3(*analyze_data,0),3,true);
		analyze_data++;
		analyze_len++;
		decomp_wlsb_analyze_field_append_bits(ts,*analyze_data,8,true);
	}else{
		decomp_wlsb_analyze_field_append_bits(ipid,BYTE_BITS_3(*analyze_data,0),3,true);
		analyze_data++;
		analyze_len++;
		decomp_wlsb_analyze_field_append_bits(ipid,*analyze_data,8,true);

	}
	analyze_data++;
	analyze_len++;
	/*filed.3 -T*/
	if(positive_t == RTP_EXT_T_TS)
		decomp_wlsb_analyze_field_append_bits(ipid,*analyze_data,8,true);
	else
		decomp_wlsb_analyze_field_append_bits(ts,*analyze_data,8,true);
	analyze_len++;
	pkt_info->decomped_hdr_len += analyze_len;

}
static int rtp_analyze_ext3_iph_flags(u8 *from,struct iph_decomp_fields *iph_fields,bool *tos,bool *ttl,bool *pr,bool *ipx,bool *dynamic_bit,struct analyze_field *new_ipid_bh,enum ip_id_behavior ipid_bh_ref,bool is_ipv4)
{
	bool nbo,rnd;
	struct iph_decomp_dynamic_part *dynamic_fields;
	*tos = !!BYTE_BIT_7(*from);
	*ttl = !!BYTE_BIT_6(*from);
	*pr = !!BYTE_BIT_4(*from);
	*ipx = !!BYTE_BIT_3(*from);
	*dynamic_bit = !!BYTE_BIT_0(*from);
	
	if(is_ipv4){
		dynamic_fields = &iph_fields->iph.iph_dynamic_part;
		rnd = !!BYTE_BIT_1(*from);
		nbo = !!BYTE_BIT_2(*from);
		if(!ip_id_is_constant(ipid_bh_ref)){
			if(rnd)
				decomp_fill_analyze_field(new_ipid_bh,IP_ID_BEHAVIOR_RANDOM);
			else{
				if(nbo)
					decomp_fill_analyze_field(new_ipid_bh,IP_ID_BEHAVIOR_SEQ);
				else
					decomp_fill_analyze_field(new_ipid_bh,IP_ID_BEHAVIOR_SEQ_SWAP);
			}
		}
		decomp_fill_analyze_field(&dynamic_fields->df,!!BYTE_BIT_5(*from));
	}else{
		//IPV6
		rohc_pr(ROHC_DRTP,"%s :now not support ipv6\n",__func__);
	}
	return 1;
}
static int rtp_analyze_ext3_iph_fields(u8 *from,struct iph_decomp_fields *iph_analyze_fields,bool tos,bool ttl,bool pr,bool ipx,bool is_ipv4)
{

	struct iph_decomp_dynamic_part *dynamic_fields;
	int analyze_len = 0;
	if(is_ipv4){
		dynamic_fields = &iph_analyze_fields->iph.dynamic_part;
		if(tos){
			decomp_fill_analyze_field(&dynamic_fields->tos_tc,*analyze_data);
			from++;
			analyze_len++;
		}
		if(ttl){
			decomp_fill_analyze_field(&dynamic_fields->ttl_hl,*analyze_data);
			from++;
			analyze_len++;
		}
	}else{
		//IPV6
	}
}

static inline  int rtp_analyze_ext3_rtph_flags(u8 *from,struct rtph_dynamic_fields *rtph_dynamic,bool *r_pt,bool *csrc,bool *tss)
{
	*tss = !!BYTE_BIT_1(*from);
	*csrc = !!BYTE_BIT_2(*from);
	*r_pt = !!BYTE_BIT_5(*from);
	decomp_fill_analyze_field(&rtph_dynamic_fields->m,!!BYTE_BIT_4(*from));
	decomp_fill_analyze_field(&rtph_dynamic_fields->x,!!BYTE_BIT_3(*from));
	return 1;
}


int decomp_rtp_analyze_ext3(struct rohc_decomp_context *context,const struct sk_buff *skb,struct rohc_decomp_pkt_hdr_info *pkt_info)
{
	u8 *analyze_data;
	struct decomp_profile_v1_context *v1_context;
	struct decomp_rtp_context *d_rtp_context;
	struct decomp_rtph_context *rtp_context;
	struct decomp_ip_context *ip_context;
	struct iph_decomp_fields *iph_analyze_fields;
	struct iph_decomp_fields *inner_iph_analyze_fields;
	struct analyze_field *new_ipid_bh,*new_inner_ipid_bh;

	struct rtph_dynamic_fields *rtph_dynamic_fields;
	struct wlsb_analyze_field *msn_update,*ts,*ipid,*inner_ipid;

	enum ip_id_behavior ipid_bh_ref,inner_ipid_bh_ref;
	bool s,r_ts,tsc,i1,i2,ip1,ip2,rtp;
	bool tos1,ttl1,pr1,ipx1;
	bool tos2,ttl2,pr2,ipx2;
	bool r_pt,csrc,tss;

	u32 decode_v;
	u16 ipid_off;
	int decode_len,decode_bits;
	int call_len;
	int analyze_len = 0;
	int retval = 0;

	v1_context = (struct decomp_profile_v1_context *)context->inherit_context;
	d_rtp_context = (struct decomp_rtp_context *)v1_context->inherit_context;
	rtp_context = &d_rtp_context->rtp_context;

	rtph_dynamic_fields = &rtp_context->update_by_packet.analyze_fields.dynamic_fields;

	ip_context = &v1_context->ip_context;

	iph_analyze_fields = &ip_context->update_by_packet.iph_fields;
	inner_iph_analyze_fields = &ip_context->update_by_packet.inner_iph_fields;
	new_ipid_bh = &ip_context->update_by_packet.ipid_bh;
	new_inner_ipid_bh = &ip_context->update_by_packet.inner_ipid_bh;

	ipid = &iph_analyze_fields->iph.iph_dynamic_part.ip_id;
	inner_ipid = &inner_iph_analyze_fileds->iph.iph_dynamic_part.ip_id;
	msn_update = &v1_context->msn_update;

	analyze_data = skb->data + pkt_info->decomped_hdr_len;
	
	ipid_bh_ref = ip_context->last_context_info.ip_id_bh[ROHC_OUTER_IPH];
	inner_ipid_bh_ref = ip_context->last_context_info.ip_id_bh[ROHC_OUTER_IPH];


	/*filed.1 FLAGS*/
	s = !!BYTE_BIT_5(*analyze_data);
	r_ts = !!BYTE_BIT_4(*analyze_data);
	tsc = !!BYTE_BIT_3(*analyze_data);
	i1 = !!BYTE_BIT_2(*analyze_data);
	ip1 = !!BYTE_BIT_1(*analyze_data);
	rtp = !!BYTE_BIT_0(*analyze_data);

	analyze_data++;
	analyze_len++;
	decomp_fill_analyze_field(&rtph_dynamic_fields->tsc,tsc);
	/*filed.2 inner ip header flags
	 */
	if(ip1){
		if(rohc_decomp_has_inner_iph(&ip_context->last_context_info,&ip_context->update_by_packet)){
			call_len = rtp_analyze_ext3_iph_flags(analyze_data,inner_iph_analyze_fields,&tos,&ttl1,&pr1,&ipx1,&ip2,new_inner_ipid_bh,inner_ipid_bh_ref,rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,&ip_context->update_by_packet,true)));	
		}else{
			call_len = rtp_analyze_ext3_iph_flags(analyze_data,iph_analyze_fileds,&tos1,&ttl1,&pr1,&ipx1,&ip2,new_ipid_bh,ipid_bh_ref,rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,&ip_context->update_by_packet,false)));
		}
		analyze_data += call_len;
		analyze_len += call_len;
	}

	/*filed.3 outer ip heade flags if ip2 = 1*/
	if(ip2){
		call_len = rtp_analyze_ext3_iph_flags(analyze_data,iph_analyze_fields,&tos2,&ttl2,&pr2,&ipx2,&i2,new_ipid_bh,ipid_bh_ref,rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,&ip_context->update_by_packet,false)));
		analyze_data += call_len;
		analyze_data += call_len;
	}
	/*field.4, sn*/
	if(s){
		decomp_wlsb_analyze_field_append_bits(msn_update,*analyze_data,8,true);
		analyze_data++;
		analyze_len++;
	}
	/*filed.5 ts*/
	if(r_ts){
		if(tsc)
			ts = &rtph_dynamic_fields->ts_scaled;
		else
			ts = &rtph_dynamic_fields->ts;
		rohc_sd_vl_decode(analyze_data,&decode_len,&decode_v);
		if(decode_len == 4)
			decomp_wlsb_analyze_field_append_bits_with_limit(ts,decode_v,29,32,true);
		else
			decomp_wlsb_analyze_field_append_bits_with_limit(ts,decode_v,(decode_len * 8 - decode_len),32,true);
		analyze_data += decode_len;
		analyze_len += decode_len;
	}
	/*filed.6 inner ip header fileds*/

	if(ip1){
		if(rohc_decomp_has_inner_iph(&ip_context->last_context_info,&ip_context->update_by_packet)){
			call_len = rtp_analyze_ext3_iph_fields(analyze_data,inner_iph_analyze_fields,tos1,ttl1,pr1,ipx1,rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,&ip_context->update_by_packet,true)));

		}else
			call_len = rtp_analyze_ext3_iph_fields(analyze_data,iph_analyze_fields,tos1,ttl1,pr1,ipx1,rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,&ip_context->update_by_packet,false)));
		analyze_data += call_len;
		analyze_len += call_len;
	}
	/*filed.7 high priority IP-ID*/
	if(i1){
		memcpy(&ipid_off,analyze_data,2);
		/*change to cpu byte order */
		ipid_off = ntohs(ipid_off);
		ipid = ip_pick_high_priority_ipid(&ip_context->last_context_info,&ip_context->update_by_packet);
		decomp_wlsb_analyze_field_append_bits_with_limit(ipid,ipid_off,16,true);
		analyze_data += 2;
		analyze_len += 2;
	}

	/*filed.8 outer ip header fileds*/
	if(ip2){
		call_len = rtp_analyze_ext3_iph_fields(analyze_data,iph_analyze_fields,tos2,ttl2,pr2,ipx2,rohc_iph_is_v4(decomp_ip_obain_vesion(&ip_context->last_context_info,&ip_context->update_by_packet,false)));
		analyze_data += call_len;
		analyze_len += call_len;
		if(i2){

			memcpy(&ipid_off,analyze_data,2);
			ipid_off = ntohs(ipid_off);
			decomp_wlsb_fill_analyze_field(&iph_analyze_fields->iph.iph_dynamic_part.ip_id,ipid_off,16,true);
			analyze_data += 2;
			analyze_len += 2;
		}
	}
	/*filed.9 rtp fields and flags*/
	if(rtp){
		call_len = rtp_analyze_ext3_rtph_flags(analyze_data,new_rtph_dynamic,r_pt,csrc,tss);
		analyze_data += call_len;
		analyze_len += call_len;
		if(r_pt){
			decomp_fill_analyze_field(&new_rtph_dynamic->p,!!BYTE_BIT_7(*analyze_data));
			decomp_fill_analyze_field(&new_rtph_dynamic->pt,BYTE_BITS_7(*analyze_data,0));
		}
		if(csrc){
			/*analyze csrc compressed list*/
			pkt_info->decomped_hdr_len += analyze_len;
			analyze_len = 0;
			retval = rtp_csrc_analyze_clist(&d_rtp_context->csrc_context,skb,pkt_info);
			if(retval){
				rohc_pr(ROHC_DRTP,"profile rtp cid-%d analyze csrc list failed when analyze extension3\n",context->cid);
				goto out;
			}
			analyze_data = skb->data + pkt_info->decomped_hdr_len;
		}
		if(tss){
			if(rohc_sd_vl_decode(analyze_data,&decode_len,&decode_v)){
				rohc_pr(ROHC_DRTP,"profile rtp cid-%d analyze ts stride failed when analyze extension3\n",context->cid);
				retval = -EFAULT;
				goto out;
			}
			decomp_fill_analyze_field(&new_rtph_dynamic->ts_stride,decode_v);
			analyze_data += decode_len;
			analyze_len += decode_len;
		}
	}
out:
	pkt_info->decomped_hdr_len += analyze_len;
	return retval;
}
