#ifndef		D__ROHC_DECOMP_WLSB_H
#define		D__ROHC_DECOMP_WLSB_H

#include <linux/types.h>

#define	FIELD_CARRYED_F	(1 << 0)

struct rohc_decomp_wlsb{
	u8 type_size;
	u32 v_ref_zero;
	u32 v_ref_before_zero;

	/*define for rohc_v2*/
	u8 sn_type;
	u32 ref_msn;
};

struct analyze_vl_field{
	u8  buff[64];
	int len;
	u32 flags;
};
struct wlsb_analyze_field{
	u32	encode_v;
	bool	is_comp;
	int	encode_p;
	u8	encode_bits;
	u32 flags;

};

struct analyze_field{
	u32 value;
	u32 flags;
};
static inline bool decomp_wlsb_analyze_field_is_carryed(struct wlsb_analyze_field *ana_field)
{
	bool retval = false;
	if(ana_field->flags & FIELD_CARRYED_F)
		retval = true;
	return retval;
}
static inline void decomp_wlsb_fill_analyze_field(struct wlsb_analyze_field *ana_field,u32 encode_v,u8 encode_bits,bool is_comp)
{
	ana_field->encode_v = encode_v;
	ana_field->encode_bits = encode_bits;
	ana_field->is_comp = is_comp;
	ana_field->flags |= FIELD_CARRYED_F;
}

static inline void decomp_wlsb_fill_analyze_field_contain_p(struct wlsb_analyze_field *ana_field,u32 encode_v,u8 encode_bits,int encode_p,bool is_comp)
{
	ana_field->encode_v = encode_v;
	ana_field->encode_bits = encode_bits;
	ana_field->encode_p = encode_p;
	ana_field->is_comp = is_comp;
	ana_field->flags |= FIELD_CARRYED_F;
}

static inline void decomp_wlsb_analyze_field_high_bits_add(struct wlsb_analyze_field *ana_field,u32 appand_value,u8 appand_bits,bool is_comp)
{
	u32 old_value,old_bits;
	bool old_is_comp;
	old_value = ana_field->encode_v;
	old_bits = ana_field->encode_bits;
	old_is_comp = ana_field->is_comp;
	old_value = (old_value << appand_bits) | appand_value;
	old_bits += appand_bits;
	decomp_wlsb_fill_analyze_field(ana_field,old_value,old_bits,is_comp);
}

static inline void decomp_wlsb_analyze_field_append_bits(struct wlsb_analyze_field *ana_field,u32 appand_value,u8 appand_bits,bool is_comp)
{
	u32 old_value,old_bits;
	bool old_is_comp;
	old_value = ana_field->encode_v;
	old_bits = ana_field->encode_bits;
	old_is_comp = ana_field->is_comp;
	old_value = (old_value << appand_bits) | appand_value;
	old_bits += appand_bits;
	decomp_wlsb_fill_analyze_field(ana_field,old_value,old_bits,is_comp);
}

static inline void decomp_wlsb_analyze_field_append_bits_with_limit(struct wlsb_analyze_field *ana_field,u32 appand_value,u8 appand_bits,int bits_limit,bool is_comp)
{
	u32 old_value,old_bits;
	old_value = ana_field->encode_v;
	old_bits = ana_field->encode_bits;
	old_value = (old_value << appand_bits) | appand_value;
	old_bits += appand_bits;
	if(old_bits > bits_limit)
		old_bits = bits_limit;
	decomp_wlsb_fill_analyze_field(ana_field,old_value,old_bits,is_comp);
}
static inline bool analyze_field_is_carryed(struct analyze_field *field)
{
	bool retval = false;
	if(field->flags & FIELD_CARRYED_F)
		retval = true;
	return retval;
}
static inline  void decomp_fill_analyze_field(struct analyze_field *field,u32 value)
{
	field->value = value;
	field->flags |= FIELD_CARRYED_F;
}


static inline void decomp_fill_analyze_vl_field(struct analyze_vl_field *field,u8 *data,int len)
{
	memcpy(field->buff,data,len);
	field->len = len;
	field->flags |= FIELD_CARRYED_F;
}

static inline bool analyze_vl_field_is_carryed(struct analyze_vl_field *field)
{
	bool retval = false;
	if(field->flags & FIELD_CARRYED_F)
		retval = true;
	return retval;
}
static inline u32 rohc_decomp_lsb_pick_ref(struct rohc_decomp_wlsb *wlsb,bool repair)
{
	u32 v_ref;
	if(!repair)
		v_ref = wlsb->v_ref_zero;
	else
		v_ref = wlsb->v_ref_before_zero;
	return v_ref;
}
static inline rohc_decomp_lsb_pick_ref_with_msn(struct rohc_decomp_wlsb *wlsb,u32 *ref,u32 *msn,bool repair)
{
	*ref = wlsb->v_ref_zero;
	*msn = wlsb->ref_msn;
}
static inline void rohc_decomp_lsb_setup_ref_with_msn(struct rohc_decomp_wlsb *wlsb,u32 new_ref,u32 msn)
{
	wlsb->v_ref_before_zero = wlsb->v_ref_zero;
	wlsb->v_ref_zero = new_ref;
	wlsb->ref_msn = msn;
}
static inline void rohc_decomp_lsb_setup_ref(struct rohc_decomp_wlsb *wlsb,u32 new_ref)
{
	wlsb->v_ref_before_zero = wlsb->v_ref_zero;
	wlsb->v_ref_zero = new_ref;
}
int rohc_decomp_lsb_decode(struct rohc_decomp_wlsb *lsb,u32 k,u32 p,u32 encode_v,u32 *decode_v,bool repair);
struct rohc_decomp_wlsb *rohc_decomp_lsb_alloc(u8 type_size,gfp_t flags);
void rohc_decomp_lsb_free(struct rohc_decomp_wlsb *wlsb);

#endif
