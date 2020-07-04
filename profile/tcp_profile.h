#ifndef	D__TCP_PROFILE_H
#define	D__TCP_PROFILE_H
/*the tcp option sack type
 */
#define	SACK_LSB_0	(0x0 << 7)
#define	SACK_LSB_10	(0x2 << 6)
#define	SACK_LSB_110	(0x3 << 6)
#define	SACK_LSB_FULL	(0xff)

/*tcp option item generic static*/
#define ITEM_GENERIC_STATIC	(0x1 << 7)

#define	ROHC_TCP_OPTIONS_MAX_LEN	64
#define	ROHC_TCP_COMP_LIST_MAX	15
#define	ROHC_TCP_OPT_GENERIC_MAX	9
enum	rohc_tcp_item_type{
	ROHC_TCP_ITEM_NOP = 0,
	ROHC_TCP_ITEM_EOL,
	ROHC_TCP_ITEM_MSS,
	ROHC_TCP_ITEM_WS,
	ROHC_TCP_ITEM_TS,
	ROHC_TCP_ITEM_SACK_PERM,
	ROHC_TCP_ITEM_SACK,
	ROHC_TCP_ITEM_GENERIC7,
	ROHC_TCP_ITEM_GENERIC8,
	ROHC_TCP_ITEM_GENERIC9,
	ROHC_TCP_ITEM_GENERIC10,
	ROHC_TCP_ITEM_GENERIC11,
	ROHC_TCP_ITEM_GENERIC12,
	ROHC_TCP_ITEM_GENERIC13,
	ROHC_TCP_ITEM_GENERIC14,
	ROHC_TCP_ITEM_GENERIC15,
	ROHC_TCP_ITEM_MAX,
};
struct tcph_option{
	u8	kind;
	u8	len;
	u16	offset;
	int	item_type;
};

struct tcph_carryed_options{
	int opt_num;
	struct tcph_option  tcp_options[ROHC_TCP_COMP_LIST_MAX];
};
struct item_to_index{
	bool is_maped;
	int index;
};

static inline void tcp_field_scaling(u32 stride_value,u32 *scaled_value,u32 unscaled_value,u32 *residue)
{
	if(stride_value){
		*scaled_value = unscaled_value / stride_value;
		*residue = unscaled_value % stride_value;
	}else{
		*scaled_value = 0;
		*residue = unscaled_value;
	}
}

#endif


