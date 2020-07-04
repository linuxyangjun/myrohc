#ifndef	D__ROHC_FEEDBACK_H
#define	D__ROHC_FEEDBACK_H

#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/types.h>
#include "rohc_profile.h"
#include "rohc_packet.h"
#include "rohc_cid.h"
#define	ROHC_FEEDBACK_HEADER_MAX_LEN	4
/**
 *feedback-2 ack type
 */
#define		ROHC_FEEDBACK_ACK	0
#define		ROHC_FEEDBACK_NACK	1
#define		ROHC_FEEDBACK_STATIC_NACK	2


/**
 *feedback-2 mode,for rohc v1
 *
 */

#define		ROHC_FEEDBACK_MODE_U	1
#define		ROHC_FEEDBACK_MODE_O	2
#define		ROHC_FEEDBACK_MODE_R	3

#define		MIN_FEEDBACK_PROF_V1_SN_BIT	12
#define		MIN_FEEDBACK_PROF_V2_SN_BIT	14
/**
 *feedback options
 */

enum rohc_feedback_option_type{
	FEEDBACK_OPTION_TYPE_CRC = 1,
	FEEDBACK_OPTION_TYPE_REJECT = 2,
	FEEDBACK_OPTION_TYPE_UNVALID_SN = 3,
	FEEDBACK_OPTION_TYPE_SN =4 ,
	FEEDBACK_OPTION_TYPE_CLOCK = 5,
	FEEDBACK_OPTION_TYPE_JITTER = 6,
	FEEDBACK_OPTION_TYPE_LOSS = 7,
	FEEDBACK_OPTION_TYPE_MEMERY = 9,

	FEEDBACK_OPTION_TYPE_MAX = 15,
};

struct rohc_feedback_option_compile{
	int option_apprear[FEEDBACK_OPTION_TYPE_MAX];
	u32 sn;
	u32 sn_opt_bits;
};
static inline enum rohc_feedback_option_type feedback_adjust_option_type(u8 *buf)
{
	enum rohc_feedback_option_type opt_type;
	opt_type = ((*buf) >> 4) & 0xff;
	return opt_type;
}
int rohc_feedback_2_data_sn(struct sk_buff *skb , enum rohc_profile prof,int ack_type,int mode,u32 sn,int sn_bits_width);
int rohc_feedback_1_data_sn(struct sk_buff *skb,u8 msn);
int rohc_feedback_add_header(struct sk_buff *skb,enum rohc_profile prof,u16 cid,enum rohc_cid_type cid_type,bool add_crc_opt);

int rohc_feedback_parse_header(struct sk_buff *skb,enum rohc_cid_type cid_type,int *hdr_len,int *feeback_size,int *cid,int *cid_len);
bool rohc_feeback_crc_is_ok(struct sk_buff *skb,enum rohc_profile prof,int cid_len);
int rohc_feeback_parse_options(struct sk_buff *skb,struct rohc_feedback_option_compile *option_compile,enum rohc_profile prof,int feedback_size);
#endif
