#ifndef	D__ROHC_PROFILE_H
#define	D__ROHC_PROFILE_H
#define	ROHC_PROFILE_MAX		16


#define		ROHC_PROFILE_HASH(prof)		((prof) & (ROHC_PROFILE_MAX - 1))
enum rohc_profile{
	ROHC_V1_PROFILE_UNCOMP = 0x00,
	ROHC_V1_PROFILE_RTP=0x01,
	ROHC_V1_PROFILE_UDP=0x02,
	ROHC_V1_PROFILE_ESP=0x03,
	ROHC_V1_PROFILE_IP = 0x04,
	ROHC_V1_PROFILE_TCP = 0x06,
	ROHC_V1_PROFILE_UDPLITE_RTP= 0x07,
	ROHC_V1_PROFILE_UDP_LITE = 0x08,
	ROHC_V2_PROFILE_RTP = 0x0101,
	ROHC_V2_PROFILE_UDP = 0x0102,
	ROHC_V2_PROFILE_ESP =0x0103,
	ROHC_V2_PROFILE_IP =0x0104,
	ROHC_V2_PROFILE_UDPLITE_RTP = 0x0107,
	ROHC_V2_PROFILE_UDP_LITE = 0x0108,

};


static inline char *rohc_profile_to_protocol(enum rohc_profile prof)
{
	char *pro_name;
	switch(prof){
		case ROHC_V1_PROFILE_UNCOMP:
			pro_name = "UNCOMP";
			break;
		case ROHC_V1_PROFILE_UDP:
			pro_name = "IP/UDP";
			break;
		case ROHC_V1_PROFILE_TCP:
			pro_name = "IP/TCP";
			break;
		case ROHC_V2_PROFILE_UDP:
			pro_name = "V2-IP/UDP";
			break;
		case ROHC_V2_PROFILE_RTP:
			pro_name = "V2-IP/UDP/RTP";
			break;
		case ROHC_V2_PROFILE_IP:
			pro_name = "V2-IP";
			break;
		default:
			pro_name = "other";
			break;
	}
	return pro_name;
}
static inline bool rohc_profile_is_v2(enum rohc_profile profile)
{
	return (profile & 0xff00) == 0x0100;
}
#endif
