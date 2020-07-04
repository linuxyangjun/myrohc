#ifndef	D__WLSB_H
#define	D__WLSB_H
/**
 *profiles p definions
 */

#define	ROHC_LSB_IPID_P		0
/* rohc udp profile always uses p = -1 when interpreting the SN,
 * since there will be no repetions or reordering of the compressor
 * generated SN.
 */
#define	ROHC_LSB_UDP_SN_P		-1
/*Tcp profile ip-id p for different packet types
 *
 */
#define	ROHC_LSB_TCP_IPID_P_COMMON	3
#define ROHC_LSB_TCP_IPID_P_S1		3
#define ROHC_LSB_TCP_IPID_P_S2		3
#define	ROHC_LSB_TCP_IPID_P_S3		3
#define	ROHC_LSB_TCP_IPID_P_S4		1
#define	ROHC_LSB_TCP_IPID_P_S5		3
#define	ROHC_LSB_TCP_IPID_P_S6		3
#define	ROHC_LSB_TCP_IPID_P_S7		3
#define	ROHC_LSB_TCP_IPID_P_S8		3

#define	ROHC_LSBC_TCP_IPID_K_TO_P(k)	(((k) > 3) ? 3 : 1)
/*inner ip header ttl hopl 
 */
#define	ROHC_LSB_TCP_TTL_HL		3

/*TCP MSN 
 */
#define	ROHC_LSB_TCP_MSN_P	4


/*p  = 1 << k -1
 */
#define	ROHC_LSB_TCP_K_RSHIFT_0_TO_P(k)	((1 << (k)) - 1)
/*p = 1 << (k - 1) - 1
 */
#define ROHC_LSB_TCP_K_RSHIFT_1_TO_P(k)	((1 << (k - 1)) - 1)
/*p = 1 << (k - 2) -1
 */
#define	ROHC_LSB_TCP_K_RSHIFT_2_TO_P(k)	((1 << (k - 2)) - 1)


#define	ROHC_LSB_TCP_SEQ_SCALED_P		7
#define	ROHC_LSB_TCP_ACK_SEQ_SCALED_P		3
#define	ROHC_LSB_TCP_WINDOW_P			16383

/*TCP timestamp P
 */
#define	ROHC_LSB_TCP_TS_K_7_P			-1
#define	ROHC_LSB_TCP_TS_K_14_P			-1
#define	ROHC_LSB_TCP_TS_K_21_P			0x40000
#define	ROHC_LSB_TCP_TS_K_29_P			0x4000000


/*RTP timestamp P*/
#define	ROHC_LSB_RTP_TS_K_TO_P(k)	(((k) > 2) ? ((1 << (k - 2)) - 1) : 1)


/*rohc_v2 IPID p
 */
#define	ROHC_LSB_V2_IPID_P(k)		(((k) > 2) ? ((1 << (k - 2)) - 1) : 1)
#endif
