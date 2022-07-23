/* Header for jnetpcap_utils utility methods */

#ifndef _Included_jnetpcap_packet_protocol_h
#define _Included_jnetpcap_packet_protocol_h
#ifdef __cplusplus

#include <stdint.h>

#include "export.h"
#include <jni.h>
#include "nio_jbuffer.h"
#include "org_jnetpcap_protocol_JProtocol.h"
#include "org_jnetpcap_packet_JScan.h"

#define END_OF_HEADERS   org_jnetpcap_packet_JScan_END_OF_HEADERS_ID
#define ETHERNET_ID      org_jnetpcap_protocol_JProtocol_ETHERNET_ID
#define TCP_ID           org_jnetpcap_protocol_JProtocol_TCP_ID
#define UDP_ID           org_jnetpcap_protocol_JProtocol_UDP_ID
#define IEEE_802DOT3_ID  org_jnetpcap_protocol_JProtocol_IEEE_802DOT3_ID
#define IEEE_802DOT2_ID  org_jnetpcap_protocol_JProtocol_IEEE_802DOT2_ID
#define IEEE_SNAP_ID     org_jnetpcap_protocol_JProtocol_IEEE_SNAP_ID
#define IP4_ID           org_jnetpcap_protocol_JProtocol_IP4_ID
#define IP6_ID           org_jnetpcap_protocol_JProtocol_IP6_ID
#define IEEE_802DOT1Q_ID org_jnetpcap_protocol_JProtocol_IEEE_802DOT1Q_ID
#define L2TP_ID          org_jnetpcap_protocol_JProtocol_L2TP_ID
#define PPP_ID           org_jnetpcap_protocol_JProtocol_PPP_ID
#define ICMP_ID          org_jnetpcap_protocol_JProtocol_ICMP_ID
#define HTTP_ID          org_jnetpcap_protocol_JProtocol_HTTP_ID
#define HTML_ID          org_jnetpcap_protocol_JProtocol_HTML_ID
#define ARP_ID           org_jnetpcap_protocol_JProtocol_ARP_ID
#define SIP_ID           org_jnetpcap_protocol_JProtocol_SIP_ID
#define SDP_ID           org_jnetpcap_protocol_JProtocol_SDP_ID
#define RTP_ID           org_jnetpcap_protocol_JProtocol_RTP_ID
#define SLL_ID           org_jnetpcap_protocol_JProtocol_SLL_ID

#define SCTP_ID              org_jnetpcap_protocol_JProtocol_SCTP_ID
#define SCTP_CHUNK_ID        org_jnetpcap_protocol_JProtocol_SCTP_DATA_ID
#define SCTP_DATA_ID         org_jnetpcap_protocol_JProtocol_SCTP_DATA_ID
#define SCTP_INIT_ID         org_jnetpcap_protocol_JProtocol_SCTP_INIT_ID
#define SCTP_INIT_ACK_ID     org_jnetpcap_protocol_JProtocol_SCTP_INIT_ACK_ID
#define SCTP_SACK_ID         org_jnetpcap_protocol_JProtocol_SCTP_SACK_ID
#define SCTP_HEARTBEAT_ID    org_jnetpcap_protocol_JProtocol_SCTP_HEARTBEAT_ID
#define SCTP_HEARTBEAT_ACK_ID    org_jnetpcap_protocol_JProtocol_SCTP_HEARTBEAT_ACK_ID
#define SCTP_ABORT_ID        org_jnetpcap_protocol_JProtocol_SCTP_ABORT_ID
#define SCTP_SHUTDOWN_ID     org_jnetpcap_protocol_JProtocol_SCTP_SHUTDOWN_ID
#define SCTP_SHUTDOWN_ACK_ID org_jnetpcap_protocol_JProtocol_SCTP_SHUTDOWN_ACK_ID
#define SCTP_ERROR_ID        org_jnetpcap_protocol_JProtocol_SCTP_ERROR_ID
#define SCTP_COOKIE_ID       org_jnetpcap_protocol_JProtocol_SCTP_COOKIE_ID
#define SCTP_COOKIE_ACK_ID   org_jnetpcap_protocol_JProtocol_SCTP_COOKIE_ACK_ID
#define SCTP_ECNE_ID         org_jnetpcap_protocol_JProtocol_SCTP_ECNE_ID
#define SCTP_CWR_ID          org_jnetpcap_protocol_JProtocol_SCTP_CWR_ID
#define SCTP_SHUTDOWN_COMPLETE_ID org_jnetpcap_protocol_JProtocol_SCTP_SHUTDOWN_COMPLETE_ID

#define RTCP_ID 		org_jnetpcap_protocol_JProtocol_RTCP_SENDER_REPORT_ID
#define RTCP_CHUNK_ID 		org_jnetpcap_protocol_JProtocol_RTCP_SENDER_REPORT_ID
#define RTCP_SENDER_REPORT_ID org_jnetpcap_protocol_JProtocol_RTCP_SENDER_REPORT_ID
#define RTCP_RECEIVER_REPORT_ID org_jnetpcap_protocol_JProtocol_RTCP_RECEIVER_REPORT_ID
#define RTCP_SDES_ID org_jnetpcap_protocol_JProtocol_RTCP_SDES_ID
#define RTCP_BYE_ID org_jnetpcap_protocol_JProtocol_RTCP_BYE_ID
#define RTCP_APP_ID org_jnetpcap_protocol_JProtocol_RTCP_APP_ID

#define NULL_HEADER_ID org_jnetpcap_protocol_JProtocol_NULL_HEADER_ID

#define WEB_IMAGE_ID        org_jnetpcap_protocol_JProtocol_WEB_IMAGE_ID

#define NETBIOS_ID END_OF_HEADERS

#pragma pack(push)  /* push current alignment to stack */
#pragma pack(1)     /* set alignment to 1 byte boundary */

typedef struct null_header_s {

	uint32_t	null_type; // PF_ protocol family type

} null_header_t;

#define NULL_STRUCT_LENGTH	4

#define NULL_GET_TYPE(p)	BIG_ENDIAN32_ALIGNED(p->null_type)

/**
 * SCTP Chunk
 */
typedef struct sctp_chunk_ {

	uint8_t		chunk_type;
	uint8_t		chunk_flags;
	uint16_t	chunk_length;

} sctp_chunk_t;

#define SCTP_CHUNK_STRUCT_LENGTH	4

#define SCTP_DATA_FLAG_LAST_SEG		0x01
#define SCTP_DATA_FLAG_FIRST_SEG	0x02
#define SCTP_DATA_FLAG_ORDERED		0x04
#define SCTP_DATA_FLAG_DELAY		0x08

#define SCTP_CHUNK_GET_TYPE(p)		(p->chunk_type)
#define SCTP_CHUNK_GET_FLAGS(p)		(p->chunk_flags)
#define SCTP_CHUNK_GET_LENGTH(p)	BIG_ENDIAN16_ALIGNED(p->chunk_type)

/**
 * Stream Control Transport Protocol
 */
typedef struct sctp_s {

	uint16_t	sctp_sport;
	uint16_t	sctp_dport;
	uint32_t	sctp_tag;
	uint32_t	sctp_crc32;

} sctp_t;

#define SCTP_STRUCT_LENGTH	12

#define SCTP_GET_SPORT(p)	BIG_ENDIAN16_ALIGNED(p->sctp_sport)
#define SCTP_GET_DPORT(p)	BIG_ENDIAN16_ALIGNED(p->sctp_dport)
#define SCTP_GET_TAG(p)		BIG_ENDIAN32_ALIGNED(p->sctp_stag)
#define SCTP_GET_CRC32(p)	BIG_ENDIAN32_ALIGNED(p->sctp_crc32)

/*
 * Linux Socket Cooked Capture header - a pseudo header as DL substitute
 */
#define SLL_ADDR_LEN	8		      // length of address field

typedef struct sll_s {

	uint16_t	sll_pkttype;	          // packet type
	uint16_t	sll_hatype;	            // link-layer address type
	uint16_t	sll_halen;	            // link-layer address length
	uint8_t		sll_addr[SLL_ADDR_LEN];	// link-layer address
	uint16_t	sll_protocol;         	// protocol

} sll_t;

#define SLL_STRUCT_LENGTH	16

#define	SLL_GET_PKTTYPE(p)	BIG_ENDIAN16_ALIGNED(p->ssl_pkttype)
#define	SLL_GET_HATYPE(p)	BIG_ENDIAN16_ALIGNED(p->sll_hatype)
#define	SLL_GET_HALEN(p)	BIG_ENDIAN16_ALIGNED(p->sll_halen)
#define	SLL_GET_ADDR(p)		(p->sll_addr)
#define	SLL_GET_PROTOCOL(p)	BIG_ENDIAN16_ALIGNED(p->sll_protocol)

/*
 * Realtime Transfer Protocol and extension
 */
typedef struct rtpx_s {
	
	uint16_t	rtpx_profile; 	// Profile specific
	uint16_t	rtpx_len;		// Length of extension header
	
} rtpx_t;

#define RTPX_STRUCT_LENGTH	4

#define RTPX_GET_PROFILE(p)	BIG_ENDIAN16_ALIGNED(p->rtpx_profile)
#define RTPX_GET_LEN(p)		BIG_ENDIAN16_ALIGNED(p->rtpx_len)

/*
 *  RTP and RTCP family of protocols
 *  See RFC3550
 */

/**
 * RTCP SSRC Sender Report (section 3 of the header)
 */
typedef struct rtcp_ssrc_s {

	uint32_t	ssrc_id; // SSRC identifier of the source

	union {

		uint32_t		ssrc_i0;

		struct {

			uint32_t	ssrc_fract_loss:8; // Fraction of RTP data lost
			uint32_t	ssrc_total_loss:24; // Cumulative of RTP data lost

		} ssrc_u1;

	} ssrc_s1;

	uint32_t	ssrc_high_seq; // Extended highest seq received
	uint32_t	ssrc_jitter; // Interarrival Jitter
	uint32_t	ssrc_lsr; // Last SR timestamp
	uint32_t	ssrc_dlsr; // Delay since last SR

} rtcp_ssrc_t;

#define ssrc_i0				ssrc_s1.ssrc_i0
#define	ssrc_fract_loss		ssrc_s1.ssrc_u1.ssrc_fract_loss
#define	ssrc_total_loss		ssrc_s1.ssrc_u1.ssrc_total_loss

#define RTCP_SSRC_STRUCT_LENGTH	24

#define RTCP_SSRC_GET_ID(p)			BIG_ENDIAN32_ALIGNED(p->ssrc_id)
#define	RTCP_SSRC_GET_FRACT_LOSS(p)	((p->ssrc_i0 >> 24) & 0x000000FF)
#define	RTCP_SSRC_GET_TOTAL_LOSS(p)	((BIG_ENDIAN32_ALIGNED(p->ssrc_i0) >> 0)  & 0x00FFFFFF)
#define RTCP_SSRC_GET_HIGH_SEQ(p)	BIG_ENDIAN32_ALIGNED(p->ssrc_high_seq)
#define RTCP_SSRC_GET_JITTER(p)		BIG_ENDIAN32_ALIGNED(p->ssrc_jitter)
#define RTCP_SSRC_GET_LSR(p)		BIG_ENDIAN32_ALIGNED(p->ssrc_lsr)
#define RTCP_SSRC_GET_DLSR(p)		BIG_ENDIAN32_ALIGNED(p->ssrc_dlsr)

/*
 * RTCP Sender Report (SR)
 * (Section 2 of the header)
 */
typedef struct rtcp_sr_s {

	uint64_t	sr_ntp; // NTP timestamp
	uint32_t	sr_pkt_count; // Sender's packet count
	uint32_t	sr_octet_count; // Sender's octet count

} rtcp_sr_t;

#define RTCP_SR_STRUCT_LENGTH	16

#define	RTCP_SR_GET_NTP(p)			BIG_ENDIAN64_ALIGNED(p->sr_ntp)
#define	RTCP_SR_GET_PKT_COUNT(p)	BIG_ENDIAN32_ALIGNED(p->sr_pkt_count)
#define	RTCP_SR_GET_OCTET_COUNT(p)	BIG_ENDIAN32_ALIGNED(p->sr_octet_count)

/*
 * RTCP - main static header present in every RTCP packet.
 * RTCP packets are always on odd port number, while RTP on even (see RFC3550)
 * (Section 1 of the header)
 */
typedef struct rtcp_s {

#  if __BYTE_ORDER == __LITTLE_ENDIAN

//	uint8_t 	rtcp_rc:5; // Reception Report Count (RC)
//	uint8_t 	rtcp_pad:1;
//	uint8_t		rtcp_ver:2; // Must be 2

#  elif __BYTE_ORDER == __BIG_ENDIAN

//	uint8_t		rtcp_ver:2; // Must be 2
//	uint8_t 	rtcp_pad:1;
//	uint8_t 	rtcp_rc:5; // Reception Report Count (RC)

#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif

	uint8_t		rtcp_b0;

	uint8_t		rtcp_type; // SR==200, RR==201
	uint16_t	rtcp_len;  // 32-bit word count (including header -1)
	uint32_t	rtcp_ssrc; // Synchronization source ID

} rtcp_t;

#define RTCP_STRUCT_LENGTH	8

#define RTCP_GET_VER(p)		((p->rtcp_b0 >> 6) & 0x03)
#define RTCP_GET_PAD(p)		((p->rtcp_b0 >> 5) & 0x01)
#define RTCP_GET_RC(p)		((p->rtcp_b0 >> 0) & 0x1F)
#define RTCP_GET_TYPE(p)	(p->rtcp_type)
#define RTCP_GET_LEN(p)		BIG_ENDIAN16_ALIGNED(p->rtcp_len)
#define RTCP_GET_SSRC(p)	BIG_ENDIAN32_ALIGNED(p->rtcp_ssrc)


typedef struct rtp_s {

#  if __BYTE_ORDER == __LITTLE_ENDIAN

//	uint8_t 	rtp_cc:4;
//	uint8_t 	rtp_ext:1;
//	uint8_t 	rtp_pad:1;
//	uint8_t		rtp_ver:2;
//
//	uint8_t		rtp_type:7;
//	uint8_t		rtp_marker:1;
	
#  elif __BYTE_ORDER == __BIG_ENDIAN

//	uint8_t		rtp_ver:2;
//	uint8_t 	rtp_pad:1;
//	uint8_t 	rtp_ext:1;
//	uint8_t 	rtp_cc:4;
//
//	uint8_t		rtp_marker:1;
//	uint8_t		rtp_type:7;
	
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif

	uint8_t		rtp_b0;
	uint8_t		rtp_b1;
	uint16_t	rtp_seq;
	uint32_t	rtp_ts;
	uint32_t	rtp_ssrc;

} rtp_t;

#define RTP_STRUCT_LENGTH	12

#define RTP_GET_VER(p)		((p->rtp_b0 >> 6) & 0x03)
#define RTP_GET_PAD(p)		((p->rtp_b0 >> 5) & 0x01)
#define RTP_GET_EXT(p)		((p->rtp_b0 >> 4) & 0x01)
#define RTP_GET_CC(p)		((p->rtp_b0 >> 0) & 0x0F)
#define RTP_GET_MARKER(p)	((p->rtp_b1 >> 7) & 0x01)
#define RTP_GET_TYPE(p)		((p->rtp_b1 >> 0) & 0x7F)
#define RTP_GET_SEQ(p)		BIG_ENDIAN16_ALIGNED(p->rtp_seq)
#define RTP_GET_TS(p)		BIG_ENDIAN32_ALIGNED(p->rtp_ts)
#define RTP_GET_SSRC(p)		BIG_ENDIAN32_ALIGNED(p->rtp_ssrc)


/*
 * Address Resolution Protocol
 */
typedef struct arp_s {

	uint16_t arp_htype;
	uint16_t arp_ptype;
	uint8_t  arp_hlen;
	uint8_t  arp_plen;

} arp_t;

#define ARP_STRUCT_LENGTH	6

#define ARP_GET_HTYPE(p)	BIG_ENDIAN16_ALIGNED(p->arp_htype)
#define ARP_GET_PTYPE(p)	BIG_ENDIAN16_ALIGNED(p->arp_ptype)
#define ARP_GET_HLEN(p)		(p->arp_hlen)
#define ARP_GET_PLEN(p)		(p->arp_plen)

/*
 * Internet Control Message Protocol
 */
typedef struct icmp4_s {

	uint8_t 	icmp4_type;
	uint8_t 	icmp4_code;
	uint16_t 	icmp4_crc;

} icmp4_t;

#define ICMP4_STRUCT_LENGTH	4

#define ICMP4_GET_TYPE(p)	(p->icmp4_type)
#define ICMP4_GET_CODE(p)	(p->icmp4_code)
#define ICMP4_GET_CRC(p)	BIG_ENDIAN16_ALIGNED(p->icmp4_crc)


/*
 * Point to Point Protocol
 */
typedef struct ppp_s {

	uint8_t ppp_addr;
	uint8_t ppp_control;
	uint16_t ppp_protocol;

} ppp_t;

#define PPP_STRUCT_LENGTH	4

#define PPP_GET_ADDR(p)		(p->ppp_addr)
#define PPP_GET_CONTROL(p)	(p->ppp_control)
#define PPP_GET_PROTOCOL(p)	BIG_ENDIAN16_ALIGNED(p->ppp_protocol)

/*
 * Layer 2 tunneling protocol
 */
typedef struct l2tp_s {

#  if __BYTE_ORDER == __LITTLE_ENDIAN

//	uint16_t p :1;
//	uint16_t o :1;
//	uint16_t res2 :1;
//	uint16_t s :1;
//	uint16_t res1 :2;
//	uint16_t l :1;
//	uint16_t t :1;
//	uint16_t version :4;
//	uint16_t res3 :4;

#  elif __BYTE_ORDER == __BIG_ENDIAN

//	uint16_t t:1;
//	uint16_t l:1;
//	uint16_t res1:2;
//	uint16_t s:1;
//	uint16_t res2:1;
//	uint16_t o:1;
//	uint16_t p:1;
//	uint16_t res3:4;
//	uint16_t version:4;

#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif

	uint8_t	l2tp_b0;
	uint8_t	l2tp_b1;

} l2tp_t;

#define L2TP_STRUCT_LENGTH	6
#define L2TP_OPTIONAL_LENGTH	2
#define L2TP_OPTIONAL_SESSION	4
#define L2TP_OPTIONAL_OFFSET	4

#define	L2TP_GET_T(p)		((p->l2tp_b0 >> 7) & 0x01)
#define	L2TP_GET_L(p)		((p->l2tp_b0 >> 6) & 0x01)
#define	L2TP_GET_RES1(p)	((p->l2tp_b0 >> 5) & 0x03)
#define	L2TP_GET_S(p)		((p->l2tp_b0 >> 3) & 0x01)
#define	L2TP_GET_RES2(p)	((p->l2tp_b0 >> 2) & 0x01)
#define	L2TP_GET_O(p)		((p->l2tp_b0 >> 1) & 0x01)
#define	L2TP_GET_P(p)		((p->l2tp_b0 >> 0) & 0x01)
#define	L2TP_GET_RES3(p)	((p->l2tp_b1 >> 4) & 0x0F)
#define	L2TP_GET_VERSION(p)	((p->l2tp_b1 >> 0) & 0x0F)

/*
 * IEEE 802.1q VLAN header
 */
typedef struct vlan_s {
	union {

		uint16_t	vlan_tci;

		struct {

			uint16_t vlan_priority :3;
			uint16_t vlan_cfi :1;
			uint16_t vlan_id :12;

		} vlan_u1;

	} vlan_control;

	uint16_t vlan_type;

} vlan_t;

#define VLAN_STRUCT_LENGTH	4

#define vlan_tci		vlan_control.vlan_tci
#define vlan_priority	vlan_control.vlan_u1.vlan_priority
#define vlan_cfi		vlan_control.vlan_u1.vlan_cfi
#define	vlan_id			vlan_control.vlan_u1.vlan_id

#define VLAN_GET_TCI(p)			BIG_ENDIAN16_ALIGNED(p->vlan_tci)
#define VLAN_GET_PRIORITY(p)	((BIG_ENDIAN16_ALIGNED(p->vlan_tci) & 0xE000) >> 13)
#define VLAN_GET_CFI(p)			((BIG_ENDIAN16_ALIGNED(p->vlan_tci) & 0x1000) >> 12)
#define VLAN_GET_ID(p)			((BIG_ENDIAN16_ALIGNED(p->vlan_tci) & 0x0FFF) >> 0)
#define VLAN_GET_TYPE(p)		BIG_ENDIAN16_ALIGNED(p->vlan_type)

/**
 * SNAP IEEE
 */
typedef struct snap_s {
	union {

		uint8_t	snap_b0[5];

		struct {

			uint32_t snap_oui:24;
			uint16_t snap_pid;

		} snap_u1;

	} snap_raw;

} snap_t;

#define SNAP_STRUCT_LENGTH	5

#define snap_b0		snap_raw.snap_b0
#define snap_oui	snap_raw.snap_oui
#define	snap_pid	snap_raw.snap_pid

#define SNAP_GET_OUI(p)		((uint32_t)((p->snap_b0[0] << 16) | (p->snap_b0[1] << 8) | (p->snap_b0[2] << 0)))
#define SNAP_GET_PID(p)		((uint16_t)((p->snap_b0[3] << 8) | (p->snap_b0[4] << 0)))
#define SNAP_GET_TYPE(p)	SNAP_GET_PID(p)

/**
 * LLC IEEE802.2
 */
typedef struct llc_s {

	uint8_t llc_dsap;
	uint8_t llc_ssap;
	uint8_t llc_control;

	union {

		uint8_t llc_info;

	} llc_optional;

} llc_t;

#define llc_info	llc_optional.llc_info

#define LLC_STRUCT_LENGTH	3

#define LLC_GET_DSAP(p)		(p->llc_dsap)
#define LLC_GET_SSAP(p)		(p->llc_ssap)
#define LLC_GET_CONTROL(p)	(p->llc_control)
#define LLC_GET_INFO(p)		(p->llc_info)

/**
 * UDP structure
 */
typedef struct udp_s {

	uint16_t udp_sport;
	uint16_t udp_dport;
	uint16_t udp_length;
	uint16_t udp_crc;

} udp_t;

#define UDP_STRUCT_LENGTH	8
#define UDP_GET_SPORT(p)	BIG_ENDIAN16_ALIGNED(p->udp_sport)
#define UDP_GET_DPORT(p)	BIG_ENDIAN16_ALIGNED(p->udp_dport)
#define UDP_GET_LENGTH(p)	BIG_ENDIAN16_ALIGNED(p->udp_length)
#define UDP_GET_CRC(p)		BIG_ENDIAN16_ALIGNED(p->udp_crc)

/**
 * TCP structure
 */
typedef struct tcp_s {
	uint16_t tcp_sport;
	uint16_t tcp_dport;
	uint32_t tcp_seq;
	uint32_t tcp_ack_seq;

#  if __BYTE_ORDER == __LITTLE_ENDIAN

//	uint16_t res1 :4;
//	uint16_t doff :4;
//	uint16_t fin :1;
//	uint16_t syn :1;
//	uint16_t rst :1;
//	uint16_t psh :1;
//	uint16_t ack :1;
//	uint16_t urg :1;
//	uint16_t res2 :2;

#  elif __BYTE_ORDER == __BIG_ENDIAN

//	uint16_t doff:4;
//	uint16_t res1:4;
//	uint16_t res2:2;
//	uint16_t urg:1;
//	uint16_t ack:1;
//	uint16_t psh:1;
//	uint16_t rst:1;
//	uint16_t syn:1;
//	uint16_t fin:1;

#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif

	uint8_t	tcp_b13;
	uint8_t	tcp_b14;
	uint16_t tcp_window;
	uint16_t tcp_crc;
	uint16_t tcp_urg_ptr;

} tcp_t;

#define PROTO_ETHERNET_HEADER_LENGTH 14
#define PROTO_802_3_MAX_LEN 0x600

#define TCP_STRUCT_LENGTH	20
#define TCP_CALC_LENGTH(p)	(TCP_GET_DOFF(p) << 2)

#define TCP_GET_SPORT(p)	BIG_ENDIAN16_ALIGNED(p->tcp_sport)
#define TCP_GET_DPORT(p)	BIG_ENDIAN16_ALIGNED(p->tcp_dport)
#define TCP_GET_SEQ(p)		BIG_ENDIAN32_ALIGNED(p->tcp_seq)
#define TCP_GET_ACK(p)		BIG_ENDIAN32_ALIGNED(p->tcp_ack_seq)
#define TCP_GET_DOFF(p)		((p->tcp_b13 & 0xF0) >> 4)
#define TCP_GET_RES1(p)		((p->tcp_b13 & 0x0F) >> 0)
#define TCP_GET_RES2(p)		((p->tcp_b14 & 0xC0) >> 6)
#define TCP_GET_URG(p)		((p->tcp_b14 & 0x20) >> 5)
#define TCP_GET_ACK_SEQ(p)	((p->tcp_b14 & 0x10) >> 4)
#define TCP_GET_PSH(p)		((p->tcp_b14 & 0x08) >> 3)
#define TCP_GET_RST(p)		((p->tcp_b14 & 0x04) >> 2)
#define TCP_GET_SYN(p)		((p->tcp_b14 & 0x02) >> 1)
#define TCP_GET_FIN(p)		((p->tcp_b14 & 0x01) >> 0)
#define TCP_GET_WINDOW(p)	BIG_ENDIAN16_ALIGNED(p->tcp_window)
#define TCP_GET_CRC(p)		BIG_ENDIAN16_ALIGNED(p->tcp_crc)
#define TCP_GET_URG_PTR(p)	BIG_ENDIAN16_ALIGNED(p->tcp_urg_ptr)

/**
 * Ethernet 2 structure
 */
typedef struct ethernet_s {

#define ETHERNET_ADDRESS_LENGTH	6
	uint8_t eth_daddr[ETHERNET_ADDRESS_LENGTH]; /* destination eth addr */
	uint8_t eth_saddr[ETHERNET_ADDRESS_LENGTH]; /* destination eth addr */
	uint16_t eth_type; /* destination e(IP4_GET_IHL(p) << 2)th addr */

} ethernet_t;

#define ETHERNET_STRUCT_LENGTH	14
#define ETHERNET_CALC_LENGTH(p)	ETHERNET_STRUCT_LENGTH
#define ETHERNET_TYPE_BOUNDRY	0x600

#define ETHERNET_GET_DADDR(p)	(p->eth_daddr)
#define ETHERNET_GET_SADDR(p)	(p->eth_saddr)
#define ETHERNET_GET_TYPE(p)	BIG_ENDIAN16_ALIGNED(p->eth_type)

/**
 * IP v6 structure
 * RFC 1883
 */
typedef struct ip6_s {
	union {
		struct ip6_hdrctl {

			uint32_t ip6_un1_flow;	/* 20 bits of flow-ID */
			uint16_t ip6_un1_plen;	/* payload length */
			uint8_t  ip6_un1_nxt;	/* next header */
			uint8_t  ip6_un1_hlim;	/* hop limit */

		} ip6_un1;

		uint8_t ip6_un2_vfc;	/* 4 bits version, 4 bits class */

	} ip6_ctlun;

	uint8_t ip6_src[16];	/* source address */
	uint8_t ip6_dst[16];	/* destination address */

} ip6_t;

#define ip6_flow	ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen	ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt		ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim	ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops	ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_vfc		ip6_ctlun.ip6_un2_vfc

#define IP6_GET_FLOW(p)		BIG_ENDIAN32_ALIGNED(p->ip6_flow)
#define IP6_GET_PLEN(p)		BIG_ENDIAN16_ALIGNED(p->ip6_plen)
#define IP6_GET_NXT(p)		(p->ip6_nxt)
#define IP6_GET_HOPS(p)		(p->ip6_hlim)
#define IP6_GET_VFC(p)		(p->ip6_vfc)
#define IP6_GET_SADDR(p)	(p->ip6_src)
#define IP6_GET_DADDR(p)	(p->ip6_dst)

#define IP6_STRUCT_LENGTH 	40
#define IP6_CALC_LENGTH(p) 	IP6_STRUCT_LENGTH

#define IP6_OPT_HOP_BY_HOP 		0
#define IP6_OPT_DEST_OPTIONS	60
#define IP6_OPT_ROUTING_HEADER	43
#define IP6_OPT_FRAGMENT_HEADER	44
#define IP6_OPT_AUTH_HEADER		51
#define IP6_OPT_SECURITY_HEADER	50
#define IP6_OPT_MOBILITY_HEADER	135
#define IP6_OPT_NO_NEXT_HEADER	59

/**
 * IP v4 structure
 */
typedef struct ip4_s {
#if __BYTE_ORDER == __LITTLE_ENDIAN
//	unsigned int ihl :4;
//	unsigned int version :4;

#elif __BYTE_ORDER == __BIG_ENDIAN
//	unsigned int version:4;
//	unsigned int ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif

	uint8_t ip4_b0;

	uint8_t ip4_tos;
	uint16_t ip4_tot_len;
	uint16_t ip4_id;
	uint16_t ip4_frag_off; // flags=3 bits, offset=13 bits
	uint8_t ip4_ttl;
	uint8_t ip4_protocol;
	uint16_t ip4_crc;

	union {
		struct {
			uint8_t ip4_saddr[4];
			uint8_t ip4_daddr[4];
		} ip4_un1;

		struct {
			uint32_t ip4_saddr32;
			uint32_t ip4_daddr32;
		} ip4_un2;

	} ip4_addr;

	/*The options start here. */
} ip4_t;

#define	ip4_saddr32	ip4_addr.ip4_un2.ip4_saddr32
#define	ip4_daddr32	ip4_addr.ip4_un2.ip4_daddr32
#define	ip4_saddr	ip4_addr.ip4_un1.ip4_saddr
#define	ip4_daddr	ip4_addr.ip4_un1.ip4_daddr

#define IP4_FLAGS_MASK 0xE000
#define IP4_FRAG_OFF_MASK ~IP4_FLAGS_MASK
#define IP4_FLAG_MF 0x2000
#define IP4_FLAG_DF 0x4000
#define IP4_FLAG_RESERVED 0x8000

#define IP4_STRUCT_LENGTH 20
#define IP4_CALC_LENGTH(p) (IP4_GET_IHL(p) << 2)

#define IP4_GET_VER(p) 		(((p->ip4_b0) & 0xF0) >> 4)
#define IP4_GET_IHL(p) 		(((p->ip4_b0) & 0x0F) >> 0)
#define IP4_GET_TOS(p) 		(p->ip4_tos)
#define IP4_GET_LEN(p) 		BIG_ENDIAN16(p->ip4_tot_len)
#define IP4_GET_ID(p) 		BIG_ENDIAN16(p->ip4_id)
#define IP4_GET_FRAG_OFF(p) (BIG_ENDIAN16(p->ip4_frag_off) & IP4_FRAG_OFF_MASK)
#define IP4_GET_FLAGS(p)  	((BIG_ENDIAN16(p->ip4_frag_off ) & IP4_FLAGS_MASK) >> 13)
#define IP4_GET_FLAG_MF(p) 	(IP4_GET_FLAGS(p) & 0x1)
#define IP4_GET_FLAG_DF(p) 	(IP4_GET_FLAGS(p) & 0x2)
#define IP4_GET_FLAG_RESERVED(p) (IP4_GET_FLAGS(p) & 0x4)
#define IP4_GET_TTL(p) 		(p->ip4_ttl)
#define IP4_GET_PROTO(p) 	(p->ip4_protocol)
#define IP4_GET_CRC(p) 		BIG_ENDIAN16(p->ip4_crc)
#define IP4_GET_SADDR(p) 	(p->ip4_saddr)
#define IP4_GET_DADDR(p) 	(p->ip4_daddr)

#ifdef __STRICT_ALIGNMENT

#define IP4_GET_SADDR32(p) 	BIG_ENDIAN32_GET(p->ip4_saddr)
#define IP4_GET_DADDR32(p) 	BIG_ENDIAN32_GET(p->ip4_daddr)

#else

#define IP4_GET_SADDR32(p) 	BIG_ENDIAN32(p->ip4_saddr32)
#define IP4_GET_DADDR32(p) 	BIG_ENDIAN32(p->ip4_daddr32)

#endif

#pragma pack(pop)   /* restore original alignment from stack */

/****************************************************************
 * **************************************************************
 * 
 * Scanner's native and java per protocol prototypes
 * 
 * **************************************************************
 ****************************************************************/

int lookup_ethertype(uint16_t type);

#endif
#endif
