// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2024 AIROHA Inc
 */
#ifndef AIROHA_DP_API_H
#define AIROHA_DP_API_H

#include <linux/etherdevice.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/of_net.h>
#include <linux/platform_device.h>
#include <linux/reset.h>
#include <linux/tcp.h>
#include <linux/u64_stats_sync.h>
#include <net/dsa.h>
#include <net/page_pool/helpers.h>
#include <uapi/linux/ppp_defs.h>
#include <linux/types.h>
#include <net/ipv6.h>
#include <linux/if_pppox.h>
#include <net/pkt_cls.h>
#include <linux/ip.h>

#include "arht_hook/arht_hook.h"
#include "arht_hook/ecnt_hook_fe_type.h"
#include <arht_hook/ecnt_hook_ifc.h>
#include <arht_hook/ecnt_hook_ifc_type.h>


#define TX_WRED_THR_NUM                         (5)
#define TX_WRED_PROBABILITY_NUM                 (4)
#define MAX_NAME_LENGTH             (16)

#define PER_CHNL_TICKSEL_NUM (2)


#define REG_QDMA_GLOBAL_CFG			0x0004
#define REG_QDMA_TXQ_TOTAL_FAST_THR			0x10d4
#define TXQ_CNGST_TXQ_TOTAL_MAX_THR_SHIFT			(16)
#define TXQ_CNGST_TXQ_TOTAL_MAX_THR_MASK			(0xFFFF<<TXQ_CNGST_TXQ_TOTAL_MAX_THR_SHIFT)
#define TXQ_CNGST_TXQ_TOTAL_MIN_THR_SHIFT			(0)
#define TXQ_CNGST_TXQ_TOTAL_MIN_THR_MASK			(0xFFFF<<TXQ_CNGST_TXQ_TOTAL_MIN_THR_SHIFT)

//fast totalmin equal to 8/10share_free
#define BUFF_FAST_TOTAL_MAX_THRH 0x2286
#define BUFF_FAST_TOTAL_MIN_THRH 0x2286

#define AIROHA_MAX_IDX_FOR_GEMPORT_RATELIMIT 31
#define AIROHA_MIN_IDX_FOR_GEMPORT_RATELIMIT 0
#define AIROHA_SKB_MARK_MASK_FOR_GEMPORT_RATELIMIT  GENMASK(31, 26)
#define AIROHA_SKB_MARK_SHIFT_FOR_GEMPORT_RATELIMIT  26

/***************************************
 fe resource manage variables
***************************************/
#define METER_MAX_NUM       127
#define NAME_LENGTH         16
#define METER_GROUP_NUM     4

#define CONFIG_FLOWCNT_MAX_DROUP_NUM            (3)
#define CONFIG_FLOWCNT_GRP0_MAX_IDX_NUM         (63)	/* ACNT_GRP[5:0] */
#define CONFIG_FLOWCNT_GRP1_MAX_IDX_NUM         (31)	/* ACNT_GRP[10:6] */
#define CONFIG_FLOWCNT_GRP2_MAX_IDX_NUM         (127)	/* MTR_GRP[6:0] */

#define CONFIG_QDMA_QUEUE                   8
#define QDMA_RX_DSCP_MSG_LENS	(16)

#define AIROHA_DEBUG_LEVEL_NONE 0
#define AIROHA_DEBUG_LEVEL_ERR  1
#define AIROHA_DEBUG_LEVEL_WARN 2
#define AIROHA_DEBUG_LEVEL_INFO 3
#define AIROHA_DEBUG_LEVEL_DBG  4
#define AIROHA_L4S_DISABLE	0
#define AIROHA_L4S_ENABLE	1
#define AIROHA_L4S_DEBUG	2
#define AIROHA_L4S_SETQID	3
#define AIROHA_L4S_AI		4
#define AIROHA_L4S_QDMA_WATER_MARK	7

// Global variable to store the debug level
extern int airoha_debug_level;
extern int airoha_l4s_flag;

// Macro to control logging based on the debug level
#define AIROHA_LOG(level, fmt, ...) \
    do { \
        if (level <= airoha_debug_level) \
            printk(fmt, ##__VA_ARGS__); \
    } while (0)
#define AIROHA_L4S_LOG(level, fmt, ...)\
	do { \
        if (level <= airoha_l4s_flag) \
            printk(KERN_ALERT fmt, ##__VA_ARGS__); \
	} while (0)
#define AIROHA_L4S_FLAG	(AIROHA_L4S_ENABLE <= airoha_l4s_flag)


struct ring_dscp_map {
    int ring;
    int dscp_num;
};
#define DEFAULT_RING_NUM	16


#define AIROHA_MAX_GSW_LAN_PORTS	4
#define PPE_NUM_ENTRIES			(PPE_SRAM_NUM_ENTRIES + PPE_DRAM_NUM_ENTRIES)
#define PPE_HASH_MASK			(PPE_NUM_ENTRIES - 1)
#define WIFI_DEV 0xcc
#define LAN_IDX_FROM_SPTAG(_sptag)		\
		(((_sptag) == 4) ? LAN4 :	\
		 ((_sptag) == 3) ? LAN3 :	\
		 ((_sptag) == 2) ? LAN2 :	\
		 ((_sptag) == 1) ? LAN1 : 0)
		 
		 
#define LAN_IDX_FROM_TX_SPTAG(_sptag)		\
		(((_sptag) == 16)? 4 :	\
		 ((_sptag) == 8) ? 3 :	\
		 ((_sptag) == 4) ? 2 :	\
		 ((_sptag) == 2) ? 1 : 0)	

struct pwan_msg{
	u32 msg0 ;
	u32 msg1 ;
	u32 msg2 ;
	u32 msg3 ;
};
enum airoha_ports_index {
	AIROHA_PORTS_GDM1_ID = 0,
	AIROHA_PORTS_GDM2_ID = 1,
	AIROHA_PORTS_GDM3_ID = 2,
	AIROHA_PORTS_GDM4_ID = 3,
};


enum {
	ARHT_GSW_LANPORT_1 = 0,
	ARHT_GSW_LANPORT_2,
	ARHT_GSW_LANPORT_3,
	ARHT_GSW_LANPORT_4,
	ARHT_ETH_PORT_0,
	ARHT_ETH_PORT_1,
	ARHT_ETH_PORT_2,
	ARHT_ETH_PORT_3,
	ARHT_ETH_PORT_4,
	ARHT_ETH_PORT_MAX,
};
enum {
	PON_RX_SUCCESS=0,
	PON_RX_FAIL,
};

#define SPEED_TEST_SUCCESS	0
#define TR471_UPSTREAM_SUCCESS	0
#define TR471_DOWNSTREAM_SUCCESS	2
#define DP_SPEED_UP 304
#define DP_SPEED_DOWNLOAD_ACK 305
#define HSGMII_LAN_ETH_CHNL						(13)

#define FOE_ENTRY_NUM(skb)		(skb_get_hash(skb) & 0xFFFF)

struct port_info {
    unsigned long int tsid:8;
    unsigned long int channel:5;
    unsigned long int nbq:5;
    unsigned long int fast:1;
    unsigned long int txq:4;
    unsigned long int atm_pppoa:1;
    unsigned long int atm_ipoa:1;
    unsigned long int atm_vc_mux:1;
    unsigned long int eth_macSTagEn:1;
	unsigned long int eth_is_wan:1;
    unsigned long int ds_to_qdma:1;
    unsigned long int ds_need_offload:1;
    unsigned long int force_high_priority_ring:1;
	unsigned long int txq_is_valid:1;
    unsigned long int stag:16;
    unsigned long int magic:16;
	unsigned long int udf:8;//add for inode wifi 
};


/* XFI_MAC */
#define AIROHA_PCS_XFI_MAC_XFI_GIB_CFG		0x0
#define   AIROHA_PCS_XFI_RX_FRAG_LEN		GENMASK(26, 22)
#define   AIROHA_PCS_XFI_TX_FRAG_LEN		GENMASK(21, 17)
#define   AIROHA_PCS_XFI_IPG_NUM		GENMASK(15, 10)
#define   AIROHA_PCS_XFI_TX_FC_EN		BIT(5)
#define   AIROHA_PCS_XFI_RX_FC_EN		BIT(4)
#define   AIROHA_PCS_XFI_RXMPI_STOP		BIT(3)
#define   AIROHA_PCS_XFI_RXMBI_STOP		BIT(2)
#define   AIROHA_PCS_XFI_TXMPI_STOP		BIT(1)
#define   AIROHA_PCS_XFI_TXMBI_STOP		BIT(0)
#define AIROHA_PCS_XFI_MAC_XFI_LOGIC_RST	0x10
#define   AIROHA_PCS_XFI_MAC_LOGIC_RST		BIT(0)
#define AIROHA_PCS_XFI_MAC_XFI_MACADDRH		0x60
#define   AIROHA_PCS_XFI_MAC_MACADDRH		GENMASK(15, 0)
#define AIROHA_PCS_XFI_MAC_XFI_MACADDRL		0x64
#define   AIROHA_PCS_XFI_MAC_MACADDRL		GENMASK(31, 0)
#define AIROHA_PCS_XFI_MAC_XFI_CNT_CLR		0x100
#define   AIROHA_PCS_XFI_GLB_CNT_CLR		BIT(0)


extern struct airoha_eth *glb_eth;

#ifndef UINT32
#define UINT32
typedef uint32_t uint32; 		/* 32-bit unsigned integer      */
#endif

typedef  unsigned long long uint64; 

#define AIROHA_TSO_BIT		26
#define AIROHA_PPE_CPU_REASON_BIT		27
//#define AIROHA_PPE_CPU_REASON			(1<<AIROHA_PPE_CPU_REASON_BIT)
#define AIROHA_PPE_CPU_MASK				(0x1F<<AIROHA_PPE_CPU_REASON_BIT)
#define AIROHA_PPE_ENTRY_MASK			0xFFFF

#define VLAN_HLEN  4
#define ETH_ALEN   6
#define ETH_HLEN   14
#define PPE_CLEAR_OFFSET1 16
#define PPE_CLEAR_OFFSET2 40
#define PPE_CLEAR_OFFSET3 40
#define PPE_CLEAR_OFFSET4 24
#define SIZE_OF_FOE_ENTRY 80

#define FOE_INFO_LEN		    7

#define IS_IPV4_HNAPT(x)	((FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, (x)->ib1) == PPE_PKT_TYPE_IPV4_HNAPT) ? 1: 0)
#define IS_IPV4_HNAT(x)		((FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, (x)->ib1) == PPE_PKT_TYPE_IPV4_ROUTE) ? 1 : 0)
#define IS_L2_RRIDGE(x)	((FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, (x)->ib1) == PPE_PKT_TYPE_BRIDGE) ? 1 : 0)
#define IS_IPV4_DSLITE(x)	((FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, (x)->ib1) == PPE_PKT_TYPE_IPV4_DSLITE) ? 1 : 0)
#define IS_IPV6_3T_ROUTE(x)	((FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, (x)->ib1) == PPE_PKT_TYPE_IPV6_ROUTE_3T) ? 1 : 0)
#define IS_IPV6_5T_ROUTE(x)	((FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, (x)->ib1) == PPE_PKT_TYPE_IPV6_ROUTE_5T) ? 1 : 0)
#define IS_IPV6_6RD(x)		((FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, (x)->ib1) == PPE_PKT_TYPE_IPV6_6RD) ? 1: 0)
#define IS_IPV4_GRP(x)		(IS_IPV4_HNAPT(x) | IS_IPV4_HNAT(x) | IS_IPV4_DSLITE(x))
#define IS_IPV6_GRP(x)		(IS_IPV6_3T_ROUTE(x) | IS_IPV6_5T_ROUTE(x) | IS_IPV6_6RD(x))


enum hwnat_status {
        HWNAT_SUCCESS = 0,
        HWNAT_FAIL = 1,
        HWNAT_ENTRY_NOT_FOUND = 2
};


#define PPP_IP		0x21	/* Internet Protocol */
#define PPP_IPV6	0x57	/* Internet Protocol Version 6 */
enum FoeTblTcpUdp {
	TCP = 0,
	UDP = 1,
	ANY = 2
};
#define FOE_MAGIC_TR471_HW_TEST_UPSTREAM 0x729d
typedef struct {
	uint rx_byte_cnt_l;
	uint resv1;
	uint resv2;
	uint rx_byte_cnt_h;
	uint resv3;
	uint resv4;
	uint resv5;
	uint seq_drop_cnt			: 16 ;
	uint seq_err_cnt			: 16 ;
} TR471_RX_DSCP_T ;

enum {
	SRC_MAC = 0,
	DST_MAC = 1,
	SRC_DST_MAC = 2
};
/************************************************************************
*                  FE Defines/MACROS
*************************************************************************
*/



/************************************************************************
*               F U N C T I O N   D E C L A R A T I O N S
                I N L I N E  F U N C T I O N  D E F I N I T I O N S
*************************************************************************
*/


#define FOE_MAGIC_GE		    0x7275
#define FOE_MAGIC_ATM		    0x7277
#define FOE_MAGIC_PTM		    0x7278
#define FOE_MAGIC_EPON		    0x7279
#define FOE_MAGIC_GPON		    0x727a
#define FOE_MAGIC_XSI		    0x7284
#define FOE_MAGIC_AE_WAN	    0x7295
#define FOE_MAGIC_WLAN		    0x7274


#define	FOE_MAGIC_GRE_HWDOWN_2	0x7298
#define FOE_MAGIC_XSI_GDM4		0x729a
#define PPE_MAGIC_DYNAMIC_IFC 	0x72b2

struct airoha_gdm_dev;
struct airoha_queue;
struct airoha_eth;
struct airoha_qdma;
struct airoha_qdma_desc;
int airoha_qdma_multicast_init(struct airoha_eth *eth);
int airoha_register_port_debugfs(struct airoha_gdm_dev *dev);
void airoha_eth_qdma_fastpath_default_cfg(struct airoha_eth *eth);
int is_ethmac_nvmem_cell_available(struct airoha_eth *eth);
int get_ethmac_from_dts(struct airoha_eth *eth);
int fe_api_set_channel_retire_one(struct ecnt_fe_data *fe_data);

typedef int (*fe_api_op_t)(struct ecnt_fe_data *fe_data);

struct airoha_eth;
struct airoha_gdm_dev;
struct airoha_qdma;
enum trtcm_mode_type;
enum trtcm_param_type ;
void airoha_eth_monitor_workqueue_init(void);
void airoha_eth_monitor_workqueue_exit(void);
void airoha_sfu_flow_offload_workqueue_init(void);
void airoha_sfu_trigger_offload_work(void);
int airoha_is_pon_sfu_mode(void);

typedef struct
{
	unsigned int proto;/*ipv4 or ipv6*/
	unsigned int vlan_tag_num;
	unsigned short outer_tci;
	unsigned short inner_tci;
	unsigned char grp_addr[16];
	unsigned char src_addr[16];
	struct net_device* ori_dev;
	unsigned short br_vid;
}MULTICAST_INFO_t;

typedef struct
{
	struct list_head list;
	MULTICAST_INFO_t ppe_multicast_info;
	unsigned int foe_index;
	unsigned int port_mask;/*bit0-3 for eth0.1-eth0.4;bit16-23 for ra0-ra7;bit24-31 for rai0-rai7;other reserve*/
    unsigned int local;
	unsigned char state;
	struct timer_list age_timer;
	unsigned char valid;
	atomic_t deleted;
}MULTICAST_HWNATENTRY_t;


enum
{
	PPE_MULTICAST_HWNATENTRY_STATE_UNBIND=0,
	PPE_MULTICAST_HWNATENTRY_STATE_BINDED,
	PPE_MULTICAST_HWNATENTRY_STATE_DROP,
};

enum hwnat_mcast_status {
        HWNAT_MCAST_INVALID = 0,
        HWNAT_MCAST_VALID = 1
};


#define HWNAT_LAN_IF_MAXNUM	12
#define HWNAT_LAN_IF_BASE		0//0~7 is lan interface
#define HWNAT_OLT_IF_BASE		13
#define HWNAT_WLAN_IF_MAXNUM	16 //16 is max wifi interface
#define HWNAT_WLAN_IF_BASE		16//16  is base
#define HWNAT_LAN_IF_MASK		(0x3FFF)
#define HWNAT_USB_IF_BASE		15
#define HWNAT_USB_IF_NUM		1 
#define HWNAT_USB_IF_MASK		(0x1)
#define HWNAT_XSI_IF_BASE		14
#define HWNAT_XSI_IF_NUM		1 
#define HWNAT_XSI_IF_MASK		(0x1)

#define HWNAT_OFF_UNI	1
#define HWNAT_OFF_MUL4	2
#define HWNAT_OFF_MUL6	3

#define FOE_OPE_GETENTRYNUM     0
#define FOE_OPE_CLEARENTRY      1

#define LRO_RING_NUM    4
#define LRO_RING_START  0xC
#define LRO_RING_END    0XF

enum lro_ring_state{
	LRO_RING_FREE = 0,
	LRO_RING_RESERVED,
};

enum
{
	PPE_MULTICAST_FORWARD_STATE_LAN_ONLY = 0,
	PPE_MULTICAST_FORWARD_STATE_WLAN_ONLY,
	PPE_MULTICAST_FORWARD_STATE_LAN_WLAN,
	PPE_MULTICAST_FORWARD_STATE_LAN_XSI,
	PPE_MULTICAST_FORWARD_STATE_XSI_ONLY,
	PPE_MULTICAST_FORWARD_STATE_XSI_WLAN,
	PPE_MULTICAST_FORWARD_STATE_LAN_HSGMII_1toN,
	PPE_MULTICAST_FORWARD_STATE_UNKNOWN,
};

#define IS_ETH_SERDES 0x10
#define IS_USB_SERDES 0x20
#define IS_PCIE0_SERDES 0x40
#define IS_PCIE1_SERDES 0x80

//for AN7581
#define ETH_SERDES_FPORT FE_PSE_PORT_GDM4
#define USB_SERDES_FPORT FE_PSE_PORT_GDM4
#define PCIE0_SERDES_FPORT FE_PSE_PORT_GDM3
#define PCIE1_SERDES_FPORT FE_PSE_PORT_GDM3

//for AN7581
#define ETH_SERDES_NBQ 		0
#define USB_SERDES_NBQ 		1
#define PCIE0_SERDES_NBQ 	4
#define PCIE1_SERDES_NBQ 	5
#define ETH_SERDES_CHNL 	0
#define USB_SERDES_CHNL 	0
#define PCIE0_SERDES_CHNL 	0
#define PCIE1_SERDES_CHNL 	0

enum FoeCpuReason {
	IPTU_CSUMF = 0x1, /* ipv4, tcp udp checksum fail */
	TTL_0 = 0x02, /* IPv4(IPv6) TTL(hop limit) = 0 */
	HAS_OPTION_HEADER = 0x03, /* IPv4(IPv6) has option(extension) header */
	NO_FLOW_IS_ASSIGNED = 0x07,	/* No flow is assigned */
	IPV4_WITH_FRAGMENT = 0x08,	/* IPv4 HNAT doesn't support IPv4 /w fragment */
	IPV4_HNAPT_DSLITE_WITH_FRAGMENT = 0x09,	/* IPv4 HNAPT/DS-Lite doesn't support IPv4 /w fragment */
	IPV4_HNAPT_DSLITE_WITHOUT_TCP_UDP = 0x0A,	/* IPv4 HNAPT/DS-Lite can't find TCP/UDP sport/dport */
	IPV6_5T_6RD_WITHOUT_TCP_UDP = 0x0B,	/* IPv6 5T-route/6RD can't find TCP/UDP sport/dport */
	TCP_FIN_SYN_RST = 0x0C,	/* Ingress packet is TCP fin/syn/rst (for IPv4 NAPT/DS-Lite or IPv6 5T-route/6RD) */
	UN_HIT = 0x0D,		/* FOE Un-hit */
	HIT_UNBIND = 0x0E,	/* FOE Hit unbind */
	HIT_UNBIND_RATE_REACH = 0x0F,	/* FOE Hit unbind & rate reach */
	HIT_BIND_TCP_FIN = 0x10,	/* Hit bind PPE TCP FIN entry */
	HIT_BIND_TTL_1 = 0x11,	/* Hit bind PPE entry and TTL(hop limit) = 1 and TTL(hot limit) - 1 */
	HIT_BIND_WITH_VLAN_VIOLATION = 0x12,	/* Hit bind and VLAN replacement violation
						   (Ingress 1(0) VLAN layers and egress 4(3 or 4) VLAN layers) */
	HIT_BIND_KEEPALIVE_UC_OLD_HDR = 0x13,	/* Hit bind and keep alive with unicast old-header packet */
	HIT_BIND_KEEPALIVE_MC_NEW_HDR = 0x14,	/* Hit bind and keep alive with multicast new-header packet */
	HIT_BIND_KEEPALIVE_DUP_OLD_HDR = 0x15,	/* Hit bind and keep alive with duplicate old-header packet */
	HIT_BIND_FORCE_TO_CPU = 0x16,	/* FOE Hit bind & force to CPU */
	HIT_BIND_WITH_OPTION_HEADER = 0x17, /* Hit bind and remove tunnel IP header, but inner IP has option/next header */
	HIT_BIND_MUL_CPU = 0x18, /*  Hit Bind and Multicast to CPU*/
	HIT_BIND_MUL_CPUR = 0x19, /*  Hit Bind and Multicast to CPU force to CPU*/
	HIT_PREBIND = 0x1A, /*  Hit Pre-Bind*/
	UNHIT_CLASS = 0x1B, /*  UnHit CLASS Packet*/
	HIT_BIND_EXCEED_MTU = 0x1C,	/* Hit bind and exceed MTU */
	NOT_THROUGH_PPE = 0x1E /* Packet not go through PPE */
};
/* -----------------PSE Port Number Info ----------------- */

#define PSE_PORT_NUM                (11) /* Port-0 ~ Port-9 for normal use , Port-15 for free */
#define PSE_PORT0_QUEUE_NUM         (6)
#define PSE_PORT1_QUEUE_NUM         (6)
#define PSE_PORT2_QUEUE_NUM         (32)
#define PSE_PORT3_QUEUE_NUM         (6)
#define PSE_PORT4_QUEUE_NUM         (4)
#define PSE_PORT5_QUEUE_NUM         (6)


//FE CNT

#define PSE_SHARE_BUF_USED_MAX_MASK	(0x7fff)
#define REG_FE_PSE_BUF_USE_REC			 0x100 /* 30:16, SHARE_USED_CNT_MAX; 14:0, FQ_CNT_MIN */
#define PSE_SHARE_BUF_USED_CNT_SHIFT	(16)
#define PSE_SHARE_BUF_USED_CNT_MASK	(0x7fff)
#define PSE_SHARE_BUF_FREE_CNT_MASK	(0x7fff)
#define REG_FE_PSE_SHARE_BUF_STA		0x104
#define REG_FE_PSE_PORT_STA        		0x10C
#define REG_FE_PSE_OQ_PCNT				0x110
#define REG_FE_PSE_OQ_PCNT_REC			0x114 /* 29:16, OQ_CNT_MAX; 13:0, OQ_REAL_CNT_MAX */
#define REG_FE_PSE_FQFC_CFG_STA(i)		(0x118 + (i<<2))
#define REG_FE_PSE_FQFC_CFG_STA0		0x118
#define REG_FE_PSE_FQFC_CFG_STA1		0x11C
#define REG_FE_PSE_DROP_CNT(i)	   		(0x120 + (i<<2))
#define REG_FE_PSE_DROP_CNT_0      		0x120
#define REG_FE_PSE_DROP_CNT_1      		0x124
#define REG_FE_PSE_DROP_CNT_2      		0x128
#define REG_FE_PSE_DROP_CNT_3      		0x12C
#define REG_FE_PSE_DROP_CNT_4      		0x130
#define REG_FE_PSE_DROP_CNT_5      		0x134
#define REG_FE_PSE_DROP_CNT_6      		0x138
#define REG_FE_PSE_DROP_CNT_7      		0x13C
#define REG_FE_PSE_DROP_CNT_8      		0x140
#define REG_FE_PSE_DROP_CNT_9      		0x144
#define REG_FE_PSE_PORT_Q_USE_STA(i)	(0x150 + (i<<2))
#define REG_FE_PSE_PORT_Q_USE_STA0		0x150/* 30:16, P0_IQ_PCNT; 14:0, P0_OQ_PCNT */
#define REG_FE_PSE_PORT_Q_USE_STA1		0x154
#define REG_FE_PSE_PORT_Q_USE_STA2		0x158
#define REG_FE_PSE_PORT_Q_USE_STA3		0x15C
#define REG_FE_PSE_PORT_Q_USE_STA4		0x160
#define REG_FE_PSE_PORT_Q_USE_STA5		0x164
#define REG_FE_PSE_PORT_Q_USE_STA6		0x168
#define REG_FE_PSE_PORT_Q_USE_STA7		0x16C
#define REG_FE_PSE_PORT_Q_USE_STA8		0x170
#define REG_FE_PSE_PORT_Q_USE_STA9		0x174


#define CDM_CNT_BASE(_n)			\
	((_n) == 2 ? (CDM_BASE(2) + 0x100) : (CDM_BASE(1) + 0x100))
	
#define REG_FE_GDM_TX_GET_PKT_CNT(_n)		(GDM_BASE(_n) + 0x100)

/*CDM1*/
#define CDMA1_TX_OK_CNT             (CDM_CNT_BASE(1) + 0x80)
#define CDMA1_RXCPU_OK_CNT          (CDM_CNT_BASE(1) + 0x90)
#define CDMA1_RXHWF_OK_CNT          (CDM_CNT_BASE(1) + 0x94)

#define CDMA1_RXCPU_KA_CNT          (CDM_CNT_BASE(1) + 0x8c)
#define CDMA1_RXHWF_FAST_ALL_CNT    (CDM_CNT_BASE(1) + 0x98)
#define CDMA1_RXOQ5_OK_CNT			(CDM_CNT_BASE(1) + 0x9c) /* default for TSO */
#define CDMA1_RXCPU_DROP_CNT        (CDM_CNT_BASE(1) + 0xa0)
#define CDMA1_RXHWF_DROP_CNT        (CDM_CNT_BASE(1) + 0xa4)
#define CDMA1_RXHWF_FAST_DROP_CNT   (CDM_CNT_BASE(1) + 0xa8)
#define CDMA1_RXOQ5_DROP_CNT		(CDM_CNT_BASE(1) + 0xac) /* default for TSO */
#define CDMA1_RXCPU0_OK_CNT         (CDM_CNT_BASE(1) + 0xb0)
#define CDMA1_RXCPU1_OK_CNT         (CDM_CNT_BASE(1) + 0xb4)
#define CDMA1_RXCPU2_OK_CNT         (CDM_CNT_BASE(1) + 0xb8)
#define CDMA1_RXCPU3_OK_CNT         (CDM_CNT_BASE(1) + 0xbc)
#define CDMA1_RXCPU0_DROP_CNT       (CDM_CNT_BASE(1) + 0xd0)
#define CDMA1_RXCPU1_DROP_CNT       (CDM_CNT_BASE(1) + 0xd4)
#define CDMA1_RXCPU2_DROP_CNT       (CDM_CNT_BASE(1) + 0xd8)
#define CDMA1_RXCPU3_DROP_CNT       (CDM_CNT_BASE(1) + 0xdc)


/*CDM2*/

#define CDMA2_TX_OK_CNT             (CDM_CNT_BASE(2) + 0x80)
#define CDMA2_RXCPU_OK_CNT          (CDM_CNT_BASE(2) + 0x90)
#define CDMA2_RXHWF_OK_CNT          (CDM_CNT_BASE(2) + 0x94)
#define CDMA2_RXCPU_KA_CNT          (CDM_CNT_BASE(2) + 0x8c)
#define CDMA2_RXHWF_FAST_ALL_CNT    (CDM_CNT_BASE(2) + 0x98)
#define CDMA2_RXOQ5_OK_CNT			(CDM_CNT_BASE(2) + 0x9c) /* default for TSO */
#define CDMA2_RXCPU_DROP_CNT        (CDM_CNT_BASE(2) + 0xa0)
#define CDMA2_RXHWF_DROP_CNT        (CDM_CNT_BASE(2) + 0xa4)
#define CDMA2_RXHWF_FAST_DROP_CNT   (CDM_CNT_BASE(2) + 0xa8)
#define CDMA2_RXOQ5_DROP_CNT		(CDM_CNT_BASE(2) + 0xac) /* default for TSO */
#define CDMA2_RXCPU0_OK_CNT         (CDM_CNT_BASE(2) + 0xb0)
#define CDMA2_RXCPU1_OK_CNT         (CDM_CNT_BASE(2) + 0xb4)
#define CDMA2_RXCPU2_OK_CNT         (CDM_CNT_BASE(2) + 0xb8)
#define CDMA2_RXCPU3_OK_CNT         (CDM_CNT_BASE(2) + 0xbc)
#define CDMA2_RXCPU0_DROP_CNT       (CDM_CNT_BASE(2) + 0xd0)
#define CDMA2_RXCPU1_DROP_CNT       (CDM_CNT_BASE(2) + 0xd4)
#define CDMA2_RXCPU2_DROP_CNT       (CDM_CNT_BASE(2) + 0xd8)
#define CDMA2_RXCPU3_DROP_CNT       (CDM_CNT_BASE(2) + 0xdc)


#define REG_FAQ_CFG(_n)			(CDM_BASE(_n) + 0x00b0)
#define FAQ_EN_MASK				BIT(0)

#define REG_FAQTHR_CFG(_n)		(CDM_BASE(_n) + 0x00b4)

#define REG_QBI_FTTR_CHANNEL_CFG	0x2068

typedef enum{
	LAN_PORT_1 = 0,   /* meter group 1, meter index 0 */
	LAN_PORT_2,
	LAN_PORT_3,
	LAN_PORT_4,
	LAN_PORT_5,
	LAN_PORT_6,
	LAN_PORT_7,
	LAN_PORT_8,
	LAN_PORT_9,
	LAN_PORT_10,
	LAN_PORT_11,
	LAN_PORT_12,
	LAN_PORT_13,
	LAN_PORT_14,
	LAN_PORT_15,
	LAN_PORT_MAX
}lan_port_t;

static const struct{
	const char *dev_name;
	unsigned short meter_idx;
}dev_meter_map[]={
	{"lan1", LAN_PORT_1},
	{"lan2", LAN_PORT_2},
	{"lan3", LAN_PORT_3},
	{"lan4", LAN_PORT_4},
	{"eth2", LAN_PORT_5},
	{"eth3", LAN_PORT_6},
	{"eth4", LAN_PORT_7},
	{"eth5", LAN_PORT_8},
	{NULL, LAN_PORT_MAX}
};

#define LINK_SPEED_2500M 2500
#define LINK_SPEED_1000M 1000


/* previous prototype for arht_ap_api.c */
struct port_info;
struct airoha_foe_entry;
struct airoha_ppe;

u32 get_fe_ppe_data(u32 reg);
void set_fe_ppe_data(u32 reg, u32 val);
u32 get_frame_engine_data(u32 reg);
void set_frame_engine_data(u32 reg, u32 val);
int cmpMacInfo(uint8_t* Dst, uint8_t* Src);
u8 get_dscp_from_skb(struct sk_buff *skb, int type);
int airoha_eth_transmit_packet(struct sk_buff *skb, u32 txmsg0, u32 txmsg1, struct port_info *pinfo);
void clear_foe_entry(struct airoha_foe_entry *hwe);
int arht_set_multicast_hwnat_info(struct sk_buff* skb, struct airoha_foe_entry *hwe);
int arht_multicast_hwnat_state_handler(struct airoha_foe_entry *hwe, unsigned int foe_index,unsigned int port_mask,unsigned int local,int priority);
int arht_multicast_get_channel_by_stag(unsigned int stag_dp);
int arht_multicast_hwnat_clean(unsigned int foe_index);
int arht_multicast_hwnat_list_update(MULTICAST_HWNATENTRY_t* entry, unsigned int update_mode,unsigned int port_mask,unsigned int local);
int arht_multicast_hwnat_list_update_lan(MULTICAST_HWNATENTRY_t* entry, unsigned int update_mode,unsigned int port_mask,unsigned int local);
int32_t FillSpeedtestEntryInfo(struct sk_buff * skb, struct airoha_foe_entry *foe_entry);
int isValidPpeEntry(struct sk_buff *skb, struct airoha_foe_entry *foe_entry);
#if defined(CONFIG_SUPPORT_QDMALAN_TR471)
void SetSpeedtestPortInfo(struct airoha_foe_entry *foe_entry, struct port_info *pinfo, u32 fport);
int speedtest_lan_tx_offload(struct sk_buff *skb, struct airoha_foe_entry *foe_entry, struct airoha_ppe *ppe, struct port_info *pinfo, u32 fport);
#else
void SetSpeedtestPortInfo(struct airoha_foe_entry * foe_entry, struct airoha_ppe *ppe,struct port_info *pinfo);
#endif
void SetTR471PortInfo(struct airoha_foe_entry * foe_entry);
int32_t FillTR471EntryInfo(struct sk_buff * skb, struct airoha_foe_entry *foe_entry);
int tr471_downstream_offload(struct sk_buff * skb,struct airoha_eth *eth);
void airoha_eth_monitor(struct work_struct *work);
int airoha_get_free_lro_ring(u32 foe_entry_idx);
struct dst_entry *arht_gen_dst_clone(struct dst_entry *dst);
void fast_path_speed_threshold_init(void);

void arht_ppe_foe_flow_update_wifi_npu_offload(struct sk_buff *skb, struct port_info *pinfo);
int arht_ppe_is_UNBIND_RATE_REACHED(struct sk_buff *skb);
void airoha_sfu_flow_offload_work(struct work_struct *work);
void airoha_ppe_update_txmsg(struct sk_buff *skb, u32 *msg1, u32 *msg2);
int is_from_lan_side(struct airoha_queue *q, struct airoha_eth *eth);
int airoha_qdma_lan_tx(struct sk_buff *skb,u32 tag,u8 fport,int channel,int qid, u32 *msg1, u32 *msg2);
unsigned int airoha_qdma_get_buf_size(struct airoha_qdma *qdma);
void airoha_set_default_acnt_meter_idx(struct airoha_foe_entry *hwe, int type);
void get_serdes_info_from_dev(struct airoha_gdm_dev *dev, int *serdes_idx, int *channel);
int arht_skip_copy_kprobe_enable(void);
void arht_skip_copy_kprobe_disable(void);

#endif /* AIROHA_DP_API_H */
