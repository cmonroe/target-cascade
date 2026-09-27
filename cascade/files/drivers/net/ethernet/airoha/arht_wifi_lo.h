/*********************************************************************************
 * decleration and function prototype for tunnel offload module
 *
 * Copyright (C) 2025 Econet Technologies, Corp.
 * All Rights Reserved.
 *
 *********************************************************************************/
#ifndef ARHT_WIFI_LO_H_
#define	ARHT_WIFI_LO_H_

#include <linux/list.h>
#include <linux/timer.h>
#include <linux/cache.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/workqueue.h>

#define SK_MARK_WIFI_LO	0xAE000001
#ifndef MSG_TRUNC
#define MSG_TRUNC 0x20
#endif

#define WIFI_LO_MAX_NUM		32
#define WIFI_LO_MAX_APPS	16
#define WIFI_LO_EXPIRE_TIME	(1 * HZ)
#define WIFI_LO_PROC_BUFSZ	4096

/* Rate-limit last_tx cache-line writes on the TX fast path. The timer
 * only cares about "activity in the last WIFI_LO_EXPIRE_TIME (1 s)", so
 * a cadence of a few writes per second is enough — this kills per-packet
 * false sharing of the entry cache line between CPUs. */
#define WIFI_LO_LAST_TX_MIN_INTERVAL	(HZ / 4)

/* Session flag bits (all live in a single unsigned long, `flags`,
 * so we can use test_bit / test_and_set_bit lock-free on the fast path). */
#define WIFI_LO_F_VALID		0
#define WIFI_LO_F_SKIP_COPY	1
#define WIFI_LO_F_IS_WIFI	2
#define WIFI_LO_F_DEV_RELEASING	3	/* rcu_head in use for dev release */

/* Hashtable sizing for O(1) session lookup (7). 5 bits => 32 buckets,
 * matches WIFI_LO_MAX_NUM. */
#define WIFI_LO_HT_BITS		5

#define APPEND(fmt, ...) do { \
	n = scnprintf(pb + len, remain, fmt, ##__VA_ARGS__); \
	len += n; \
	remain -= n; \
} while (0)

#define LRO_AGG_NUM_DEFAULT        18
#define LRO_AGG_NUM_MIN            1
#define LRO_AGG_NUM_MAX            255
#define PHY_REG_CDM1_LRO_LIMIT     0x1fb50484
#define PHY_REG_CDM2_LRO_LIMIT     0x1fb51484
#define CDM_LRO_AGG_NUM_MASK_VAL   0x00FF0000
#define CDM_LRO_AGG_NUM_SHIFT      16

#define PPE_CPU_REASON_BIT		27
#define PPE_CPU_MASK			(0x1F << PPE_CPU_REASON_BIT)

#define REG_FE_LAN_MAC_H		0x1fb50040
#define REG_FE_MAC_LMIN(_n)		((_n) + 0x04)

/*
 * struct wifi_lo layout is tuned so every field the RX/TX fast path
 * touches lives in the first cache line (64B on Cortex-A53). Cold
 * teardown-only members (dst, timer, hlist links used only on
 * add/remove) fall on the second line. Do not reorder without
 * re-measuring.
 */
struct wifi_lo {
	/* --- hot: read on every fast-path packet & every table scan --- */
	unsigned long		flags;		/* VALID / SKIP_COPY / IS_WIFI /
						 * DEV_RELEASING */
	u16			lport;
	u16			rport;
	u16			hash;
	u16			pad0;
	struct sock		*sk;
	struct net_device	*dev;
	unsigned long		last_tx;

	/* --- cold: session lifecycle only --- */
	struct dst_entry	*tx_dst;
	struct hlist_node	port_node;	/* by (lport,rport) */
	struct hlist_node	hash_node;	/* by lo->hash */
	struct timer_list	age_timer;
	/* Pending netdev release. dev to dev_put is snapshotted here while
	 * we wait a grace period, so wifi_lo_prepare_gro readers that
	 * observed the pre-xchg lo->dev finish. */
	struct rcu_head		dev_rcu;
	struct net_device	*dev_pending_release;
} ____cacheline_aligned;

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
#define FOE_ENTRY_NUM(skb)		(skb_get_hash(skb) & 0xFFFF)

/*
 * Trigger-app list (which processes' outgoing packets create a
 * session). Read on every LOCAL_OUT for a not-yet-tracked flow --
 * must be lock-free from softirq. Snapshot published under a mutex,
 * read under RCU.
 */
struct wifi_lo_apps {
	struct rcu_head	rcu;
	unsigned int	count;
	/* Interned first byte per entry for a cheap prefilter -- skip
	 * strcmp when current->comm[0] doesn't match. */
	char		first[WIFI_LO_MAX_APPS];
	char		name[WIFI_LO_MAX_APPS][32];
};

/*
 * -------------------------------------------------------------------------
 *   Symbols pulled in from other airoha_eth translation units.
 * -------------------------------------------------------------------------
 */
extern struct airoha_eth *glb_eth;

extern int airoha_ppe_tx_handler(struct sk_buff *skb, struct port_info *pinfo, u8 fport);
extern u32 get_frame_engine_data(u32 reg);
extern void set_frame_engine_data(u32 reg, u32 val);
extern int (*offload_eth_fast_tx_hook)(struct sk_buff *skb, int channel);
extern int (*arht_force_to_cpu_prepare_gro_hook)(struct sk_buff *skb, bool ipv6);
extern int (*local_out_pingpong_hook)(struct sk_buff *skb);
extern int (*dynamic_ifc_sock_in_use_hook)(u16 lport, u16 rport);
extern int (*ra_sw_nat_hook_clean_entry_by_port)(u16 src_port, u16 dest_port);
extern struct dst_entry *arht_gen_dst_clone(struct dst_entry *dst);

#endif
