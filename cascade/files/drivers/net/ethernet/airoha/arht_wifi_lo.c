// SPDX-License-Identifier: GPL-2.0-only
/*
 * Airoha LOCAL_IN / LOCAL_OUT offload (wifi fast path)
 *
 * Copyright (C) 2025 AIROHA Inc
 *
 * IFC-free spin-off of arht-general_offload. Sessions live in
 * `wifi_lo_ety[]`; on the RX side, PPE-force-CPU'd packets go through
 * wifi_lo_prepare_gro() and are delivered via napi_gro_receive so they
 * traverse the standard bridge -> netfilter -> TCP datapath. The IP-layer
 * shortcut path is intentionally not provided by this module.
 *
 * The PPE FOE entry's magic is always PPE_MAGIC_LOCAL_IN_NS; airoha's
 * receive_hook dispatches force-CPU packets to
 * arht_force_to_cpu_prepare_gro_hook -> wifi_lo_prepare_gro.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/hashtable.h>
#include <linux/jump_label.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <net/inet_hashtables.h>
#include <net/protocol.h>
#include <net/dst.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_bridge.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <../net/bridge/br_private.h>
#include <ecnt_hook/ecnt_hook_gen_offload.h>
#include "airoha_eth.h"
#include "arht_wifi_lo.h"
#include "arht_kprobe.h"

/*
 * Placeholder for the dynamic-ifc hook. This symbol is normally defined and
 * EXPORT_SYMBOL'd by arht_dynamic_ifc.c, which is not built at the moment, so
 * arht_wifi_lo would otherwise fail to link. Provide a weak NULL definition so
 * it links standalone (a NULL hook simply means "no dynamic-ifc", matching the
 * disabled behaviour). When arht_dynamic_ifc.c is compiled back in, its strong
 * definition overrides this weak one automatically.
 * NOTE: remove this once arht_dynamic_ifc.c is restored.
 */
int (*dynamic_ifc_sock_in_use_hook)(u16 lport, u16 rport) __weak;

/*
 * -------------------------------------------------------------------------
 *   Module state
 * -------------------------------------------------------------------------
 */

static u32 lro_agg_num_orig_cdm1;
static u32 lro_agg_num_orig_cdm2;
static bool lro_agg_num_saved;
static int lro_agg_num = LRO_AGG_NUM_DEFAULT;

static struct wifi_lo wifi_lo_ety[WIFI_LO_MAX_NUM];

/*
 * Two hashtables for O(1) lookup (7):
 *   - port_ht: key = (lport,rport), used by TX/LOCAL_OUT and the RX
 *              netfilter LOCAL_IN capture step.
 *   - hash_ht: key = FOE_ENTRY_NUM stamped by the PPE, used by the RX
 *              force-CPU prepare_gro path.
 */
static DEFINE_HASHTABLE(wifi_lo_port_ht, WIFI_LO_HT_BITS);
static DEFINE_HASHTABLE(wifi_lo_hash_ht, WIFI_LO_HT_BITS);

/*
 * Whole-module fast-reject (1) + (8): when the session table is empty we
 * want the netfilter hooks to be free. Static-key path compiles to a
 * patched NOP in the idle case; the atomic counter is the source of truth
 * used to decide when to flip the key.
 *
 * static_branch_{enable,disable} take cpus_read_lock() and can sleep,
 * so we synchronise the key from a workqueue. Fast-path readers only
 * see the key (never the counter), so the small key-vs-counter skew
 * during transitions is harmless: at worst the RX/TX hook takes the
 * slow path for a few packets around session-add/expiry.
 */
static DEFINE_STATIC_KEY_FALSE(wifi_lo_active_key);
static atomic_t wifi_lo_active_num = ATOMIC_INIT(0);

static void wifi_lo_active_sync_work(struct work_struct *w);
static DECLARE_WORK(wifi_lo_active_sync, wifi_lo_active_sync_work);

static void wifi_lo_active_sync_work(struct work_struct *w)
{
	bool want = atomic_read(&wifi_lo_active_num) > 0;
	bool have = static_key_enabled(&wifi_lo_active_key.key);

	if (want && !have)
		static_branch_enable(&wifi_lo_active_key);
	else if (!want && have)
		static_branch_disable(&wifi_lo_active_key);
}

/*
 * Trigger-app list snapshot (see struct wifi_lo_apps in the header).
 * Read from softirq under RCU (LOCAL_OUT hook), published under mutex.
 */
static struct wifi_lo_apps __rcu *wifi_lo_apps_snap;
static DEFINE_MUTEX(wifi_lo_apps_mutex);

static DEFINE_SPINLOCK(wifi_lo_lock);

/*
 * LAN MAC cache (3). One-shot: populated on the first LOCAL_OUT that
 * needs it. Fixed after boot; no invalidation.
 */
static u8 wifi_lo_lan_mac[ETH_ALEN];
static unsigned int wifi_lo_lan_mac_ready;	/* 0 -> not populated; 1 -> populated */

/*
 * When true (default), the fast path is gated on lo->flags having
 * IS_WIFI set — i.e. we only offload flows whose ingress netdev was
 * confirmed to be an ieee80211 slave. Flipped to false via
 *   echo "wifi_only 0" > /proc/wifi_local_fastpath
 * to run the offload for any tracked TCP flow regardless of ingress
 * netdev type.
 */
static bool wifi_lo_wifi_only = true;

/*
 * -------------------------------------------------------------------------
 *   LRO aggregation-num register save/restore
 * -------------------------------------------------------------------------
 */

static void wifi_lo_lro_save_and_set_agg_num(int agg_num)
{
	u32 val;

	if (lro_agg_num_saved)
		return;

	val = get_frame_engine_data(PHY_REG_CDM1_LRO_LIMIT);
	lro_agg_num_orig_cdm1 = (val & CDM_LRO_AGG_NUM_MASK_VAL) >> CDM_LRO_AGG_NUM_SHIFT;

	val = get_frame_engine_data(PHY_REG_CDM2_LRO_LIMIT);
	lro_agg_num_orig_cdm2 = (val & CDM_LRO_AGG_NUM_MASK_VAL) >> CDM_LRO_AGG_NUM_SHIFT;

	lro_agg_num_saved = true;

	val = get_frame_engine_data(PHY_REG_CDM1_LRO_LIMIT);
	val &= ~CDM_LRO_AGG_NUM_MASK_VAL;
	val |= ((u32)agg_num << CDM_LRO_AGG_NUM_SHIFT) & CDM_LRO_AGG_NUM_MASK_VAL;
	set_frame_engine_data(PHY_REG_CDM1_LRO_LIMIT, val);

	val = get_frame_engine_data(PHY_REG_CDM2_LRO_LIMIT);
	val &= ~CDM_LRO_AGG_NUM_MASK_VAL;
	val |= ((u32)agg_num << CDM_LRO_AGG_NUM_SHIFT) & CDM_LRO_AGG_NUM_MASK_VAL;
	set_frame_engine_data(PHY_REG_CDM2_LRO_LIMIT, val);
}

static void wifi_lo_lro_restore_agg_num(void)
{
	u32 val;

	if (!lro_agg_num_saved)
		return;

	val = get_frame_engine_data(PHY_REG_CDM1_LRO_LIMIT);
	val &= ~CDM_LRO_AGG_NUM_MASK_VAL;
	val |= (lro_agg_num_orig_cdm1 << CDM_LRO_AGG_NUM_SHIFT) & CDM_LRO_AGG_NUM_MASK_VAL;
	set_frame_engine_data(PHY_REG_CDM1_LRO_LIMIT, val);

	val = get_frame_engine_data(PHY_REG_CDM2_LRO_LIMIT);
	val &= ~CDM_LRO_AGG_NUM_MASK_VAL;
	val |= (lro_agg_num_orig_cdm2 << CDM_LRO_AGG_NUM_SHIFT) & CDM_LRO_AGG_NUM_MASK_VAL;
	set_frame_engine_data(PHY_REG_CDM2_LRO_LIMIT, val);

	lro_agg_num_saved = false;
}

/*
 * -------------------------------------------------------------------------
 *   App-list helpers (RCU snapshot; (6))
 * -------------------------------------------------------------------------
 */

static bool wifi_lo_app_match(const char *comm)
{
	const struct wifi_lo_apps *snap;
	unsigned int i;
	bool ret = false;
	char c0;

	rcu_read_lock();
	snap = rcu_dereference(wifi_lo_apps_snap);
	if (!snap || !snap->count)
		goto out;

	c0 = comm[0];
	for (i = 0; i < snap->count; i++) {
		/* First-byte prefilter to skip strcmp when possible. */
		if (snap->first[i] != c0)
			continue;
		if (!strcmp(snap->name[i], comm)) {
			ret = true;
			break;
		}
	}
out:
	rcu_read_unlock();
	return ret;
}

/* Rebuild the snapshot with an added/removed entry, publish via RCU.
 * Caller must hold wifi_lo_apps_mutex. */
static struct wifi_lo_apps *wifi_lo_apps_clone(struct wifi_lo_apps *old)
{
	struct wifi_lo_apps *neu = kzalloc(sizeof(*neu), GFP_KERNEL);

	if (!neu)
		return NULL;
	if (old) {
		neu->count = old->count;
		memcpy(neu->first, old->first, sizeof(neu->first));
		memcpy(neu->name, old->name, sizeof(neu->name));
	}
	return neu;
}

static void wifi_lo_apps_free_rcu(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct wifi_lo_apps, rcu));
}

static int wifi_lo_app_add(const char *name)
{
	struct wifi_lo_apps *neu, *old;
	unsigned int i;
	int ret = 0;

	if (!name[0])
		return 0;

	mutex_lock(&wifi_lo_apps_mutex);
	old = rcu_dereference_protected(wifi_lo_apps_snap,
					lockdep_is_held(&wifi_lo_apps_mutex));

	if (old) {
		for (i = 0; i < old->count; i++) {
			if (!strcmp(old->name[i], name)) {
				ret = 1;
				goto unlock;
			}
		}
		if (old->count >= WIFI_LO_MAX_APPS)
			goto unlock;
	}

	neu = wifi_lo_apps_clone(old);
	if (!neu)
		goto unlock;

	i = neu->count;
	strscpy(neu->name[i], name, sizeof(neu->name[i]));
	neu->first[i] = neu->name[i][0];
	neu->count++;

	rcu_assign_pointer(wifi_lo_apps_snap, neu);
	if (old)
		call_rcu(&old->rcu, wifi_lo_apps_free_rcu);
	ret = 1;

unlock:
	mutex_unlock(&wifi_lo_apps_mutex);
	return ret;
}

static int wifi_lo_app_del(const char *name)
{
	struct wifi_lo_apps *neu, *old;
	unsigned int i, j;
	int ret = 0;

	mutex_lock(&wifi_lo_apps_mutex);
	old = rcu_dereference_protected(wifi_lo_apps_snap,
					lockdep_is_held(&wifi_lo_apps_mutex));
	if (!old)
		goto unlock;

	for (i = 0; i < old->count; i++)
		if (!strcmp(old->name[i], name))
			break;
	if (i == old->count)
		goto unlock;

	neu = wifi_lo_apps_clone(old);
	if (!neu)
		goto unlock;

	/* Remove index i, shift tail down. */
	for (j = i; j + 1 < neu->count; j++) {
		memcpy(neu->name[j], neu->name[j + 1], sizeof(neu->name[j]));
		neu->first[j] = neu->first[j + 1];
	}
	memset(neu->name[neu->count - 1], 0, sizeof(neu->name[0]));
	neu->first[neu->count - 1] = 0;
	neu->count--;

	rcu_assign_pointer(wifi_lo_apps_snap, neu);
	call_rcu(&old->rcu, wifi_lo_apps_free_rcu);
	ret = 1;

unlock:
	mutex_unlock(&wifi_lo_apps_mutex);
	return ret;
}

static bool wifi_lo_is_wifi_dev(struct net_device *dev)
{
    return dev && dev->ieee80211_ptr;
}

/*
 * Resolve the pre-bridge ingress netdev for a packet arriving at
 * IP LOCAL_IN. skb->dev at that point is the bridge master (br-lan)
 * for any packet that traversed the bridge, so we ask the bridge FDB
 * which port owns the source MAC.
 *
 * br_fdb_find_port has ASSERT_RTNL and we only hold rcu_read_lock here,
 * so call br_fdb_find_rcu directly instead.
 */
static struct net_device *wifi_lo_bridge_port(struct sk_buff *skb)
{
	struct net_bridge_fdb_entry *f;
	struct net_bridge *br;
	struct net_device *dev = NULL;

	if (!skb->dev || !netif_is_bridge_master(skb->dev) ||
	    !skb_mac_header_was_set(skb))
		return NULL;

	br = netdev_priv(skb->dev);

	rcu_read_lock();
	f = br_fdb_find_rcu(br, eth_hdr(skb)->h_source, 0);
	if (f) {
		const struct net_bridge_port *dst = READ_ONCE(f->dst);

		if (dst)
			dev = dst->dev;
	}
	rcu_read_unlock();

	return dev;
}

/*
 * -------------------------------------------------------------------------
 *   Active-session counter + static key gate ((1),(8))
 * -------------------------------------------------------------------------
 */

static void wifi_lo_active_inc(void)
{
	if (atomic_inc_return(&wifi_lo_active_num) == 1)
		schedule_work(&wifi_lo_active_sync);
}

/*
 * -------------------------------------------------------------------------
 *   Session table lookup (hashtable; (7))
 * -------------------------------------------------------------------------
 */

/* Compose a 32-bit key from the (lport,rport) pair. */
static inline u32 wifi_lo_port_key(u16 lport, u16 rport)
{
	return ((u32)lport << 16) | (u32)rport;
}

static struct wifi_lo *wifi_lo_find_by_hash(u16 hash)
{
	struct wifi_lo *lo;

	/* hash == 0 is the "not stamped yet" sentinel; refuse to match on it
	 * so a packet whose FOE_ENTRY_NUM happens to be zero can't get glued
	 * to an unrelated session that has just been added but hasn't yet
	 * observed its first inbound packet. */
	if (!hash)
		return NULL;

	hash_for_each_possible_rcu(wifi_lo_hash_ht, lo, hash_node, hash) {
		if (!test_bit(WIFI_LO_F_VALID, &lo->flags))
			continue;
		if (READ_ONCE(lo->hash) != hash)
			continue;
		return lo;
	}
	return NULL;
}

static struct wifi_lo *wifi_lo_find_by_port(u16 lport, u16 rport)
{
	u32 key = wifi_lo_port_key(lport, rport);
	struct wifi_lo *lo;

	hash_for_each_possible_rcu(wifi_lo_port_ht, lo, port_node, key) {
		if (!test_bit(WIFI_LO_F_VALID, &lo->flags))
			continue;
		if (lo->lport != lport || lo->rport != rport)
			continue;
		return lo;
	}
	return NULL;
}

/*
 * Return a pointer to the TCP header inside skb if the packet is a
 * well-formed TCP-over-IPv4/IPv6 frame AND the full L3+L4 header range
 * is present in skb's linear region. Callers dereference (th->source,
 * th->dest, ...) directly, so we must NOT return a pointer that walks
 * off the end of the linear buffer -- a malicious short packet could
 * otherwise leak/corrupt kernel memory during netfilter dispatch.
 */
static struct tcphdr *wifi_lo_get_tcp_header(struct sk_buff *skb,
                                              unsigned short protocol)
{
	unsigned int nh_off, hdr_bytes;
	unsigned int headlen = skb_headlen(skb);

	/* skb_network_offset returns skb->network_header - skb->head. If
	 * the network header hasn't been set yet, network_header is the
	 * "unset" sentinel (~0U) which would produce an absurdly large
	 * unsigned offset; the length checks below reject that case. */
	nh_off = skb_network_offset(skb);
	if (unlikely(nh_off > headlen))
		return NULL;

	if (protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;

		hdr_bytes = nh_off + sizeof(*ip6h) + sizeof(struct tcphdr);
		if (unlikely(headlen < hdr_bytes))
			return NULL;

		ip6h = ipv6_hdr(skb);
		if (ip6h->version != 6 || ip6h->nexthdr != IPPROTO_TCP)
			return NULL;

		return (struct tcphdr *)((u8 *)ip6h + sizeof(*ip6h));
	} else if (protocol == htons(ETH_P_IP)) {
		struct iphdr *iph;
		unsigned int ihl;

		hdr_bytes = nh_off + sizeof(*iph);
		if (unlikely(headlen < hdr_bytes))
			return NULL;

		iph = ip_hdr(skb);
		if (iph->version != 4 || iph->ihl < 5 ||
		    iph->protocol != IPPROTO_TCP)
			return NULL;

		ihl = iph->ihl * 4;
		hdr_bytes = nh_off + ihl + sizeof(struct tcphdr);
		if (unlikely(headlen < hdr_bytes))
			return NULL;

		return (struct tcphdr *)((u8 *)iph + ihl);
	}
	return NULL;
}

static struct wifi_lo *wifi_lo_get_ety(struct sk_buff *skb,
                                              unsigned short protocol,
                                              int out)
{
	struct tcphdr *th = wifi_lo_get_tcp_header(skb, protocol);

	if (!th)
		return NULL;
	if (out)
		return wifi_lo_find_by_port(th->source, th->dest);
	return wifi_lo_find_by_port(th->dest, th->source);
}

/*
 * -------------------------------------------------------------------------
 *   Ingress netdev capture + LRO management
 * -------------------------------------------------------------------------
 */

/*
 * RCU callback: fires one grace period after wifi_lo_free_dev,
 * guaranteeing any wifi_lo_prepare_gro reader that observed the pre-
 * xchg lo->dev pointer has finished. Only then is it safe to drop the
 * final reference.
 */
static void wifi_lo_dev_release_rcu(struct rcu_head *head)
{
	struct wifi_lo *lo = container_of(head, struct wifi_lo, dev_rcu);
	struct net_device *dev = lo->dev_pending_release;

	lo->dev_pending_release = NULL;
	smp_mb__before_atomic();
	clear_bit(WIFI_LO_F_DEV_RELEASING, &lo->flags);
	if (dev)
		dev_put(dev);
}

/*
 * Detach lo->dev and defer its release across one RCU grace period.
 * Safe from any context (softirq/timer/process). No allocation, no
 * synchronize_rcu, no blocking.
 *
 * The DEV_RELEASING flag prevents wifi_lo_add_ety from reusing this
 * slot until the callback fires, which protects the embedded rcu_head
 * from being handed back to call_rcu() while it's already queued.
 */
static void wifi_lo_free_dev(struct wifi_lo *lo)
{
	struct net_device *dev = xchg(&lo->dev, NULL);

	if (!dev)
		return;

	/* Should be impossible to see DEV_RELEASING set here: VALID is
	 * cleared before we come here, and add_ety won't reuse the slot
	 * while either flag is set. Defensively drop the ref inline if
	 * this ever happens rather than corrupt an in-flight callback. */
	if (WARN_ON_ONCE(test_and_set_bit(WIFI_LO_F_DEV_RELEASING,
					  &lo->flags))) {
		dev_put(dev);
		return;
	}

	lo->dev_pending_release = dev;
	call_rcu(&lo->dev_rcu, wifi_lo_dev_release_rcu);
}

/*
 * Publish the resolved ingress netdev into the session. Publish-once
 * via cmpxchg; refuses to cache a bridge master or (when wifi_only is
 * on) a non-wifi netdev.
 */
static void wifi_lo_publish_ingress_dev(struct wifi_lo *lo,
                                        struct net_device *dev)
{
    if (!dev || netif_is_bridge_master(dev))
        return;

    if (READ_ONCE(wifi_lo_wifi_only) && !wifi_lo_is_wifi_dev(dev))
        return;

    dev_hold(dev);

    /* Publish only once. */
    if (cmpxchg(&lo->dev, NULL, dev) != NULL) {
        dev_put(dev);
        return;
    }

    /* IS_WIFI advertises "the captured netdev is definitely wifi" --
     * only set it when that's actually true. Ordered after the dev
     * publish so an observer seeing the flag also sees lo->dev. */
    if (wifi_lo_is_wifi_dev(dev)) {
        smp_wmb();
        set_bit(WIFI_LO_F_IS_WIFI, &lo->flags);
    }
}

/*
 * -------------------------------------------------------------------------
 *   MAC address helper — cached; (3)
 * -------------------------------------------------------------------------
 */

static void wifi_lo_read_macaddr_mmio(u8 addr[ETH_ALEN])
{
	u32 val;

	val = get_frame_engine_data(REG_FE_LAN_MAC_H);
	addr[0] = (val >> 16) & 0xFF;
	addr[1] = (val >> 8) & 0xFF;
	addr[2] = val & 0xFF;

	val = get_frame_engine_data(REG_FE_MAC_LMIN(REG_FE_LAN_MAC_H));
	addr[3] = (val >> 16) & 0xFF;
	addr[4] = (val >> 8) & 0xFF;
	addr[5] = val & 0xFF;
}

static const u8 *wifi_lo_get_lan_mac(void)
{
	if (likely(READ_ONCE(wifi_lo_lan_mac_ready)))
		return wifi_lo_lan_mac;

	{
		u8 tmp[ETH_ALEN];

		wifi_lo_read_macaddr_mmio(tmp);
		memcpy(wifi_lo_lan_mac, tmp, ETH_ALEN);
		smp_wmb();
		WRITE_ONCE(wifi_lo_lan_mac_ready, 1);
	}
	return wifi_lo_lan_mac;
}

/*
 * -------------------------------------------------------------------------
 *   RX force-CPU delivery
 * -------------------------------------------------------------------------
 */

/*
 * wifi_lo_prepare_gro - prepare skb for napi_gro_receive delivery.
 *
 * Return value semantics (contract with airoha_receive_hook):
 *   1  -> skb prepared; caller MUST NOT free. Caller does
 *         napi_gro_receive() so the packet traverses GRO -> bridge ->
 *         netfilter -> TCP like a normal receive.
 *   0  -> skb consumed/dropped by us; caller MUST NOT touch.
 */
static int wifi_lo_prepare_gro(struct sk_buff *skb, bool ipv6)
{
	struct wifi_lo *lo;
	struct net_device *dev;
	struct sock *sk;

	if (unlikely(!skb_mac_header_was_set(skb)))
		goto free;

	/* Single RCU section covers the table lookup, the skip_copy set,
	 * and the dev capture. (12) */
	rcu_read_lock();
	lo = wifi_lo_find_by_hash(FOE_ENTRY_NUM(skb));
	if (unlikely(!lo)) {
		rcu_read_unlock();
		goto free;
	}

	/* (5) lock-free: mark-once via test_and_set_bit. */
	sk = READ_ONCE(lo->sk);
	if (sk && !test_and_set_bit(WIFI_LO_F_SKIP_COPY, &lo->flags))
		WRITE_ONCE(sk->sk_mark, SK_MARK_WIFI_LO);

	dev = READ_ONCE(lo->dev);
	if (dev)
		dev_hold(dev);
	rcu_read_unlock();

	skb->pkt_type = PACKET_HOST;

	if (dev) {
		skb->dev = dev;
		dev_put(dev);
	}

	if (unlikely(ipv6))
		skb->protocol = htons(ETH_P_IPV6);
	else
		skb->protocol = htons(ETH_P_IP);

	skb->ip_summed = CHECKSUM_UNNECESSARY;

	/* LRO super-packet fixup (user note): we always come in here with
	 * LRO enabled, skb->len > MTU, and skb->data pointing at the IP
	 * header. Directly restamp the length -- no ntohs/compare needed.
	 * TCP checksum is skipped via CHECKSUM_UNNECESSARY (the driver's
	 * LRO aggregator already validated per-segment TCP csums during
	 * merging). */
	if (likely(!ipv6)) {
		struct iphdr *iph = (struct iphdr *)skb->data;

		iph->tot_len = htons(skb->len);
		iph->check   = 0;
		iph->check   = ip_fast_csum((void *)iph, iph->ihl);
	} else {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)skb->data;

		ip6h->payload_len = htons(skb->len - sizeof(*ip6h));
	}

	return 1;

free:
	dev_kfree_skb(skb);
	return 0;
}

/*
 * -------------------------------------------------------------------------
 *   TX force-CPU delivery
 * -------------------------------------------------------------------------
 */

static int wifi_lo_pingpong(struct sk_buff *skb)
{
	struct wifi_lo *lo;
	struct dst_entry *dst_clone;
	struct dst_entry *tx_dst = NULL;
	const struct ethhdr *eth;

	if (unlikely(!skb_mac_header_was_set(skb))) {
		dev_kfree_skb(skb);
		return 0;
	}
	eth = (const struct ethhdr *)skb_mac_header(skb);

	skb_reset_network_header(skb);

	/* Look up the session and take a fresh reference on tx_dst under
	 * the spinlock. This closes the UAF window against wifi_lo_timeout,
	 * which drops the session's tx_dst reference only after clearing
	 * VALID and releasing the lock. */
	spin_lock_bh(&wifi_lo_lock);
	lo = wifi_lo_get_ety(skb, eth->h_proto, 1);
	if (lo && test_bit(WIFI_LO_F_VALID, &lo->flags) && lo->tx_dst) {
		tx_dst = lo->tx_dst;
		dst_hold(tx_dst);
	}
	spin_unlock_bh(&wifi_lo_lock);

	if (unlikely(!tx_dst)) {
		dev_kfree_skb(skb);
		return 0;
	}

	dst_clone = arht_gen_dst_clone(tx_dst);
	dst_release(tx_dst);
	if (unlikely(!dst_clone || !dst_clone->dev)) {
		if (dst_clone)
			dst_release(dst_clone);
		dev_kfree_skb(skb);
		return 0;
	}

	skb->inner_protocol = PPE_MAGIC_LOCAL_OUT;
	skb_dst_set(skb, dst_clone);
	dst_clone->output(dev_net(dst_clone->dev), skb->sk, skb);

	return 0;
}

/*
 * -------------------------------------------------------------------------
 *   Session lifecycle
 * -------------------------------------------------------------------------
 */

static void wifi_lo_timeout(struct timer_list *arg)
{
	struct wifi_lo *e = timer_container_of(e, arg, age_timer);
	int (*sock_in_use_fn)(u16, u16);
	int (*ppe_clean_fn)(u16, u16);
	struct dst_entry *dst_to_release = NULL;
	struct sock *sk_to_release = NULL;
	bool difc_active = false;

	spin_lock_bh(&wifi_lo_lock);
	if (time_before(jiffies, e->last_tx + WIFI_LO_EXPIRE_TIME)) {
		mod_timer(&e->age_timer,
		          jiffies + WIFI_LO_EXPIRE_TIME);
		spin_unlock_bh(&wifi_lo_lock);
		return;
	}

	rcu_read_lock();
	sock_in_use_fn = rcu_dereference(dynamic_ifc_sock_in_use_hook);
	if (sock_in_use_fn &&
	    sock_in_use_fn(ntohs(e->rport), ntohs(e->lport)))
		difc_active = true;
	rcu_read_unlock();

	if (e->sk) {
		if (!difc_active)
			WRITE_ONCE(e->sk->sk_mark, 0);
		sk_to_release = e->sk;
		e->sk = NULL;
	}
	if (!difc_active) {
		ppe_clean_fn = READ_ONCE(ra_sw_nat_hook_clean_entry_by_port);
		if (ppe_clean_fn)
			ppe_clean_fn(ntohs(e->rport), ntohs(e->lport));
	}

	/* Drop from hashtables while the entry is still marked VALID so
	 * concurrent readers see a coherent state. hash_node is only
	 * populated once the FOE hash lands; guard the del. */
	hash_del_rcu(&e->port_node);
	if (!hlist_unhashed(&e->hash_node))
		hash_del_rcu(&e->hash_node);

	wifi_lo_free_dev(e);
	dst_to_release = e->tx_dst;
	e->tx_dst = NULL;

	clear_bit(WIFI_LO_F_IS_WIFI, &e->flags);
	clear_bit(WIFI_LO_F_VALID,   &e->flags);
	e->hash = 0;

	spin_unlock_bh(&wifi_lo_lock);

	/* Decrement the active-session counter; if this was the last live
	 * session and DIFC didn't claim it, restore the LRO knob. */
	if (atomic_dec_return(&wifi_lo_active_num) == 0) {
		schedule_work(&wifi_lo_active_sync);	/* flip key -> off */
		if (!difc_active) {
			spin_lock_bh(&wifi_lo_lock);
			wifi_lo_lro_restore_agg_num();
			spin_unlock_bh(&wifi_lo_lock);
		}
	}

	if (dst_to_release)
		dst_release(dst_to_release);
	if (sk_to_release)
		sock_put(sk_to_release);
}

static void wifi_lo_add_ety(struct sk_buff *skb, struct tcphdr *th)
{
	struct wifi_lo *lo;
	struct dst_entry *dst = skb_dst(skb);
	struct sock *sk = skb->sk;
	bool added = false;
	int i;

	/*
	 * skb->sk at LOCAL_OUT may point at objects that are NOT full,
	 * refcounted sockets:
	 *   - request_sock  (TCP_NEW_SYN_RECV) -- lifetime managed by the
	 *     listener's accept queue, sock_hold/sock_put unsafe.
	 *   - timewait_sock (TCP_TIME_WAIT)    -- similar; different alloc
	 *     path.
	 *   - skb_orphan()'d skbs may carry a stale sk pointer.
	 * Calling sock_hold() on any of those, then sock_put() from our
	 * timer, produces a refcount_t underflow/use-after-free warning
	 * (as seen on the box). Track sk only when it's a full, still-
	 * refcounted socket; otherwise leave lo->sk == NULL. The offload
	 * itself works without the sk -- only the skip_copy optimization
	 * relies on it.
	 */
	if (sk && (!sk_fullsock(sk) ||
		   !refcount_inc_not_zero(&sk->sk_refcnt))) {
		sk = NULL;
	}

	/* Pre-take references outside the lock; drop them if we don't land
	 * a slot. dst_hold is cheap and can't sleep; sk was refcount-inc'd
	 * above. */
	if (dst)
		dst_hold(dst);

	spin_lock_bh(&wifi_lo_lock);
	for (i = 0; i < WIFI_LO_MAX_NUM; i++) {
		lo = &wifi_lo_ety[i];
		/* Skip both live slots and slots whose previous occupant is
		 * still waiting for its RCU-deferred dev_put -- the embedded
		 * rcu_head is still queued and reusing the slot would corrupt
		 * the callback. */
		if (test_bit(WIFI_LO_F_VALID, &lo->flags) ||
		    test_bit(WIFI_LO_F_DEV_RELEASING, &lo->flags))
			continue;

		lo->lport      = th->source;
		lo->rport      = th->dest;
		lo->tx_dst     = dst;
		lo->last_tx    = jiffies;
		lo->hash       = 0;
		lo->dev        = NULL;
		lo->sk         = sk;
		/* Fresh entry: clear all flag bits. */
		WRITE_ONCE(lo->flags, 0);

		/* Publish into the port hashtable and set VALID last so
		 * lookups can't find a half-initialised entry. The hash
		 * hashtable is populated lazily by wifi_lo_rehash once the
		 * PPE stamps the FOE hash on the first inbound packet. */
		INIT_HLIST_NODE(&lo->hash_node);
		hash_add_rcu(wifi_lo_port_ht, &lo->port_node,
		             wifi_lo_port_key(lo->lport, lo->rport));

		smp_wmb();
		set_bit(WIFI_LO_F_VALID, &lo->flags);

		wifi_lo_lro_save_and_set_agg_num(lro_agg_num);

		timer_setup(&lo->age_timer, wifi_lo_timeout, 0);
		mod_timer(&lo->age_timer,
		          jiffies + WIFI_LO_EXPIRE_TIME);
		added = true;
		break;
	}
	spin_unlock_bh(&wifi_lo_lock);

	if (!added) {
		if (dst)
			dst_release(dst);
		if (sk)
			sock_put(sk);
		return;
	}

	wifi_lo_active_inc();

	/* pr_info_ratelimited("wifi_lo: add_ety lport=%u rport=%u comm=%s\n",
	                    ntohs(th->source), ntohs(th->dest),
	                    current->comm); */
}

/*
 * Publish lo->hash into the hash-keyed bucket. Called from the LOCAL_IN
 * hook once the PPE has stamped a real FOE hash on an inbound packet.
 * First stamp only — we never rehash a live session. */
static void wifi_lo_hash_publish(struct wifi_lo *lo, u16 new_hash)
{
	spin_lock_bh(&wifi_lo_lock);
	if (test_bit(WIFI_LO_F_VALID, &lo->flags) && lo->hash == 0) {
		lo->hash = new_hash;
		hash_add_rcu(wifi_lo_hash_ht, &lo->hash_node, new_hash);
	}
	spin_unlock_bh(&wifi_lo_lock);
}

/*
 * -------------------------------------------------------------------------
 *   Netfilter hooks
 * -------------------------------------------------------------------------
 */

static unsigned int wifi_lo_nf_hook_local_in(void *priv, struct sk_buff *skb,
                                              const struct nf_hook_state *state)
{
	struct wifi_lo *lo;
	struct port_info pinfo = {0};
	u16 hash;

	/* Idle fast-reject (1)+(8): NOP-patched when no sessions exist. */
	if (!static_branch_unlikely(&wifi_lo_active_key))
		return NF_ACCEPT;

	rcu_read_lock();
	lo = wifi_lo_get_ety(skb, skb->protocol, 0);
	if (!lo) {
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	/*
	 * Resolve the true ingress netdev for this packet:
	 *   1. Bridged: skb->dev is the bridge master; ask the bridge FDB
	 *      which port owns the source MAC.
	 *   2. Non-bridged: skb->dev is already the real netdev.
	 */
	if (!READ_ONCE(lo->dev) && skb->dev) {
		struct net_device *dev = netif_is_bridge_master(skb->dev)
			? wifi_lo_bridge_port(skb)
			: skb->dev;

		if (dev)
			wifi_lo_publish_ingress_dev(lo, dev);
	}

	/* Gate the offload on IS_WIFI only when wifi_only mode is on. */
	if (READ_ONCE(wifi_lo_wifi_only) &&
	    !test_bit(WIFI_LO_F_IS_WIFI, &lo->flags)) {
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	hash = FOE_ENTRY_NUM(skb);
	if (hash != 0 && READ_ONCE(lo->hash) == 0)
		wifi_lo_hash_publish(lo, hash);

	pinfo.magic = PPE_MAGIC_LOCAL_IN_NS;
	airoha_ppe_tx_handler(skb, &pinfo, 0);
	rcu_read_unlock();

	return NF_ACCEPT;
}

static unsigned int wifi_lo_nf_hook_local_out(void *priv, struct sk_buff *skb,
                                               const struct nf_hook_state *state)
{
	struct wifi_lo *lo;
	struct tcphdr *th;
	int (*fast_tx_fn)(struct sk_buff *, int);
	bool fast_path = static_branch_unlikely(&wifi_lo_active_key);

	th = wifi_lo_get_tcp_header(skb, skb->protocol);
	if (!th)
		return NF_ACCEPT;

	/* Fast path only exists when we have sessions. (1)+(8) */
	if (fast_path) {
		bool wifi_only = READ_ONCE(wifi_lo_wifi_only);

		rcu_read_lock();
		lo = wifi_lo_find_by_port(th->source, th->dest);
		if (lo && (!wifi_only ||
			   test_bit(WIFI_LO_F_IS_WIFI, &lo->flags))) {
			unsigned long now = jiffies;

			/* (4) rate-limit last_tx writes to avoid bouncing the
			 * session cache line on every packet. */
			if (now - READ_ONCE(lo->last_tx) >= WIFI_LO_LAST_TX_MIN_INTERVAL)
				WRITE_ONCE(lo->last_tx, now);

			fast_tx_fn = READ_ONCE(offload_eth_fast_tx_hook);
			if (unlikely(!fast_tx_fn)) {
				rcu_read_unlock();
				return NF_ACCEPT;
			}

			/* Ensure headroom for the Ethernet header we're about
			 * to prepend; without this, a locally-generated skb
			 * with headroom < ETH_HLEN hits BUG_ON in skb_push. */
			if (skb_cow_head(skb, ETH_HLEN)) {
				rcu_read_unlock();
				return NF_ACCEPT;
			}

			skb->inner_protocol = PPE_MAGIC_LOCAL_OUT;
			skb_push(skb, ETH_HLEN);
			/* dst MAC = LAN MAC (device downstream will rewrite);
			 * src MAC = LAN MAC too. Explicitly zeroing or copying
			 * the source is required -- leaving skb->data[6..11]
			 * uninitialised would leak kernel headroom bytes onto
			 * the wire. */
			memcpy(skb->data, wifi_lo_get_lan_mac(), ETH_ALEN);
			memcpy(skb->data + ETH_ALEN, wifi_lo_get_lan_mac(), ETH_ALEN);
			*(unsigned short *)(skb->data + 12) = skb->protocol;
			fast_tx_fn(skb, 7);
			rcu_read_unlock();
			return NF_STOLEN;
		}
		rcu_read_unlock();
	}

	if (wifi_lo_app_match(current->comm))
		wifi_lo_add_ety(skb, th);

	return NF_ACCEPT;
}


static struct nf_hook_ops wifi_lo_ipv4_local_in_ops = {
	.hook		= wifi_lo_nf_hook_local_in,
	.pf		= NFPROTO_IPV4,
	.hooknum	= NF_INET_LOCAL_IN,
	.priority	= (NF_IP_PRI_CONNTRACK + 1),
};

static struct nf_hook_ops wifi_lo_ipv4_local_out_ops = {
	.hook		= wifi_lo_nf_hook_local_out,
	.pf		= NFPROTO_IPV4,
	.hooknum	= NF_INET_LOCAL_OUT,
	.priority	= (NF_IP_PRI_CONNTRACK + 1),
};

static struct nf_hook_ops wifi_lo_ipv6_local_in_ops = {
	.hook		= wifi_lo_nf_hook_local_in,
	.pf		= NFPROTO_IPV6,
	.hooknum	= NF_INET_LOCAL_IN,
	.priority	= (NF_IP6_PRI_CONNTRACK + 1),
};

static struct nf_hook_ops wifi_lo_ipv6_local_out_ops = {
	.hook		= wifi_lo_nf_hook_local_out,
	.pf		= NFPROTO_IPV6,
	.hooknum	= NF_INET_LOCAL_OUT,
	.priority	= (NF_IP6_PRI_CONNTRACK + 1),
};

/*
 * -------------------------------------------------------------------------
 *   /proc/wifi_local_fastpath
 * -------------------------------------------------------------------------
 */

static ssize_t wifi_lo_proc_read(struct file *file, char __user *buf,
                                  size_t count, loff_t *ppos)
{
	struct wifi_lo_apps *snap;
	struct wifi_lo *lo;
	char *pb;
	size_t remain;
	int len = 0, n, i;
	ssize_t ret;

	if (*ppos > 0)
		return 0;

	pb = kmalloc(WIFI_LO_PROC_BUFSZ, GFP_KERNEL);
	if (!pb)
		return -ENOMEM;

	remain = WIFI_LO_PROC_BUFSZ;

	APPEND("lro_agg_num: %d (default: %d)\n",
	       lro_agg_num, LRO_AGG_NUM_DEFAULT);
	APPEND("wifi_only: %d\n", READ_ONCE(wifi_lo_wifi_only) ? 1 : 0);
	APPEND("active_sessions: %d\n", atomic_read(&wifi_lo_active_num));

	APPEND("Apps: ");
	rcu_read_lock();
	snap = rcu_dereference(wifi_lo_apps_snap);
	if (snap) {
		for (i = 0; i < snap->count; i++)
			APPEND("%s ", snap->name[i]);
	}
	rcu_read_unlock();
	APPEND("\nentry: \n");

	spin_lock_bh(&wifi_lo_lock);
	for (i = 0; i < WIFI_LO_MAX_NUM; i++) {
		struct net_device *d;

		lo = &wifi_lo_ety[i];
		if (!test_bit(WIFI_LO_F_VALID, &lo->flags))
			continue;

		d = READ_ONCE(lo->dev);
		APPEND("\t[%d] lport:%d rport:%d hash:%d dev:%s time:%lums\n",
		       i, ntohs(lo->lport), ntohs(lo->rport), lo->hash,
		       d ? d->name : "(none)",
		       (jiffies - lo->last_tx) * 10);
	}
	spin_unlock_bh(&wifi_lo_lock);
	APPEND("\n");

	if (count > (size_t)len)
		count = len;
	if (copy_to_user(buf, pb, count)) {
		ret = -EFAULT;
		goto out;
	}

	*ppos += count;
	ret = count;
out:
	kfree(pb);
	return ret;
}

static ssize_t wifi_lo_proc_write(struct file *file, const char __user *buf,
                                   size_t count, loff_t *ppos)
{
	char str[64] = {0};
	char cmd[32] = {0};
	char name[32] = {0};
	int val = 0;

	if (count == 0 || count > sizeof(str) - 1)
		return -EINVAL;
	if (copy_from_user(str, buf, count))
		return -EFAULT;
	str[count] = '\0';

	if (sscanf(str, "%31s", cmd) < 1)
		return -EINVAL;

	if (!strcmp(cmd, "agg_num")) {
		if (sscanf(str, "%31s %d", cmd, &val) == 2) {
			if (val < LRO_AGG_NUM_MIN ||
			    val > LRO_AGG_NUM_MAX) {
				pr_err("wifi_lo: agg_num out of range [%d, %d]\n",
				       LRO_AGG_NUM_MIN,
				       LRO_AGG_NUM_MAX);
			} else {
				lro_agg_num = val;
				pr_info("wifi_lo: lro_agg_num = %d\n",
				        lro_agg_num);
			}
		} else {
			pr_info("wifi_lo: current lro_agg_num = %d\n",
			        lro_agg_num);
		}
	} else if (!strcmp(cmd, "wifi_only")) {
		if (sscanf(str, "%31s %d", cmd, &val) == 2) {
			WRITE_ONCE(wifi_lo_wifi_only, !!val);
			pr_info("wifi_lo: wifi_only = %d\n", !!val);
		} else {
			pr_info("wifi_lo: current wifi_only = %d\n",
			        READ_ONCE(wifi_lo_wifi_only) ? 1 : 0);
		}
	} else {
		/* "1 iperf3" / "0 iperf3" - add/del app to the trigger list */
		val = 0;
		if (sscanf(str, "%d %31s", &val, name) >= 2) {
			if (val)
				wifi_lo_app_add(name);
			else
				wifi_lo_app_del(name);
		}
	}
	return count;
}

static const struct proc_ops wifi_lo_proc_ops = {
	.proc_read  = wifi_lo_proc_read,
	.proc_write = wifi_lo_proc_write,
};

/*
 * -------------------------------------------------------------------------
 *   Module init / exit
 * -------------------------------------------------------------------------
 */

static int __init wifi_lo_init(void)
{
	int ret;

	hash_init(wifi_lo_port_ht);
	hash_init(wifi_lo_hash_ht);

	ret = nf_register_net_hook(&init_net, &wifi_lo_ipv4_local_in_ops);
	if (ret)
		goto err;

	ret = nf_register_net_hook(&init_net, &wifi_lo_ipv4_local_out_ops);
	if (ret)
		goto err_unhook_v4_in;

	ret = nf_register_net_hook(&init_net, &wifi_lo_ipv6_local_in_ops);
	if (ret)
		goto err_unhook_v4_out;

	ret = nf_register_net_hook(&init_net, &wifi_lo_ipv6_local_out_ops);
	if (ret)
		goto err_unhook_v6_in;

	if (!proc_create("wifi_local_fastpath", 0, NULL,
	                 &wifi_lo_proc_ops)) {
		ret = -ENOMEM;
		goto err_unhook_v6_out;
	}

	/* Seed the trigger app list. Additional entries can be added at
	 * runtime via /proc/wifi_local_fastpath. */
	wifi_lo_app_add("iperf3");

	rcu_assign_pointer(arht_force_to_cpu_prepare_gro_hook,
	                   wifi_lo_prepare_gro);
	rcu_assign_pointer(local_out_pingpong_hook, wifi_lo_pingpong);
	arht_skip_copy_kprobe_enable();

	return 0;

err_unhook_v6_out:
	nf_unregister_net_hook(&init_net, &wifi_lo_ipv6_local_out_ops);
err_unhook_v6_in:
	nf_unregister_net_hook(&init_net, &wifi_lo_ipv6_local_in_ops);
err_unhook_v4_out:
	nf_unregister_net_hook(&init_net, &wifi_lo_ipv4_local_out_ops);
err_unhook_v4_in:
	nf_unregister_net_hook(&init_net, &wifi_lo_ipv4_local_in_ops);
err:
	return ret;
}

static void __exit wifi_lo_exit(void)
{
	struct sock *sks_to_release[WIFI_LO_MAX_NUM] = {0};
	struct dst_entry *dsts_to_release[WIFI_LO_MAX_NUM] = {0};
	struct net_device *devs_to_release[WIFI_LO_MAX_NUM] = {0};
	struct wifi_lo_apps *apps;
	int i;

	/* Detach hooks first so no new sessions can be added / no packets
	 * enter our RX or TX fast paths after this point. */
	rcu_assign_pointer(arht_force_to_cpu_prepare_gro_hook, NULL);
	rcu_assign_pointer(local_out_pingpong_hook, NULL);
	arht_skip_copy_kprobe_disable();

	nf_unregister_net_hook(&init_net, &wifi_lo_ipv4_local_in_ops);
	nf_unregister_net_hook(&init_net, &wifi_lo_ipv4_local_out_ops);
	nf_unregister_net_hook(&init_net, &wifi_lo_ipv6_local_in_ops);
	nf_unregister_net_hook(&init_net, &wifi_lo_ipv6_local_out_ops);

	/* Ensure any in-flight readers of the hook pointers have exited. */
	synchronize_rcu();

	for (i = 0; i < WIFI_LO_MAX_NUM; i++)
		timer_delete_sync(&wifi_lo_ety[i].age_timer);

	spin_lock_bh(&wifi_lo_lock);
	for (i = 0; i < WIFI_LO_MAX_NUM; i++) {
		struct wifi_lo *lo = &wifi_lo_ety[i];

		if (!test_bit(WIFI_LO_F_VALID, &lo->flags))
			continue;

		if (lo->sk) {
			WRITE_ONCE(lo->sk->sk_mark, 0);
			sks_to_release[i] = lo->sk;
			lo->sk = NULL;
		}
		dsts_to_release[i] = lo->tx_dst;
		lo->tx_dst = NULL;
		devs_to_release[i] = xchg(&lo->dev, NULL);

		hash_del_rcu(&lo->port_node);
		if (!hlist_unhashed(&lo->hash_node))
			hash_del_rcu(&lo->hash_node);
		WRITE_ONCE(lo->flags, 0);
	}
	spin_unlock_bh(&wifi_lo_lock);

	/* Force active counter to zero and drain the sync worker before we
	 * disable the static key (which needs a sleepable context). */
	atomic_set(&wifi_lo_active_num, 0);
	cancel_work_sync(&wifi_lo_active_sync);
	if (static_key_enabled(&wifi_lo_active_key.key))
		static_branch_disable(&wifi_lo_active_key);

	/* Wait for any in-flight prepare_gro reader to drain before we
	 * dev_put(): the RX path grabs a fresh ref under rcu_read_lock,
	 * so a single synchronize_rcu() outside the spinlock covers every
	 * captured device. */
	synchronize_rcu();

	for (i = 0; i < WIFI_LO_MAX_NUM; i++) {
		if (sks_to_release[i])
			sock_put(sks_to_release[i]);
		if (dsts_to_release[i])
			dst_release(dsts_to_release[i]);
		if (devs_to_release[i])
			dev_put(devs_to_release[i]);
	}

	/* Drop the app-list snapshot. */
	mutex_lock(&wifi_lo_apps_mutex);
	apps = rcu_dereference_protected(wifi_lo_apps_snap,
			lockdep_is_held(&wifi_lo_apps_mutex));
	rcu_assign_pointer(wifi_lo_apps_snap, NULL);
	mutex_unlock(&wifi_lo_apps_mutex);
	if (apps)
		call_rcu(&apps->rcu, wifi_lo_apps_free_rcu);

	/* Wait for any pending call_rcu callbacks (wifi_lo_dev_release_rcu
	 * from softirq/timer paths, wifi_lo_apps_free_rcu from the app-list
	 * teardown just above) to fire before the module text disappears. */
	rcu_barrier();

	remove_proc_entry("wifi_local_fastpath", NULL);
}

module_init(wifi_lo_init);
module_exit(wifi_lo_exit);
MODULE_DESCRIPTION("Airoha Wi-Fi LOCAL_IN / LOCAL_OUT Fastpath driver");
MODULE_LICENSE("GPL");
