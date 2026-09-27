 // SPDX-License-Identifier: GPL-2.0-only
 /*
  * Copyright (c) 2024 AIROHA Inc
  * Author:  2024 AIROHA Inc
  */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#if __has_include("airoha_function.h") && __has_include("arht_dynamic_ifc.h") && __has_include("arht_kprobe.h")
#define ARHT_DIFC_FULL_SUPPORT 1
#else
#define ARHT_DIFC_FULL_SUPPORT 0
#endif

#if ARHT_DIFC_FULL_SUPPORT
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h> 
#include <linux/ipv6.h>

#include <net/ip.h>
#include <net/inet_hashtables.h>
#include <net/protocol.h>
#include <net/dst.h>
#include <net/inet_sock.h>
#include <net/tcp.h>

#include "airoha_regs.h"
#include "airoha_eth.h"
#include "airoha_function.h"
#include "arht_dynamic_ifc.h"
#include "arht_kprobe.h"

/************************************************************************************************
*				   E X T E R N A L     D A T A	 D E C L A R A T I O N S
*************************************************************************************************
*/
extern struct airoha_eth *glb_eth;

/************************************************************************************************
*				   E X T E R N A L     F U N C T I O N	 D E C L A R A T I O N S
*************************************************************************************************
*/
extern int (*arht_hook_get_crsn) (struct sk_buff * skb);

/************************************************************************************************
*                              D A T A	 D E C L A R A T I O N S
*************************************************************************************************
*/
static int debug_level = DEBUG_LEVEL_NONE;
static int dynamic_ifc_enable = 0;
static int ifc_ring_reserve[IFC_LRO_RING_NUM];

static u32 lro_agg_num_orig_cdm1 = 0;
static u32 lro_agg_num_orig_cdm2 = 0;
static bool lro_agg_num_saved = false;
static int lro_agg_num = LRO_AGG_NUM_DEFAULT;

static struct dynamic_ifc dynamic_ifc_ety[MAX_DYNAMIC_IFC_NUM];
static char dynamic_ifc_apps[MAX_DYNAMIC_IFC_APP_NUM][TASK_COMM_LEN] = {0};
static int dynamic_ifc_app_valid[MAX_DYNAMIC_IFC_APP_NUM] = {0};
static atomic_t dynamic_ifc_app_num = ATOMIC_INIT(0);

static struct proc_dir_entry *df_proc_entry = NULL;

static DEFINE_MUTEX(dynamic_ifc_enable_mutex);
static DEFINE_SPINLOCK(dynamic_ifc_lock);

/************************************************************************************************
*                        F U N C T I O N	 D E C L A R A T I O N S
*************************************************************************************************
*/
/* Lazy-resolved function pointer to __ECNT_HOOK (provided by arht-hook.ko) */
static ecnt_hook_fn_t __difc_ecnt_hook_fn = NULL;

int (*dynamic_ifc_pingpong_hook)(struct sk_buff*) = NULL;
EXPORT_SYMBOL(dynamic_ifc_pingpong_hook);
int (*dynamic_ifc_sock_in_use_hook)(u16 local_port, u16 remote_port) = NULL;
EXPORT_SYMBOL(dynamic_ifc_sock_in_use_hook);


/************************************************************************************************
*
*************************************************************************************************
*/
static inline ecnt_hook_fn_t difc_get_hook_fn(void)
{
	return READ_ONCE(__difc_ecnt_hook_fn);
}

static int ifc_get_free_lro_ring(int entry_idx)
{
	int i;

	for (i = 0; i < IFC_LRO_RING_NUM; i++) 
	{
		if (ifc_ring_reserve[i] == entry_idx){
			return (IFC_LRO_RING_START + i);
		}

		if (ifc_ring_reserve[i] != IFC_RING_SLOT_FREE) 
		{
			int prev = ifc_ring_reserve[i];
			if (prev >= MAX_DYNAMIC_IFC_NUM ||
				!dynamic_ifc_ety[prev].valid ||
				!dynamic_ifc_ety[prev].ifc_valid) 
			{
				ifc_ring_reserve[i] = entry_idx;
				return (IFC_LRO_RING_START + i);
			}
		}
	}

	for (i = 0; i < IFC_LRO_RING_NUM; i++) 
	{
		if (ifc_ring_reserve[i] == IFC_RING_SLOT_FREE) 
		{
			ifc_ring_reserve[i] = entry_idx;
			return (IFC_LRO_RING_START + i);
		}
	}

	return IFC_DEFAULT_RING;
}

/* Release ring reservation */
static void ifc_release_lro_ring(int entry_idx)
{
	int i;

	for (i = 0; i < IFC_LRO_RING_NUM; i++) 
	{
		if (ifc_ring_reserve[i] == entry_idx) 
		{
			ifc_ring_reserve[i] = IFC_RING_SLOT_FREE;
			return;
		}
	}
}

/* Create IFC rule for a data session. First 4 data sessions get ring 12~15, rest get ring 1 (default).
 *
 * NOTE: This function is called under dynamic_ifc_lock (spinlock_irqsave).
 * All IFC API functions used herein (DIFC_API_SET_LUT_RULE_AUTO,
 * DIFC_API_SET_ACTION, DIFC_API_DEL_LUT_RULE_AUTO) are guaranteed to be
 * atomic-safe: they only perform MMIO register reads/writes without any
 * mutex, semaphore, or other potentially-sleeping operations.
 * Therefore, calling them in atomic/IRQ-disabled context is safe.
 */
static int dynamic_ifc_add_ifc(struct dynamic_ifc *lo)
{
	struct ecnt_ifc_param ifc_param;
	ecnt_hook_fn_t hook_fn;
	int ret;

	if (!lo->valid || lo->ifc_valid){
		return 0;
	}

	hook_fn = difc_get_hook_fn();
	if (unlikely(!hook_fn)) {
		pr_warn_ratelimited("arht_dynamic_ifc: hook_fn is NULL, cannot add IFC\n");
		return -ENODEV;
	}
	
	memset(&ifc_param, 0, sizeof(struct ecnt_ifc_param));
	/* DPORT = local port (iperf3 server side) */
	ifc_param.field[0] = DPORT;
	ifc_param.mask[0]  = 0xFFFF;
	ifc_param.key[0]   = ntohs(lo->local_port);
	/* SPORT = remote port (iperf3 client side) */
	ifc_param.field[1] = SPORT;
	ifc_param.mask[1]  = 0xFFFF;
	ifc_param.key[1]   = ntohs(lo->remote_port);

	lo->ifc_index = DIFC_API_SET_LUT_RULE_AUTO(hook_fn, &ifc_param);
	if (lo->ifc_index == 0 || lo->ifc_index == ECNT_HOOK_ERROR) 
	{
		DYNAMIC_IFC_LOG(DEBUG_LEVEL_ERR, "arht_dynamic_ifc: IFC add failed local_port=%u remote_port=%u\n",
						ntohs(lo->local_port), ntohs(lo->remote_port));
		lo->ifc_index = 0;
		return -1;
	}

	lo->ring_id = ifc_get_free_lro_ring(lo - dynamic_ifc_ety);

	/* actIdx=14 (ACT_ForceCPU): force to CPU, specify ring */
	ret = DIFC_API_SET_ACTION(hook_fn, lo->ifc_index, 14, IFC_ENABLE, 1, lo->ring_id, 0, 0);
	if (ret == ECNT_HOOK_ERROR) {
		DYNAMIC_IFC_LOG(DEBUG_LEVEL_ERR, "arht_dynamic_ifc: IFC set action failed idx=%u\n", lo->ifc_index);
		memset(&ifc_param, 0, sizeof(struct ecnt_ifc_param));
		ifc_param.field[0]   = DPORT;
		ifc_param.command[0] = 0;
		ifc_param.mask[0]    = 0xFFFF;
		ifc_param.key[0]     = ntohs(lo->local_port);
		ifc_param.field[1]   = SPORT;
		ifc_param.command[1] = 0;
		ifc_param.mask[1]    = 0xFFFF;
		ifc_param.key[1]     = ntohs(lo->remote_port);
		DIFC_API_DEL_LUT_RULE_AUTO(hook_fn, &ifc_param);
		lo->ifc_index = 0;
		ifc_release_lro_ring(lo - dynamic_ifc_ety);
		return -1;
	}

	lo->ifc_valid = 1;

	DYNAMIC_IFC_LOG(DEBUG_LEVEL_INFO, "arht_dynamic_ifc: IFC added idx=%u local_port=%u remote_port=%u -> ring %d\n", 
			 lo->ifc_index, ntohs(lo->local_port), ntohs(lo->remote_port), lo->ring_id);

	return 0;
}

/* Delete IFC rule for a session.
 *
 * Context: Must be called under dynamic_ifc_lock (spinlock_irqsave).
 * DIFC_API_DEL_LUT_RULE_AUTO is atomic-safe (MMIO only, no sleeping).
 */
static void dynamic_ifc_del_ifc(struct dynamic_ifc *lo)
{
	struct ecnt_ifc_param ifc_param;
	ecnt_hook_fn_t hook_fn;

	if (!lo->ifc_valid || lo->ifc_index == 0){
		return;
	}

	hook_fn = difc_get_hook_fn();
	if (unlikely(!hook_fn)) {
		pr_warn_ratelimited("arht_dynamic_ifc: hook_fn is NULL, cannot del IFC (idx=%u)\n", lo->ifc_index);
		goto clear_state;
	}
	
	memset(&ifc_param, 0, sizeof(struct ecnt_ifc_param));
	ifc_param.field[0]   = DPORT;
	ifc_param.command[0] = 0;
	ifc_param.mask[0]    = 0xFFFF;
	ifc_param.key[0]     = ntohs(lo->local_port);
	ifc_param.field[1]   = SPORT;
	ifc_param.command[1] = 0;
	ifc_param.mask[1]    = 0xFFFF;
	ifc_param.key[1]     = ntohs(lo->remote_port);

	DIFC_API_DEL_LUT_RULE_AUTO(hook_fn, &ifc_param);
	DYNAMIC_IFC_LOG(DEBUG_LEVEL_INFO, "arht_dynamic_ifc: IFC deleted idx=%u local_port=%u rport=%u ring=%d\n", 
			lo->ifc_index, ntohs(lo->local_port), ntohs(lo->remote_port), lo->ring_id);

clear_state:
	lo->ifc_index = 0;
	lo->ifc_valid = 0;
	lo->ring_id = 0;

	ifc_release_lro_ring(lo - dynamic_ifc_ety);
}

static void lro_save_and_set_agg_num(int agg_num)
{
	struct airoha_eth *eth;

	if (lro_agg_num_saved) {
		return;
	}

	eth = READ_ONCE(glb_eth);
	if (!eth || !eth->fe_regs) {
		pr_warn_ratelimited("arht_dynamic_ifc: glb_eth not ready\n");
		return;
	}

	/* Save original agg_num values */
	lro_agg_num_orig_cdm1 = FIELD_GET(CDM_LRO_AGG_NUM_MASK, airoha_fe_rr(eth, REG_CDM_LRO_LIMIT(1)));
	lro_agg_num_orig_cdm2 = FIELD_GET(CDM_LRO_AGG_NUM_MASK, airoha_fe_rr(eth, REG_CDM_LRO_LIMIT(2)));

	lro_agg_num_saved = true;

	/* Set new agg_num for both CDM1 and CDM2 */
	airoha_fe_rmw(eth, REG_CDM_LRO_LIMIT(1), CDM_LRO_AGG_NUM_MASK, FIELD_PREP(CDM_LRO_AGG_NUM_MASK, agg_num));
	airoha_fe_rmw(eth, REG_CDM_LRO_LIMIT(2), CDM_LRO_AGG_NUM_MASK, FIELD_PREP(CDM_LRO_AGG_NUM_MASK, agg_num));
}

static void lro_restore_agg_num(void)
{
	struct airoha_eth *eth;

	if (!lro_agg_num_saved) {
		return;
	}

	eth = READ_ONCE(glb_eth);
	if (!eth || !eth->fe_regs) {
		pr_warn_ratelimited("arht_dynamic_ifc: glb_eth not ready\n");
		return;
	}

	/* Restore original agg_num for both CDM1 and CDM2 */
	airoha_fe_rmw(eth, REG_CDM_LRO_LIMIT(1), CDM_LRO_AGG_NUM_MASK, FIELD_PREP(CDM_LRO_AGG_NUM_MASK, lro_agg_num_orig_cdm1));
	airoha_fe_rmw(eth, REG_CDM_LRO_LIMIT(2), CDM_LRO_AGG_NUM_MASK, FIELD_PREP(CDM_LRO_AGG_NUM_MASK, lro_agg_num_orig_cdm2));

	lro_agg_num_saved = false;
}

static int is_dynamic_ifc_app(char * name)
{
	int i;

	if (!name){
		return 0;
	}

	for (i = 0; i < MAX_DYNAMIC_IFC_APP_NUM; i++)
	{
		if (smp_load_acquire(&dynamic_ifc_app_valid[i]) &&
			!strncmp(dynamic_ifc_apps[i], name, TASK_COMM_LEN - 1))
		{
			return 1;
		}
	}

	return 0;
}

static int dynamic_ifc_app_list_add(char * name)
{
	int i;

	if(is_dynamic_ifc_app(name)){
		return 1;
	}

	for (i = 0; i < MAX_DYNAMIC_IFC_APP_NUM; i++)
	{
		if (!smp_load_acquire(&dynamic_ifc_app_valid[i]))
		{
			strscpy(dynamic_ifc_apps[i], name, TASK_COMM_LEN);
			smp_store_release(&dynamic_ifc_app_valid[i], 1);
			atomic_inc(&dynamic_ifc_app_num);
			return 1;
		}
	}

	return 0;
}

static int dynamic_ifc_app_list_del(char * name)
{
	int i;

	for (i = 0; i < MAX_DYNAMIC_IFC_APP_NUM; i++)
	{
		if (smp_load_acquire(&dynamic_ifc_app_valid[i]) &&
			!strncmp(dynamic_ifc_apps[i], name, TASK_COMM_LEN - 1))
		{
			smp_store_release(&dynamic_ifc_app_valid[i], 0);
			dynamic_ifc_apps[i][0] = '\0';
			atomic_dec(&dynamic_ifc_app_num);
			return 1;
		}
	}

	return 0;
}

static int dynamic_ifc_sock_in_use(u16 local_port, u16 remote_port)
{
	int i;
	unsigned long flags;

	spin_lock_irqsave(&dynamic_ifc_lock, flags);
	for (i = 0; i < MAX_DYNAMIC_IFC_NUM; i++) 
	{
		if (!dynamic_ifc_ety[i].valid){
			continue;
		}

		if (ntohs(dynamic_ifc_ety[i].local_port) == local_port && ntohs(dynamic_ifc_ety[i].remote_port) == remote_port)
		{
			spin_unlock_irqrestore(&dynamic_ifc_lock, flags);
			return 1;
		}

		if (ntohs(dynamic_ifc_ety[i].local_port) == remote_port && ntohs(dynamic_ifc_ety[i].remote_port) == local_port)
		{
			spin_unlock_irqrestore(&dynamic_ifc_lock, flags);
			return 1;
		}
	}
	spin_unlock_irqrestore(&dynamic_ifc_lock, flags);

	return 0;
}

static struct dynamic_ifc* find_dynamic_ifc_ety_by_port(unsigned short local_port, unsigned short remote_port)
{
	int i;

	for(i=0; i<MAX_DYNAMIC_IFC_NUM; i++)
	{
		if(dynamic_ifc_ety[i].valid == 0 || dynamic_ifc_ety[i].local_port != local_port || dynamic_ifc_ety[i].remote_port != remote_port)
		{
			continue;
		}
		return &dynamic_ifc_ety[i];
	}
	
	return NULL;
}

static void dynamic_ifc_timeout(struct timer_list *arg)
{
	struct dynamic_ifc *e = timer_container_of(e, arg, age_timer);
	int i;
	unsigned long flags;
	struct sock *sk_to_release = NULL;
	struct dst_entry *tx_dst_to_release = NULL;
	struct dst_entry *rx_dst_to_release = NULL;
	bool has_active_session = false;

	spin_lock_irqsave(&dynamic_ifc_lock, flags);
	if (!e->valid) {
		spin_unlock_irqrestore(&dynamic_ifc_lock, flags);
		return;
	}

	if(time_before(jiffies, e->last_tx+EXPIRE_TIME)) 
	{
		mod_timer(&e->age_timer, jiffies+EXPIRE_TIME);
		spin_unlock_irqrestore(&dynamic_ifc_lock, flags);
		return;
	}

	if (e->ifc_valid) {
		/* Safe in timer/softirq context: IFC APIs are atomic (MMIO only) */
		dynamic_ifc_del_ifc(e);
	}

	e->timer_active = 0;
	if (e->sk) {
		sk_to_release = e->sk;
		WRITE_ONCE(e->sk->sk_mark, 0);
		e->sk = NULL;
	}
	if (e->tx_dst) {
		tx_dst_to_release = e->tx_dst;
		e->tx_dst = NULL;
	}
	if (e->rx_dst) {
		rx_dst_to_release = e->rx_dst;
		e->rx_dst = NULL;
	}
	e->valid = 0;

	for (i = 0; i < MAX_DYNAMIC_IFC_NUM; i++) 
	{
		if (dynamic_ifc_ety[i].valid) {
			has_active_session = true;
			break;
		}
	}

	if (!has_active_session) {
		lro_restore_agg_num();
	}
	spin_unlock_irqrestore(&dynamic_ifc_lock, flags);

	if (sk_to_release)
		sock_put(sk_to_release);
	if (tx_dst_to_release)
		dst_release(tx_dst_to_release);
	if (rx_dst_to_release)
		dst_release(rx_dst_to_release);

	return;
}

static struct tcphdr *get_tcp_header(struct sk_buff *skb, unsigned short protocol)
{
	struct ipv6hdr *ipv6h;
	struct iphdr *iph;
	unsigned int ihl;
	unsigned int nhoff = skb_network_offset(skb);
	
	if (protocol == htons(ETH_P_IPV6)) 
	{
		/* NOTE: IPv6 extension headers are intentionally not parsed.
		* Only direct nexthdr==TCP is handled. Packets with extension
		* headers will gracefully fall back to the normal (non-IFC) path.
		*/
		if (skb_headlen(skb) < nhoff + sizeof(struct ipv6hdr) + sizeof(struct tcphdr)){
			return NULL;
		}
	
		ipv6h = ipv6_hdr(skb);
		if (ipv6h->nexthdr == IPPROTO_TCP){
			return (struct tcphdr *)((unsigned char *)ipv6h + sizeof(struct ipv6hdr));
		}
	} 
	else if (protocol == htons(ETH_P_IP)) 
	{
		if (skb_headlen(skb) < nhoff + sizeof(struct iphdr)){
			return NULL;
		}

		iph = ip_hdr(skb);
		ihl = iph->ihl << 2;

		if (ihl < sizeof(struct iphdr)){
			return NULL;
		}

		if (skb_headlen(skb) < nhoff + ihl + sizeof(struct tcphdr)){
			return NULL;
		}

		if (iph->protocol == IPPROTO_TCP){
			return (struct tcphdr *)((unsigned char *)iph + ihl);
		}
	}

	return NULL;
}

static struct dynamic_ifc* get_dynamic_ifc_ety(struct sk_buff *skb, unsigned short protocol, int out)
{
	struct tcphdr *th = get_tcp_header(skb, protocol);

	if(!th){
		return NULL;
	}

	if(out){
		return find_dynamic_ifc_ety_by_port(th->source,th->dest);
	}
	
	return find_dynamic_ifc_ety_by_port(th->dest,th->source);
}

static int local_out_pingpong(struct sk_buff *skb)
{
	struct dynamic_ifc* lo;
	struct dst_entry *tx_dst_clone;
	unsigned long flags;
	const struct ethhdr *eth;
	unsigned int min_net_hdr_len;

	if (unlikely(!skb_mac_header_was_set(skb))) {
		dev_kfree_skb(skb);
		return 0;
	}

	if (skb_headlen(skb) < ETH_HLEN) {
		dev_kfree_skb(skb);
		return 0;
	}

	eth = (struct ethhdr *)skb_mac_header(skb);
	if (unlikely((unsigned char *)eth != skb->data)) {
		dev_kfree_skb(skb);
		return 0;
	}
	
	if (eth->h_proto == htons(ETH_P_IP))
		min_net_hdr_len = sizeof(struct iphdr);
	else if (eth->h_proto == htons(ETH_P_IPV6))
		min_net_hdr_len = sizeof(struct ipv6hdr);
	else {
		dev_kfree_skb(skb);
		return 0;
	}

	if (skb_headlen(skb) < ETH_HLEN + min_net_hdr_len) {
		dev_kfree_skb(skb);
		return 0;
	}

	skb_set_network_header(skb, ETH_HLEN);
	if (skb_headlen(skb) < ETH_HLEN + min_net_hdr_len + sizeof(struct tcphdr)) {
		dev_kfree_skb(skb);
		return 0;
	}

	spin_lock_irqsave(&dynamic_ifc_lock, flags);
	lo = get_dynamic_ifc_ety(skb, eth->h_proto, 1);
	if (unlikely(!lo)) {
		spin_unlock_irqrestore(&dynamic_ifc_lock, flags);
		dev_kfree_skb(skb);
		return 0;
	}

	if (unlikely(!lo->tx_dst)) {
		spin_unlock_irqrestore(&dynamic_ifc_lock, flags);
		dev_kfree_skb(skb);
		return 0;
	}

	skb->inner_protocol = PPE_MAGIC_DYNAMIC_IFC;
	/* dst_clone() must be called under dynamic_ifc_lock to prevent
	* race with age_timer callback which may release lo->tx_dst.
	* The lock ensures tx_dst remains valid during dst_hold(). */
	tx_dst_clone = dst_clone(lo->tx_dst);
	spin_unlock_irqrestore(&dynamic_ifc_lock, flags);

	if (unlikely(!tx_dst_clone)) {
		dev_kfree_skb(skb);
		return 0;
	}

	skb_dst_drop(skb);
	skb_dst_set(skb, tx_dst_clone);
	if (unlikely(!tx_dst_clone->dev) || unlikely(!tx_dst_clone->output)) {
		skb_dst_drop(skb);
		dev_kfree_skb(skb);
		return 0;
	}

	skb_pull(skb, ETH_HLEN);       /* remove the fake ETH header */       
	skb_reset_network_header(skb);

	if (unlikely(!skb->sk)) {
		tx_dst_clone->output(dev_net(tx_dst_clone->dev), NULL, skb);
	} else {
		tx_dst_clone->output(dev_net(tx_dst_clone->dev), skb->sk, skb);
	}

	return 0;
}

int difc_get_app_num(void)
{
	return atomic_read(&dynamic_ifc_app_num);
}
EXPORT_SYMBOL(difc_get_app_num);

int difc_is_current_app(void)
{
	return is_dynamic_ifc_app(current->comm);
}
EXPORT_SYMBOL(difc_is_current_app);

void difc_add_entry_from_sock(struct sock *sk)
{
	int i;
	struct dynamic_ifc *lo;
	unsigned long flags;
	struct inet_sock *inet = inet_sk(sk);
	__be16 sport = inet->inet_sport;
	__be16 dport = inet->inet_dport;

	spin_lock_irqsave(&dynamic_ifc_lock, flags);
	if (find_dynamic_ifc_ety_by_port(sport, dport)) {
		spin_unlock_irqrestore(&dynamic_ifc_lock, flags);
		return;
	}

	for (i = 0; i < MAX_DYNAMIC_IFC_NUM; i++) 
	{
		lo = &dynamic_ifc_ety[i];
		if (!lo->valid) 
		{
			lo->local_port = sport;
			lo->remote_port = dport;
			lo->tx_dst = NULL;
			lo->rx_dst = NULL;
			lo->hash = 0;
			lo->last_tx = jiffies;
			sock_hold(sk);
			lo->sk = sk;
			lo->skip_copy = 0;
			lo->ifc_valid = 0;
			lo->ifc_index = 0;
			lo->ring_id = 0;
			lo->timer_active = 1;

			lro_save_and_set_agg_num(READ_ONCE(lro_agg_num));
			timer_setup(&lo->age_timer, dynamic_ifc_timeout, 0);
			mod_timer(&lo->age_timer, jiffies + EXPIRE_TIME);
			smp_wmb();
			lo->valid = 1;
			break;
		}
	}
	spin_unlock_irqrestore(&dynamic_ifc_lock, flags);
}
EXPORT_SYMBOL(difc_add_entry_from_sock);

int difc_handle_tcp_do_rcv(struct sock *sk, struct sk_buff *skb,
						   __be16 sport, __be16 dport)
{
	struct dynamic_ifc *lo;
	unsigned long flags;
	int cpu_reason = -1;
	struct dst_entry *old_dst = NULL;

	spin_lock_irqsave(&dynamic_ifc_lock, flags);
	lo = find_dynamic_ifc_ety_by_port(sport, dport);
	if (!lo || !lo->valid) {
		spin_unlock_irqrestore(&dynamic_ifc_lock, flags);
		return 0;
	}

	if (skb_dst(skb) && lo->rx_dst != skb_dst(skb)) {
		old_dst = lo->rx_dst;
		dst_hold(skb_dst(skb));
		lo->rx_dst = skb_dst(skb);
	}
	lo->hash = FOE_ENTRY_NUM(skb);

	if (!lo->ifc_valid) 
	{
		if (arht_hook_get_crsn) {
			cpu_reason = arht_hook_get_crsn(skb);
		} else {
			cpu_reason = (skb->hash & PPE_CPU_MASK) >> PPE_CPU_REASON_BIT;
		}

		if (cpu_reason != PPE_CPU_REASON_HIT_UNBIND_RATE_REACHED) {
			spin_unlock_irqrestore(&dynamic_ifc_lock, flags);
			if (old_dst){
				dst_release(old_dst);
			}
			return 0;
		}

		if (!lo->skip_copy && lo->sk) {
			lo->skip_copy = 1;
			WRITE_ONCE(lo->sk->sk_mark, SK_MARK_LOCAL_OFFLOAD);
		}
		/* Safe under spinlock: IFC APIs are atomic (MMIO only) */
		dynamic_ifc_add_ifc(lo);
	}
	spin_unlock_irqrestore(&dynamic_ifc_lock, flags);
	
	if (old_dst){
		dst_release(old_dst);
	}

	return 0;
}
EXPORT_SYMBOL(difc_handle_tcp_do_rcv);

/**
 * difc_handle_local_out - Build headers and transmit via hardware fast path.
 * @sk: socket owning this flow
 * @skb: packet buffer (may be GSO - hardware supports TSO)
 * @sport: source port (network byte order)
 * @dport: destination port (network byte order)
 * @is_ipv4: true for IPv4, false for IPv6
 * @mac: local MAC address (used for both src/dst in PPE pingpong path)
 * @fast_tx_fn: hardware TX function (QDMA fast path, TSO-capable)
 *
 * This function bypasses the normal kernel TX path (netfilter, GSO software
 * segmentation, traffic control). The QDMA hardware natively supports TSO,
 * so GSO-marked skbs are passed directly without software segmentation.
 *
 * Return: >0 if skb consumed, 0 if caller should continue normal path.
 */
int difc_handle_local_out(struct sock *sk, struct sk_buff *skb,
						  __be16 sport, __be16 dport,
						  bool is_ipv4, uint8_t *mac,
						  int (*fast_tx_fn)(struct sk_buff *, int))
{
	if (skb->inner_protocol == PPE_MAGIC_DYNAMIC_IFC){   
		return 0;      /* already been around once, let it go */
		}	
	struct dynamic_ifc *lo;
	unsigned long flags;
	struct iphdr *iph;
	int ipv6_plen = 0;
	struct dst_entry *old_tx_dst = NULL;
	__be16 proto;

	if (!is_ipv4) {
		ipv6_plen = skb->len - skb_network_offset(skb) - sizeof(struct ipv6hdr);
	}

	spin_lock_irqsave(&dynamic_ifc_lock, flags);
	lo = find_dynamic_ifc_ety_by_port(sport, dport);
	if (!lo) {
		spin_unlock_irqrestore(&dynamic_ifc_lock, flags);
		return 0;
	}

	if (skb_dst(skb) && lo->tx_dst != skb_dst(skb)) {
		old_tx_dst = lo->tx_dst;
		dst_hold(skb_dst(skb));
		lo->tx_dst = skb_dst(skb);
	}

	lo->last_tx = jiffies;
	spin_unlock_irqrestore(&dynamic_ifc_lock, flags);

	/*
	 * Safe to proceed without lock: after updating last_tx = jiffies,
	 * the age_timer cannot expire for at least EXPIRE_TIME (1 second).
	 * All resources used below (skb, mac, fast_tx_fn) are independent
	 * of the session entry and cannot be invalidated by the timer.
	 */
	if (old_tx_dst){
		dst_release(old_tx_dst);
	}

	/*
	 * Ensure headroom for ETH_HLEN prepend below.
	 * skb_cow_head() may reallocate skb->head, but all subsequent L3/L4
	 * header accesses (ip_hdr(skb), ipv6_hdr(skb)) use offset-based
	 * macros (skb->head + skb->network_header), NOT cached pointers.
	 * Therefore no stale pointer issue exists after this call.
	 *
	 * If skb_cow_head fails, return 0 to let the normal IP output path
	 * handle this packet (skb is unmodified at this point).
	 */
	if (skb_cow_head(skb, ETH_HLEN)) {
		return 0;
	}

	/*
	 * Build L3 headers as template for hardware TSO.
	 * The QDMA hardware supports TSO natively and segments packets based on
	 * skb_shinfo(skb)->gso_size. For GSO skbs, tot_len/payload_len reflects
	 * total unsegmented size intentionally. For IPv6 when payload > 65535,
	 * payload_len is set to 0 per kernel TSO convention (skb_gso_reset).
	 */
	if (is_ipv4) {
		iph = ip_hdr(skb);
		iph_set_totlen(iph, skb->len);
		ip_send_check(iph);
		skb->protocol = htons(ETH_P_IP);
	} else {
		if (ipv6_plen > IPV6_MAXPLEN)
			ipv6_plen = 0;
		ipv6_hdr(skb)->payload_len = htons(ipv6_plen);
		IP6CB(skb)->nhoff = offsetof(struct ipv6hdr, nexthdr);
		skb->protocol = htons(ETH_P_IPV6);
	}

	/* Build L2 header and transmit */
	skb->inner_protocol = PPE_MAGIC_DYNAMIC_IFC;
	skb_push(skb, ETH_HLEN);
	/* INTENTIONAL: dummy L2 hdr, PPE routes by sp_tag not MAC, pkt never leaves SoC */
	memcpy(skb->data, mac, ETH_ALEN);
	memcpy(skb->data + ETH_ALEN, mac, ETH_ALEN);
	proto = skb->protocol;
	memcpy(skb->data + 12, &proto, sizeof(proto));

	/*
	 * fast_tx_fn always consumes skb (queued on success, freed on error).
	 * Do NOT access skb after this call.
	 */
	fast_tx_fn(skb, 7);

	return 1;  /* skb consumed */
}
EXPORT_SYMBOL(difc_handle_local_out);

int difc_resolve_ecnt_hook(void)
{
	void *addr;

	addr = arht_kprobe_resolve_symbol("__ECNT_HOOK");
	if (!addr) {
		pr_err("arht_dynamic_ifc: resolve __ECNT_HOOK failed (arht-hook.ko not loaded!)\n");
		return -ENODEV;
	}

	WRITE_ONCE(__difc_ecnt_hook_fn, (ecnt_hook_fn_t)addr);
	return 0;
}

void difc_clear_ecnt_hook(void)
{
	WRITE_ONCE(__difc_ecnt_hook_fn, NULL);
}
EXPORT_SYMBOL(difc_clear_ecnt_hook);

static void dynamic_ifc_cleanup_all_sessions(void)
{
	int i;
	struct dynamic_ifc *lo;
	unsigned long flags;
	bool need_timer_sync[MAX_DYNAMIC_IFC_NUM] = {false};
	struct sock *sk_list[MAX_DYNAMIC_IFC_NUM] = {NULL};
	struct dst_entry *tx_dst_list[MAX_DYNAMIC_IFC_NUM] = {NULL};
	struct dst_entry *rx_dst_list[MAX_DYNAMIC_IFC_NUM] = {NULL};

	spin_lock_irqsave(&dynamic_ifc_lock, flags);	
	for (i = 0; i < MAX_DYNAMIC_IFC_NUM; i++) 
	{
		lo = &dynamic_ifc_ety[i];
		if (lo->valid && lo->timer_active) {
			need_timer_sync[i] = true;
			lo->timer_active = 0;
		}
	}
	spin_unlock_irqrestore(&dynamic_ifc_lock, flags);
	
	for (i = 0; i < MAX_DYNAMIC_IFC_NUM; i++) {
		if (need_timer_sync[i])
			timer_delete_sync(&dynamic_ifc_ety[i].age_timer);
	}

	spin_lock_irqsave(&dynamic_ifc_lock, flags);
	for (i = 0; i < MAX_DYNAMIC_IFC_NUM; i++) 
	{
		lo = &dynamic_ifc_ety[i];
		if (!lo->valid)
			continue;
	
		if (lo->ifc_valid) {
			/* Safe under spinlock: IFC APIs are atomic (MMIO only) */
			dynamic_ifc_del_ifc(lo);
		}
	
		if (lo->sk) {
			WRITE_ONCE(lo->sk->sk_mark, 0);
			sk_list[i] = lo->sk;
			lo->sk = NULL;
		}
		if (lo->tx_dst) {
			tx_dst_list[i] = lo->tx_dst;
			lo->tx_dst = NULL;
		}
		if (lo->rx_dst) {
			rx_dst_list[i] = lo->rx_dst;
			lo->rx_dst = NULL;
		}
	
		lo->valid = 0;
		lo->skip_copy = 0;
	}

	lro_restore_agg_num();
	spin_unlock_irqrestore(&dynamic_ifc_lock, flags);

	for (i = 0; i < MAX_DYNAMIC_IFC_NUM; i++) {
		if (sk_list[i])
			sock_put(sk_list[i]);
		if (tx_dst_list[i])
			dst_release(tx_dst_list[i]);
		if (rx_dst_list[i])
			dst_release(rx_dst_list[i]);
	}
}

static int dynamic_ifc_seq_show(struct seq_file *m, void *v)
{
	int i;
	struct dynamic_ifc *lo;
	unsigned long flags;

	seq_printf(m, "arht_dynamic_ifc: %s\n", READ_ONCE(dynamic_ifc_enable) ? "enabled" : "disabled");
	seq_printf(m, "lro_agg_num: %d (default: %d)\n", lro_agg_num, LRO_AGG_NUM_DEFAULT);

	seq_printf(m, "Apps: ");
	spin_lock_irqsave(&dynamic_ifc_lock, flags);
	for (i = 0; i < MAX_DYNAMIC_IFC_APP_NUM; i++)
	{
		if (dynamic_ifc_app_valid[i] && dynamic_ifc_apps[i][0] != '\0')
			seq_printf(m, "%s ", dynamic_ifc_apps[i]);
	}

	seq_printf(m, "\nentry: \n");
	for(i=0; i<MAX_DYNAMIC_IFC_NUM; i++)
	{
		lo = &dynamic_ifc_ety[i];
		if(!lo->valid)
			continue;
		seq_printf(m, "\t[%d] local_port:%d remote_port:%d hash:%d ifc:%d ring:%d time:%ums\n", 
			i, ntohs(lo->local_port), ntohs(lo->remote_port), lo->hash, lo->ifc_valid, lo->ring_id, jiffies_to_msecs(jiffies - lo->last_tx));
	}
	spin_unlock_irqrestore(&dynamic_ifc_lock, flags);
	seq_printf(m, "\n");

	return 0;
}

static int dynamic_ifc_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, dynamic_ifc_seq_show, NULL);
}

static ssize_t dynamic_ifc_write_proc(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char str[64] = {0};
	char cmd[32] = {0};
	char name[TASK_COMM_LEN] = {0};
	int val = 0, ret;
	unsigned long flags;

	if (count > sizeof(str) - 1)
		return -EINVAL;

	if (copy_from_user(str, buf, count))
		return -EFAULT;

	str[count] = '\0';

	if (count > 0 && str[count - 1] == '\n')
		str[count - 1] = '\0';

	if (sscanf(str, "%31s", cmd) < 1)
		return -EINVAL;

	if (!strcmp(cmd, "enable")) 
	{
		mutex_lock(&dynamic_ifc_enable_mutex);
		if (!dynamic_ifc_enable) 
		{
			ret = difc_resolve_ecnt_hook();
			if (ret == 0)
			{
				ret = arht_kprobe_difc_init();
				if (ret == 0) {
					WRITE_ONCE(dynamic_ifc_enable, 1);
					pr_info("arht_dynamic_ifc enabled\n");
				} else {
					difc_clear_ecnt_hook();
					pr_err("arht_dynamic_ifc enable failed - kprobe: %d\n", ret);
					mutex_unlock(&dynamic_ifc_enable_mutex);
					return ret;
				}
			} else {
				pr_err("arht_dynamic_ifc enable failed - __ECNT_HOOK not available!!!");
				mutex_unlock(&dynamic_ifc_enable_mutex);
				return -ENODEV;
			}
		} else {
			pr_info("arht_dynamic_ifc already enabled\n");
		}
		mutex_unlock(&dynamic_ifc_enable_mutex);
	} else if (!strcmp(cmd, "disable")) {
		mutex_lock(&dynamic_ifc_enable_mutex);
		if (dynamic_ifc_enable) {
			arht_kprobe_difc_exit();
			WRITE_ONCE(dynamic_ifc_enable, 0);
			dynamic_ifc_cleanup_all_sessions();
			WRITE_ONCE(__difc_ecnt_hook_fn, NULL);
			pr_info("arht_dynamic_ifc disabled\n");
		} else {
			pr_info("arht_dynamic_ifc already disabled\n");
		}
		mutex_unlock(&dynamic_ifc_enable_mutex);
	} else if (!strcmp(cmd, "debug")) {
		if (sscanf(str, "%31s %d", cmd, &val) == 2) {
			if (val) {
				debug_level = val;
			} else {
				debug_level = 0;
			}
			pr_info("arht_dynamic_ifc: debug_level = %d\n", debug_level);
		}
	} else if (!strcmp(cmd, "agg_num")) {
		if (sscanf(str, "%31s %d", cmd, &val) == 2) {
			if (val < LRO_AGG_NUM_MIN || val > LRO_AGG_NUM_MAX) {
				pr_err("arht_dynamic_ifc: agg_num out of range [%d, %d]\n", LRO_AGG_NUM_MIN, LRO_AGG_NUM_MAX);
			} else {
				WRITE_ONCE(lro_agg_num, val);
				pr_info("arht_dynamic_ifc: lro_agg_num = %d\n", lro_agg_num);
			}
		} else {
			pr_info("arht_dynamic_ifc: current lro_agg_num = %d\n", lro_agg_num);
		}
	} else {
		/* Original format: "1 iperf3" or "0 iperf3" - add/del app */
		val = 0;
		if (sscanf(str, "%d %15s", &val, name) == 2) {
			if (name[0] == '\0') {
				return -EINVAL;
			} else if (val != 0 && val != 1) {
				return -EINVAL;
			}
			spin_lock_irqsave(&dynamic_ifc_lock, flags);
			if (val){
				if (strlen(name) > TASK_COMM_LEN - 1){
					pr_err("arht_dynamic_ifc: app name '%s' truncated to %d chars (TASK_COMM_LEN limit)\n", 
						name, TASK_COMM_LEN - 1);
				}
				dynamic_ifc_app_list_add(name);
			}else{
				dynamic_ifc_app_list_del(name);
			}
			spin_unlock_irqrestore(&dynamic_ifc_lock, flags);
		}
	}
	
	return count;
}

static const struct proc_ops dynamic_ifc_fops = {
	.proc_open = dynamic_ifc_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
	.proc_write = dynamic_ifc_write_proc,
};

static int __init arht_dynamic_ifc_init(void)
{
	int i;

	df_proc_entry = proc_create("dynamic_ifc", 0644, NULL, &dynamic_ifc_fops);
	if (!df_proc_entry) {
		pr_err("arht_dynamic_ifc: failed to create proc entry\n");
		return -ENOMEM;
	}

	rcu_assign_pointer(dynamic_ifc_pingpong_hook, local_out_pingpong);
	rcu_assign_pointer(dynamic_ifc_sock_in_use_hook, dynamic_ifc_sock_in_use);

	for (i = 0; i < IFC_LRO_RING_NUM; i++){
		ifc_ring_reserve[i] = IFC_RING_SLOT_FREE;
	}

	dynamic_ifc_app_list_add("iperf3");
	dynamic_ifc_app_list_add("ookla");

	return 0;
}

static void __exit arht_dynamic_ifc_exit(void)
{
	if (df_proc_entry) {
		remove_proc_entry("dynamic_ifc", NULL);
		df_proc_entry = NULL;
	}

	mutex_lock(&dynamic_ifc_enable_mutex);
	if (dynamic_ifc_enable) {
		arht_kprobe_difc_exit();
		WRITE_ONCE(dynamic_ifc_enable, 0);
		pr_info("arht_dynamic_ifc disabled\n");
	}
	mutex_unlock(&dynamic_ifc_enable_mutex);

	rcu_assign_pointer(dynamic_ifc_pingpong_hook, NULL);
	rcu_assign_pointer(dynamic_ifc_sock_in_use_hook, NULL);
	synchronize_rcu();

	/* No race: proc removed, kprobes unregistered, no new entries possible. */
	dynamic_ifc_cleanup_all_sessions();

	WRITE_ONCE(__difc_ecnt_hook_fn, NULL);
}

#else /* !ARHT_DIFC_FULL_SUPPORT */

static int __init arht_dynamic_ifc_init(void)
{
	pr_info("arht_dynamic_ifc: No Dynamic IFC support!!!\n");
	return 0;
}

static void __exit arht_dynamic_ifc_exit(void)
{
}

#endif

late_initcall(arht_dynamic_ifc_init);
module_exit(arht_dynamic_ifc_exit);
