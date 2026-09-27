// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 AIROHA Inc
 * Author:  2024 AIROHA Inc
 */
#include <linux/if_bridge.h>
#include <linux/version.h>
#include <arht_hook/ecnt_hook_gen_offload.h>
#include <../net/bridge/br_private.h>
#include <../net/dsa/tag.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <../net/8021q/vlan.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/notifier.h>

#include "airoha_eth.h"
#include "airoha_regs.h"
#include "airoha_function.h"
#include "arht_loopback.h"


/*
 * To prevent excessive CPU load caused by continuously deleting a large
 * number of nf_conntrack rules, limit the maximum number of conntrack
 * deletions per clean operation to 50.
 */
#define PPE_MAX_CT_DELETE_PER_CLEAN 50

extern int (*fe_resource_mark_if_meter_hook)( struct sk_buff *skb, int dir);
/************************************************************************
*                  P U B L I C   D A T A
*************************************************************************
*/
struct FoeEntryExt*  foe_ext = NULL;
EXPORT_SYMBOL(foe_ext);
struct hwnat_shrink_table shnkTbl[UPDMEM_NUM];
EXPORT_SYMBOL(shnkTbl);
static DEFINE_SPINLOCK(shnk_tbl_lock);
int timeOutVal=3000;	//30s
static DEFINE_SPINLOCK(ppe_sram_access_lock);

int packet_is_transparent_mode = 0;
EXPORT_SYMBOL(packet_is_transparent_mode);

struct devBandwidthList_s *gHwBandwidthList = NULL;
EXPORT_SYMBOL(gHwBandwidthList);

enum clean_entry_type {
    CLEAN_BY_GEMPORT,
    CLEAN_BY_CHANNEL,
    CLEAN_BY_MAC,
    CLEAN_BY_SRC_MAC,
    CLEAN_BY_DST_MAC,
    CLEAN_BY_TYPE,
    CLEAN_BY_IP,
    CLEAN_MULTICAST,
	CLEAN_TABLE,
	CLEAN_BY_LANDEV,
	CLEAN_BY_FPORT_AND_CHANNEL,
	CLEAN_BY_PORT,
	CLEAN_TYPE_MAX
};

/* Structure to hold fport and channel clean parameters */
struct clean_lan_params {
	int fport;
	int channel;
};

struct clean_port_params {
    u16 src_port;
    u16 dest_port;
};

struct clean_entry_work {
    struct work_struct work;
    enum clean_entry_type type;
    void *data;
    size_t data_len;
};

static struct workqueue_struct *clean_entry_wq;

/************************************************************************
*                  E X T E R N E L   D A T A
*************************************************************************
*/
extern spinlock_t ppe_lock;
extern int (*ra_sw_nat_hook_clean_table) (void);

int (*ra_sw_nat_hook_drop_packet) (struct sk_buff * skb) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_drop_packet);
int (*ra_sw_nat_hook_clean_entry_by_gemport)(unsigned int gemport_id) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_clean_entry_by_gemport);
int (*ra_sw_nat_hook_clean_entry_by_channel)(int channelIdx) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_clean_entry_by_channel);
int (*ra_sw_nat_hook_clean_entry_by_dev)(struct net_device *dev) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_clean_entry_by_dev);
int (*ra_sw_nat_hook_clean_entry_by_mac)(const unsigned char *mac) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_clean_entry_by_mac);
int (*hwnat_clean_entry_by_src_mac_hook)(const unsigned char *mac) = NULL;
EXPORT_SYMBOL(hwnat_clean_entry_by_src_mac_hook);
int (*hwnat_clean_entry_by_dst_mac_hook)(const unsigned char *mac) = NULL;
EXPORT_SYMBOL(hwnat_clean_entry_by_dst_mac_hook);
int (*ra_sw_nat_hook_clean_entry_by_type)(unsigned char type) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_clean_entry_by_type);
int (*ra_sw_nat_hook_clean_entry_by_ip)(unsigned int ip_addr) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_clean_entry_by_ip);
int (*ra_sw_nat_hook_clean_multicast_entry) (void) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_clean_multicast_entry);
int (*ra_sw_nat_hook_foeentry) (void *inputvalue, int operation) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_foeentry);
unsigned int (*hwnat_set_bind_threshold_hook)(unsigned int threshold) = NULL;
EXPORT_SYMBOL(hwnat_set_bind_threshold_hook);
int (*hwnat_set_special_tag_hook)(int index, int tag) = NULL;
EXPORT_SYMBOL(hwnat_set_special_tag_hook);
int (*multicast_flood_is_bind_hook)(int index) = NULL;
EXPORT_SYMBOL(multicast_flood_is_bind_hook);
int (*hwnat_delete_foe_entry_hook_unlock)(int index) = NULL;
EXPORT_SYMBOL(hwnat_delete_foe_entry_hook_unlock);
int (*arht_multicast_list_add_hook)(struct airoha_foe_entry *hwe, struct sk_buff* skb);
EXPORT_SYMBOL(arht_multicast_list_add_hook);
int (*hwnat_set_multicast_vlan_hook)(int index, int vid, int vpm) = NULL;
EXPORT_SYMBOL(hwnat_set_multicast_vlan_hook);
int (*hwnat_is_multicast_entry_hook)(int index ,unsigned char* grp_addr,unsigned char* src_addr,int type) = NULL;
EXPORT_SYMBOL(hwnat_is_multicast_entry_hook);
int (*hwnat_is_drop_entry_hook)(int index ,unsigned char* grp_addr,unsigned char* src_addr,int type) = NULL;
EXPORT_SYMBOL(hwnat_is_drop_entry_hook);
int (*arht_soe_offload_get_valid_hook)(unsigned int foe_index) = NULL;
EXPORT_SYMBOL(arht_soe_offload_get_valid_hook);
int (*arht_multicast_hwnat_data_handler_hook)(struct airoha_foe_entry *hwe, struct sk_buff* skb) = NULL;
EXPORT_SYMBOL(arht_multicast_hwnat_data_handler_hook);
int (*arht_multicast_hwnat_set_valid_hook)(unsigned int foe_index) = NULL;
EXPORT_SYMBOL(arht_multicast_hwnat_set_valid_hook);
int (*arht_multicast_hwnat_get_valid_hook)(unsigned int foe_index) = NULL;
EXPORT_SYMBOL(arht_multicast_hwnat_get_valid_hook);
int (*ra_sw_nat_hook_clean_entry_by_landev)(struct net_device *dev) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_clean_entry_by_landev);
int (*ra_sw_nat_hook_clean_entry_by_fport_and_channel)(int fport, int channelIdx) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_clean_entry_by_fport_and_channel);
int (*ra_sw_nat_hook_clean_entry_by_port)(u16 src_port, u16 dest_port) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_clean_entry_by_port);

int (*airoha_ppe_foe_commit_entry_ptr)(struct airoha_ppe *ppe,struct airoha_foe_entry *e,u32 hash,bool rx_wlan) = airoha_ppe_foe_commit_entry;
EXPORT_SYMBOL(airoha_ppe_foe_commit_entry_ptr);
int (*hwnat_skb_to_foe_hook)(struct sk_buff* skb) = NULL;
EXPORT_SYMBOL(hwnat_skb_to_foe_hook);
int (*hwnat_delete_foe_entry_hook)(int index) = NULL; 
EXPORT_SYMBOL(hwnat_delete_foe_entry_hook);


int (*ra_sw_nat_update_acnt_info_hook) (struct airoha_foe_entry *foe_entry, struct sk_buff * skb, struct port_info * pinfo, u8 fport);
EXPORT_SYMBOL(ra_sw_nat_update_acnt_info_hook);

int (*hwnat_loopback_hook)(struct sk_buff *skb, struct port_info *pinfo, unsigned int crsn, u8 fport) = NULL;
EXPORT_SYMBOL(hwnat_loopback_hook);

static int ppe_is_multicast_entry(struct airoha_foe_entry *hwe);


/************************************************************************
*                  E X T E R N E L   F U N C T I O N
*************************************************************************
*/
extern int (*airoha_pon_is_sfu_point_to_point_mode_hook)(struct sk_buff *skb);
extern u8 get_dscp_from_skb(struct sk_buff *skb, int type);
extern int (*airoha_tunnel_hook_tx) (struct sk_buff * skb,struct airoha_ppe *ppe,struct port_info *pinfo);
extern int (*set_entry_reason_hook)(struct sk_buff *skb,u32 reason);
extern int (*arht_hook_get_crsn) (struct sk_buff * skb);
extern unsigned short get_meter_idx_by_gemport(struct sk_buff *skb, struct port_info *pinfo, u8 fport);
extern unsigned short get_meter_idx_by_lan(struct sk_buff *skb, struct port_info *pinfo, u8 fport);
extern void airoha_set_default_acnt_meter_idx(struct airoha_foe_entry *hwe, int type);
extern int airoha_get_free_lro_ring(u32 foe_entry_idx);
extern int (*ra_sw_nat_hook_rxinfo) (struct sk_buff * skb, int magic, char *data, int data_length);
extern int (*fe_resource_mark_acnt_hook)( struct sk_buff *skb, int dir);
extern int (*fe_resource_mark_meter_hook)( struct sk_buff *skb, int dir);

int airoha_set_entry_fe_resource_mark(u32 foe_entry_idx, u32 fe_resource_mark)
{
	if ( foe_entry_idx >= glb_eth->soc->ppe_sram_etry_num )
	{
		return 0;
	}
	if ( foe_ext[foe_entry_idx].fe_resource_mark != fe_resource_mark )
	{
		foe_ext[foe_entry_idx].fe_resource_mark = fe_resource_mark;
	}
	return 1;
}
EXPORT_SYMBOL(airoha_set_entry_fe_resource_mark);

u32 airoha_get_entry_fe_resource_mark(u32 foe_entry_idx)
{
	if ( foe_entry_idx >= glb_eth->soc->ppe_sram_etry_num )
	{
		return 0;
	}
	return foe_ext[foe_entry_idx].fe_resource_mark;
}
EXPORT_SYMBOL(airoha_get_entry_fe_resource_mark);

static int set_entry_cpu_reason(struct sk_buff *skb,u32 reason)
{
	reason &= 0x1F;
	
	skb->hash &= ~AIROHA_PPE_CPU_MASK;
	skb->hash |= (reason << 27);
	
	return 1;
}

int is_Valid_Foe_Entry(struct sk_buff * skb)
{
	u32 hash = FOE_ENTRY_NUM(skb);
	if ( hash >= glb_eth->soc->ppe_sram_etry_num || !skb->l4_hash || skb->sw_hash != false || skb->sk != NULL )
		return 0;
	return 1;
}
EXPORT_SYMBOL(is_Valid_Foe_Entry);

static int get_entry_cpu_reason(struct sk_buff * skb)
{
	if ( !is_Valid_Foe_Entry(skb) )
		return -1;
	return (skb->hash & AIROHA_PPE_CPU_MASK) >> AIROHA_PPE_CPU_REASON_BIT;
}

int arht_multicast_handler_for_sfu(struct sk_buff* skb)
{
	struct airoha_foe_entry *hwe = NULL;
	u32 hash = FOE_ENTRY_NUM(skb);

	if(glb_eth == NULL)
		return 0;
	
	if(!airoha_is_pon_sfu_mode())
		return 0;
	//transparent mode is for single port, no need learn drop
	if(packet_is_transparent_mode)
		return 0;
	if(arht_hook_get_crsn(skb) != PPE_CPU_REASON_HIT_UNBIND_RATE_REACHED)
		return 0;
	
	spin_lock_bh(&ppe_lock);
	hwe = airoha_ppe_foe_get_entry_locked(glb_eth->ppe, hash);
	
	if(ppe_is_multicast_entry(hwe)){
		spin_unlock_bh(&ppe_lock);
		arht_ppe_multicast_handler(glb_eth->ppe, skb);
		return 1;
	}
	spin_unlock_bh(&ppe_lock);
	return 0;
}
EXPORT_SYMBOL(arht_multicast_handler_for_sfu);

static int airoha_is_pon_point_to_point_mode(struct sk_buff *skb)
{
	//0: not point to point mode, 1: is point to point mode
	if(airoha_pon_is_sfu_point_to_point_mode_hook){
		return airoha_pon_is_sfu_point_to_point_mode_hook(skb);
	}
	
	return 0;
}


static int packet_hash_collision_check(struct sk_buff *skb,
				       struct airoha_foe_entry *foe_entry)
{
	__be16 proto = skb->protocol;

	/* Unwrap 802.1Q/802.1ad to reach the inner ethertype */
	if (proto == htons(ETH_P_8021Q) || proto == htons(ETH_P_8021AD)) {
		if (!pskb_may_pull(skb, skb_network_offset(skb) + sizeof(struct vlan_hdr)))
			return 0;
		proto = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
	}

	if (proto == htons(ETH_P_IP)) {
		struct iphdr *iph;

		if (!pskb_may_pull(skb, skb_network_offset(skb) + sizeof(struct iphdr)))
			return 0;

		iph = ip_hdr(skb);
		if (IS_IPV4_GRP(foe_entry)) {
			if (ntohl(iph->saddr) != foe_entry->ipv4.orig_tuple.src_ip ||
			    ntohl(iph->daddr) != foe_entry->ipv4.orig_tuple.dest_ip) {
				AIROHA_LOG(AIROHA_DEBUG_LEVEL_DBG,
					   "packet_hash_collision_check: IPv4 collision sip=%pI4 dip=%pI4\n",
					   &iph->saddr, &iph->daddr);
				return -1;
			}
		}
	} else if (proto == htons(ETH_P_IPV6)) {
		struct ipv6hdr *iph6;
		struct in6_addr foe_sip = {}, foe_dip = {};

		if (!pskb_may_pull(skb, skb_network_offset(skb) + sizeof(struct ipv6hdr)))
			return 0;

		iph6 = ipv6_hdr(skb);
		if (IS_IPV6_GRP(foe_entry)) {
			foe_sip.s6_addr32[0] = htonl(foe_entry->ipv6.src_ip[0]);
			foe_sip.s6_addr32[1] = htonl(foe_entry->ipv6.src_ip[1]);
			foe_sip.s6_addr32[2] = htonl(foe_entry->ipv6.src_ip[2]);
			foe_sip.s6_addr32[3] = htonl(foe_entry->ipv6.src_ip[3]);
			foe_dip.s6_addr32[0] = htonl(foe_entry->ipv6.dest_ip[0]);
			foe_dip.s6_addr32[1] = htonl(foe_entry->ipv6.dest_ip[1]);
			foe_dip.s6_addr32[2] = htonl(foe_entry->ipv6.dest_ip[2]);
			foe_dip.s6_addr32[3] = htonl(foe_entry->ipv6.dest_ip[3]);
			if (memcmp(&iph6->saddr, &foe_sip, sizeof(struct in6_addr)) != 0 ||
			    memcmp(&iph6->daddr, &foe_dip, sizeof(struct in6_addr)) != 0) {
				AIROHA_LOG(AIROHA_DEBUG_LEVEL_DBG,
					   "packet_hash_collision_check: IPv6 collision\n");
				return -1;
			}
		}
	}

	return 0;
	
}

inline static bool arht_vlan_exist(struct sk_buff *skb)
{
    return (vlan_eth_hdr(skb)->h_vlan_proto == htons(ETH_P_8021Q));
}

static struct net_device* arht_get_vlandev(struct sk_buff* skb)
{
	struct net_device* dev = NULL;
	struct vlan_ethhdr *vlan_eth = NULL;

	vlan_eth = vlan_eth_hdr(skb);
	if(!skb->dev || !vlan_eth){
		return NULL;
	}

	dev = vlan_find_dev(skb->dev, vlan_eth->h_vlan_proto, ntohs(vlan_eth->h_vlan_TCI) & VLAN_VID_MASK);
	
	return dev;
}

static int airoha_check_flood_packet(struct sk_buff *skb, u16 vid, u32 tag)
{
	struct net_bridge *br;
	struct net_device *dev = NULL, *tmp_dev = NULL;
	struct net_bridge_port *p;
	struct net_bridge_fdb_entry *f;
	unsigned char *addr;
	int port_idx = 1;

	//transparent mode is for single port, no need check flood
	if(packet_is_transparent_mode)
		return 1;
	
	if (!skb || !skb->dev){
		return 0;
	}
	tmp_dev = skb->dev;

	if (netdev_uses_dsa(tmp_dev))
	{
		port_idx = ffs(tag)-1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0)
		tmp_dev = dsa_master_find_slave(tmp_dev, 0, port_idx);
#else
		tmp_dev = dsa_conduit_find_user(tmp_dev, 0, port_idx);
#endif
		if(!tmp_dev)
			return 0;

	}

	p = br_port_get_rcu(tmp_dev);
	if (!p || !p->dev){
		if(arht_vlan_exist(skb)){
			tmp_dev = arht_get_vlandev(skb);
			if(!tmp_dev){
				struct net_device *br_dev;
				addr = skb->data;
				rcu_read_lock();
				for_each_netdev_rcu(dev_net(skb->dev), br_dev) {
					if (!netif_is_bridge_master(br_dev))
						continue;
					struct net_bridge *br_tmp = netdev_priv(br_dev);
					if (!br_tmp)
						continue;
					struct net_bridge_fdb_entry *f_tmp = br_fdb_find_rcu(br_tmp, addr, vid);
					if (f_tmp && f_tmp->dst) {
						rcu_read_unlock();
						return 1;
					}
				}
				rcu_read_unlock();
				return 0;
			}
			p = br_port_get_rcu(tmp_dev);
			
			if (!p || !p->dev){
				return 0;
			}
		}
		else
		{
			return 0;
		}
	}
	br = p->br;

	if (!br){
		return 0;
	}

	addr = skb->data;
	
	rcu_read_lock();
	f = br_fdb_find_rcu(br, addr, vid);
	if (f && f->dst){
		dev = f->dst->dev;
	}	
	rcu_read_unlock();

	if (dev && dev == tmp_dev){
		return 1;
	}

	return 0;
}

static u32 airoha_ppe_get_timestamp(struct airoha_ppe *ppe)
{
	u16 timestamp = airoha_fe_rr(ppe->eth, REG_FE_FOE_TS);

	return FIELD_GET(AIROHA_FOE_IB1_BIND_TIMESTAMP, timestamp);
}

void UpdateShrinkTable(int index,const u8 *addr)
{	
	if (index >= 0 && index < UPDMEM_NUM)
	{
		spin_lock_bh(&shnk_tbl_lock);
		memcpy(&shnkTbl[index].smac[0], addr, ETH_ALEN);
		shnkTbl[index].valid[PPE_UPDMEM_SEL_SMAC] = 1;
		shnkTbl[index].pinned[PPE_UPDMEM_SEL_SMAC] = 1;
		spin_unlock_bh(&shnk_tbl_lock);
	}
	return;
}

inline static int is_ipv4_multicast(u32 ip)
{
	// 224.0.0.0 ~ 224.0.0.255 control packet    
	// 224.0.1.0 ~ 239.255.255.255 data packet    
	if (ip >= 0xE0000000 && ip <= 0xE00000FF) 
	{
		return TO_CPU;
	} 
	else if (ip >= 0xE0000100 && ip <= 0xEFFFFFFF) 
	{
		return TO_MULTICAST_OFFLOAD;
	}    
	return TO_CPU; 
}

inline static int is_ipv6_multicast(u32 addr)
{
	if (((addr >> 24) & 0xFF) == 0xFF) 
	{ 
		u8 scope = (addr >> 16) & 0xFF;
		if (scope == 0x02) {
			return TO_CPU;
		} else {
			return TO_MULTICAST_OFFLOAD;
		}    
	}
	return TO_CPU;
}

static void FoeGetEntryDstMac(u8 * Dst, u32 Dst_hi, u16 Dst_lo)
{
	Dst[0] = ((Dst_hi&0xff000000) >> 24);
	Dst[1] = ((Dst_hi&0xff0000) >> 16);
	Dst[2] = ((Dst_hi&0xff00) >> 8);
	Dst[3] = (Dst_hi&0xff) ;
	Dst[4] = ((Dst_lo&0xff00) >> 8);
	Dst[5] = (Dst_lo&0xff);
}


/*Using return value to judge
0:is not multicast entry
1:is multicast entry and is for ipv4
2:is multicast entry and is for ipv6
*/
static int ppe_is_multicast_entry(struct airoha_foe_entry *hwe)
{
	unsigned char dst_mac[ETH_ALEN] = {0};

	if(hwe == NULL)
	{
		return 0;
	}

	if (FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, hwe->ib1) < PPE_PKT_TYPE_BRIDGE )
	{
		if(is_ipv4_multicast(hwe->ipv4.orig_tuple.dest_ip))
		{
			return 1;
		}
	}
	else if (FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, hwe->ib1) == PPE_PKT_TYPE_BRIDGE)
	{
		FoeGetEntryDstMac(dst_mac, hwe->bridge.dest_mac_hi, hwe->bridge.dest_mac_lo);
		if(is_multicast_ether_addr(dst_mac) && !is_broadcast_ether_addr(dst_mac)) {
			return 1;
		} else {
			return 0;
		}
	}
	else if((FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, hwe->ib1) == PPE_PKT_TYPE_IPV6_ROUTE_3T)||
		(FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, hwe->ib1) == PPE_PKT_TYPE_IPV6_ROUTE_5T))
	{
		if (is_ipv6_multicast(hwe->ipv6.dest_ip[0]))
			return 2;
	}

	return 0;
}

int arht_ppe_multicast_handler(struct airoha_ppe *ppe, struct sk_buff* skb)
{
	unsigned int foe_index = FOE_ENTRY_NUM(skb);

	if ( !is_Valid_Foe_Entry(skb) )
		return 0;
	
	if(arht_multicast_hwnat_data_handler_hook)
	{
		struct airoha_foe_entry *hwe = NULL;
		spin_lock_bh(&ppe_lock);
		hwe = airoha_ppe_foe_get_entry_locked(ppe, foe_index);
		spin_unlock_bh(&ppe_lock);

		arht_multicast_hwnat_data_handler_hook(hwe, skb);
	}
	return 0;
}

void set_ppe_entry_smac_index (struct airoha_foe_entry *foe_entry, unsigned int type, unsigned char value)
{
    if(0x10 == value)/*workround for hw remove keep smac bit issue,now smac idx 0xf means keep smac*/
    {
		foe_entry->ipv6.l2.src_mac_hi = (foe_entry->ipv6.l2.src_mac_hi & ~AIROHA_FOE_MAC_SMAC_ID) | 
										FIELD_PREP(AIROHA_FOE_MAC_SMAC_ID, 0xf);
    }
    else
    {
		foe_entry->ipv6.l2.src_mac_hi = (foe_entry->ipv6.l2.src_mac_hi & ~AIROHA_FOE_MAC_SMAC_ID) | 
										FIELD_PREP(AIROHA_FOE_MAC_SMAC_ID, value);
    }
    return;
}

inline static int get_ppe_entry_smac_index (struct airoha_foe_entry *foe_entry, unsigned short type)
{
    if(type == PPE_PKT_TYPE_IPV6_ROUTE_3T || type == PPE_PKT_TYPE_IPV6_ROUTE_5T)
    {
        if(0xf == FIELD_GET(AIROHA_FOE_MAC_SMAC_ID, foe_entry->ipv6.l2.src_mac_hi))
            return 0x10;    /*workround for hw remove keep smac bit issue, now smac idx 0xf means keep smac*/
        else
            return FIELD_GET(AIROHA_FOE_MAC_SMAC_ID, foe_entry->ipv6.l2.src_mac_hi);
    }

    return 0;
}

inline static int get_ppe_entry_tunnel_ip_index (struct airoha_foe_entry *foe_entry, unsigned short type) 
{
    if(type == PPE_PKT_TYPE_IPV6_6RD)
        return FIELD_GET(AIROHA_FOE_TUNNEL_ID, foe_entry->ipv6.data);
    else if(type == PPE_PKT_TYPE_IPV4_DSLITE)
        return FIELD_GET(AIROHA_FOE_TUNNEL_ID, foe_entry->dslite.data);

    return 0;
}

static int airoha_is_bridge_packet(struct net_device *dev,unsigned char* src_addr)
{
	const unsigned char* dev_addr= dev->dev_addr;
	if( ether_addr_equal_64bits(dev_addr,src_addr))
		return false;
	else 
		return true;
}

static int ppeChecConfigDone(uint reg, uint doneBit)
{
	int RETRY = 10;
	volatile uint regValue = 0 ;
	
	while(RETRY--) {
		regValue = airoha_fe_rr(glb_eth, reg);
		
		if(regValue & doneBit) {
			break ;
		}
	}
	if(RETRY < 0) {
		return -ETIME ;
	}

	return 0;
}

static int ppeSetUpdateMemCtrl(unsigned int select, unsigned int addr, unsigned int offset)
{
	uint val=0 ;
	
	val = (PPE_UPDMEM_REQ | PPE_UPDMEM_WR 
		| ((addr<<PPE_UPDMEM_ADDR_SHIFT)&PPE_UPDMEM_ADDR_MASK)
		| ((offset<<PPE_UPDMEM_OFST_SHIFT)&PPE_UPDMEM_OFST_MASK)
		| ((select<<PPE_UPDMEM_SEL_SHIFT)&PPE_UPDMEM_SEL_MASK)) ;
	airoha_fe_wr(glb_eth, REG_UPDMEM_CTRL(0), val);

	if(ppeChecConfigDone(REG_UPDMEM_CTRL(0), PPE_UPDMEM_ACK) < 0) {
		printk("Timeout for set ppe update sram control configuration.\n") ;
		return -ETIME ;
	}
	
	return 0 ;
}

static void ppeSetUpdMemData(unsigned int mac_data)
{
	airoha_fe_wr(glb_eth, REG_UPDMEM_DATA(0), mac_data);
	return;
}

static int ppeSetShrinkField(int select, int index, struct hwnat_shrink_field *shrinkFieldPtr)
{
	int i=0;
	unsigned int mac_data=0;
	
	if(select==PPE_UPDMEM_SEL_SMAC) {
		for(i=0; i<2; i++) {

			if(i==0)
				mac_data = (shrinkFieldPtr->smac[2]<<24) | (shrinkFieldPtr->smac[3]<<16) | (shrinkFieldPtr->smac[4]<<8) | shrinkFieldPtr->smac[5];
			else
				mac_data = (shrinkFieldPtr->smac[0]<<8) | shrinkFieldPtr->smac[1];
			ppeSetUpdMemData(mac_data);
			ppeSetUpdateMemCtrl(select, index, i);
		}
	} else if(select==PPE_UPDMEM_SEL_IPv4) {
		for(i=0; i<UPDMEM_IPV4_LINE; i++) {
			ppeSetUpdMemData(shrinkFieldPtr->eg_ipv4[i]);
			ppeSetUpdateMemCtrl(select, index, i);
		}
	} else if(select==PPE_UPDMEM_SEL_IPv6) {
		for(i=0; i<UPDMEM_IPV6_LINE; i++) {
			ppeSetUpdMemData(shrinkFieldPtr->eg_ipv6[i]);
			if(i<=3)
				ppeSetUpdateMemCtrl(select, index, 3-i);
			else 
				ppeSetUpdateMemCtrl(select, index, 11-i);
		}
	}
	
	return 0;
}

static void reuse_shrink_table(void)
{
	unsigned int i = 0, j = 0, index = 0, select = 0, idx = 0, need_reuse = 1;
	struct airoha_foe_entry *foe_entry;
	unsigned int max_entries;
	lockdep_assert_held(&shnk_tbl_lock);

	if (!glb_eth || !glb_eth->ppe || !glb_eth->ppe->eth || !glb_eth->ppe->eth->soc){
	        return;
	}
	max_entries = glb_eth->ppe->eth->soc->ppe_sram_etry_num;

	/* if current entry is time out and no bindidx, invalid this entry */
	for(index = 0; index < UPDMEM_NUM; index++) 
	{
		for(select = 0; select < 3; select++) 
		{
			need_reuse = 1;
			if((!shnkTbl[index].pinned[select]) && time_after(jiffies, shnkTbl[index].timestamp[select]+ timeOutVal)) 
			{
				for(i = 0; i < BITMAP_IDX_SIZE; i++)
				{
					if(shnkTbl[index].bitmap[select][i] == 0){
						continue;
					}
					for(j = 0; j < 32; j++)
					{
						idx = i * 32 + j;
						if(idx >= max_entries){
							break;
						}

						if(test_bit(idx, shnkTbl[index].bitmap[select]))
						{
							foe_entry = airoha_ppe_foe_get_entry(glb_eth->ppe, idx);
							if(foe_entry == NULL){
								continue;
							}else if(FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, foe_entry->ib1) == AIROHA_FOE_STATE_BIND){
								need_reuse = 0;
							}else if(FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, foe_entry->ib1) == AIROHA_FOE_STATE_UNBIND){
								clear_bit(idx, shnkTbl[index].bitmap[select]);
							}
						}
					}
				}

				if(need_reuse){
					shnkTbl[index].valid[select] = 0;
				}
			}
		}
	}
}

int find_and_update_shrink_table(int select, struct hwnat_shrink_field *shrinkFieldPtr)
{
	int index=0, invldIdx=UPDMEM_NUM;
	unsigned idx_in = 0;

	if (!shrinkFieldPtr) {
		pr_err("%s: shrinkFieldPtr is NULL\n", __func__);
		return -1;
	}
	
	idx_in = shrinkFieldPtr->foe_idx;
	spin_lock_bh(&shnk_tbl_lock);
	/* find matched entry */
	for(index=0; index<UPDMEM_NUM; index++) 
	{
		if(shnkTbl[index].valid[select] == 1)
		{
			switch(select)
			{
				case PPE_UPDMEM_SEL_SMAC:
					if(memcmp(&shnkTbl[index].smac[0], &shrinkFieldPtr->smac[0], UPDMEM_SMAC_CNT) == 0) {
						goto success;
					}
					break;
					
				case PPE_UPDMEM_SEL_IPv4:
					if(memcmp(&shnkTbl[index].eg_ipv4[0], &shrinkFieldPtr->eg_ipv4[0], UPDMEM_IPV4_LINE*4) == 0) {
						goto success;
					}
					break;
					
				case PPE_UPDMEM_SEL_IPv6:
					if(memcmp(&shnkTbl[index].eg_ipv6[0], &shrinkFieldPtr->eg_ipv6[0], UPDMEM_IPV6_LINE*4) == 0) {
						goto success;
					}
					break;
					
				default:
					break;
			}
				
			/* if current entry is time out, invalid this entry */
			if((!shnkTbl[index].pinned[select]) && time_after(jiffies, shnkTbl[index].timestamp[select]+timeOutVal)) {
				shnkTbl[index].valid[select] = 0;
			}
		}
		
		if((shnkTbl[index].valid[select] == 0) && (index<invldIdx))
			invldIdx = index;
	}

	/* update entry if has position */
	if(invldIdx==UPDMEM_NUM) {
		index=-1;
		goto fail; 
	} else {
		index = invldIdx;
		switch(select) {
			case PPE_UPDMEM_SEL_SMAC:
				memcpy(&shnkTbl[index].smac[0], &shrinkFieldPtr->smac[0], UPDMEM_SMAC_CNT);
				ppeSetShrinkField(select, index, shrinkFieldPtr);				
				break;
				
			case PPE_UPDMEM_SEL_IPv4:
				memcpy(&shnkTbl[index].eg_ipv4[0], &shrinkFieldPtr->eg_ipv4[0], UPDMEM_IPV4_LINE*4);
				ppeSetShrinkField(select, index, shrinkFieldPtr);
				break;
				
			case PPE_UPDMEM_SEL_IPv6:
				memcpy(&shnkTbl[index].eg_ipv6[0], &shrinkFieldPtr->eg_ipv6[0], UPDMEM_IPV6_LINE*4);
				ppeSetShrinkField(select, index, shrinkFieldPtr);
				break;
				
			default:
				break;
		}
	}
	
success:
	shnkTbl[index].valid[select] = 1;
	if (glb_eth){
		if((idx_in > 0) && (idx_in < glb_eth->ppe->eth->soc->ppe_sram_etry_num)){
			set_bit(idx_in, shnkTbl[index].bitmap[select]);
		}
	}
	shnkTbl[index].timestamp[select] = jiffies;
	
fail:
	reuse_shrink_table();
	spin_unlock_bh(&shnk_tbl_lock);
	return index;
}
EXPORT_SYMBOL(find_and_update_shrink_table);

int ppe_dump_shrink_table(void)
{
	int index = 0;

	spin_lock_bh(&shnk_tbl_lock);
	reuse_shrink_table();
	
	printk("\nSMAC Table as Below:\n");
	for(index = 0; index < UPDMEM_NUM; index++) 
	{
		if(shnkTbl[index].valid[PPE_UPDMEM_SEL_SMAC] == 0) {
			printk("SMAC[%d]:  SW valid:0\n", index);
		} else {
			printk("SMAC[%d]:  SW valid:1, timestamp:%ld, SMAC:%x:%x:%x:%x:%x:%x\n",
				index, shnkTbl[index].timestamp[PPE_UPDMEM_SEL_SMAC], 
				shnkTbl[index].smac[0], shnkTbl[index].smac[1], shnkTbl[index].smac[2],
				shnkTbl[index].smac[3], shnkTbl[index].smac[4], shnkTbl[index].smac[5]);
		}
	}
	
	printk("\nTunel IPv6 Table as Below:\n");
	for(index = 0; index < UPDMEM_NUM; index++) 
	{
		if(shnkTbl[index].valid[PPE_UPDMEM_SEL_IPv6] == 0) {
			printk("IPv6[%d]:  SW valid:0\n", index);
		} else {
			printk("IPv6[%d]:  SW valid:1, timestamp:%ld, Tunel SIPv6:%X:%X:%X:%X, Tunel DIPv6:%X:%X:%X:%X\n",
					index, shnkTbl[index].timestamp[PPE_UPDMEM_SEL_IPv6], 
					shnkTbl[index].eg_ipv6[4], shnkTbl[index].eg_ipv6[5], shnkTbl[index].eg_ipv6[6], shnkTbl[index].eg_ipv6[7], 
					shnkTbl[index].eg_ipv6[0], shnkTbl[index].eg_ipv6[1], shnkTbl[index].eg_ipv6[2], shnkTbl[index].eg_ipv6[3]);
		}
	}
	
	printk("\nTunel IPv4 Table as Below:\n");
	for(index = 0; index < UPDMEM_NUM; index++) 
	{
		if(shnkTbl[index].valid[PPE_UPDMEM_SEL_IPv4] == 0) {
			printk("IPv4[%d]:  SW valid:0\n", index);
		} else {
			printk("IPv4[%d]:  SW valid:1, timestamp:%ld, Tunel SIPv4:%X, Tunel DIPv4:%X\n",
					index, shnkTbl[index].timestamp[PPE_UPDMEM_SEL_IPv4], shnkTbl[index].eg_ipv4[1], shnkTbl[index].eg_ipv4[0]);
		}
	}
	spin_unlock_bh(&shnk_tbl_lock);

	return 0;
}

int airoha_set_ppe_mac(struct airoha_foe_entry *foe_entry, struct net_device *dev, char* src_mac, char*dst_mac, u16 pppid)
{
	/* CID:900929 */
	struct airoha_foe_mac_info_common *l2 = NULL;
	int type = 0, index = 0;
	struct hwnat_shrink_field shrinkField = {0};
	type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1);
	
	switch (type) {
		case PPE_PKT_TYPE_IPV4_ROUTE:
		case PPE_PKT_TYPE_IPV4_HNAPT:
			l2 = &foe_entry->ipv4.l2.common;			
			break;
		case PPE_PKT_TYPE_BRIDGE:
			l2 = &foe_entry->bridge32.l2;
			break;
		case PPE_PKT_TYPE_IPV6_ROUTE_3T:
		case PPE_PKT_TYPE_IPV6_ROUTE_5T:
		case PPE_PKT_TYPE_IPV6_6RD:
			l2 = &foe_entry->ipv6.l2;
			break;		
		case PPE_PKT_TYPE_IPV4_DSLITE:
			l2 = &foe_entry->dslite.l2.common;
			break;
			
		default:
			break;
	}
	if (NULL == l2)
	{
		printk("airoha_set_ppe_mac l2 is NULL.\n");
		return -1;
	}
	l2->dest_mac_hi = get_unaligned_be32(dst_mac);
	l2->dest_mac_lo = get_unaligned_be16(dst_mac + 4);
	if (type <= PPE_PKT_TYPE_IPV4_DSLITE) {
		struct airoha_foe_mac_info *mac_info;
		mac_info = (struct airoha_foe_mac_info *)l2;
		l2->src_mac_hi = get_unaligned_be32(src_mac);
		mac_info->src_mac_lo = get_unaligned_be16(src_mac + 4);
		if(pppid)
			mac_info->pppoe_id = pppid;
	} else {
		if((dev != NULL) && (airoha_is_bridge_packet(dev,src_mac) == true)) {
			set_ppe_entry_smac_index(foe_entry, PPE_PKT_TYPE_IPV6_ROUTE_5T, 0x10);
		} else {
			memcpy(shrinkField.smac, src_mac, ETH_ALEN);

			index = find_and_update_shrink_table(PPE_UPDMEM_SEL_SMAC, &shrinkField);
			if(index != -1) {
				set_ppe_entry_smac_index(foe_entry, PPE_PKT_TYPE_IPV6_ROUTE_5T, index);
			} else {
				printk("smac: find and update shrink table failed!\n");
			}
		}
		if(pppid)
			l2->src_mac_hi |=  FIELD_PREP(AIROHA_FOE_MAC_PPPOE_ID, pppid);
		
	}	
	AIROHA_LOG(AIROHA_DEBUG_LEVEL_WARN, "%s:%d  type:%d / smac_id:%d\n",
	__func__,__LINE__, type,index);
	return 0;
}

inline static int airoha_ppe_is_vlan_proto(u16 etype)
{
	return (etype == htons(0x8100) || etype == htons(0x88a8)
		|| etype == htons(0x9100) || etype == htons(0x884c));
}

int airoha_ppe_foe_get_vlan_info(struct sk_buff *skb, u16 *vn, u16 *vid1, u16 *vid2)
{
    unsigned int foe_entry_idx = FOE_ENTRY_NUM(skb);
	int vlan_count = 0;
	unsigned char *ptr = skb->data + ETH_ALEN * 2;
	u16 tci = 0;
	
	*vn = 0;
	*vid1 = 0;
	*vid2 = 0;

	if(foe_entry_idx >= glb_eth->soc->ppe_sram_etry_num){
		return 0;
	}

	while (vlan_count < MAX_VLAN_DEPTH) 
	{
		if (ptr + VLAN_HLEN > skb->data + skb_headlen(skb)) {
			break;
		}

        u16 etype = *(u16 *)ptr;
		if (airoha_ppe_is_vlan_proto(etype)) 
		{
			vlan_count++;
			tci = ntohs(*(u16 *)(ptr + sizeof(u16)));

			if (vlan_count == 1) {
				*vid1 = tci;
			} else if (vlan_count == 2) {
				*vid2 = tci;
			}
			ptr += VLAN_HLEN;
		} else {
			break;
		}
	}

	AIROHA_LOG(AIROHA_DEBUG_LEVEL_WARN, "%s %d foe_entry_idx: %u, vlan_count: %d, foe_ext[foe_entry_idx].vlan_count: %d,\n", __func__, __LINE__,
	           foe_entry_idx, vlan_count, foe_ext[foe_entry_idx].vlan_count);

	if (vlan_count >= MAX_VLAN_DEPTH || foe_ext[foe_entry_idx].vlan_count >= MAX_VLAN_DEPTH) {
		return -EINVAL;
	}

	*vn = vlan_count;
	return 0;
}

void ppe_set_vlan_info(struct airoha_foe_entry *hwe, struct sk_buff *skb)
{
	u16 vn = 0, vid1 = 0, vid2 = 0;	
	u32 ib1;
	
	if(FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, hwe->ib1) == AIROHA_FOE_STATE_BIND){
		return;
	}
	
	airoha_ppe_foe_get_vlan_info(skb, &vn, &vid1, &vid2);

	ib1 = hwe->ib1;
	ib1 &= ~(AIROHA_FOE_IB1_BIND_VLAN_LAYER | AIROHA_FOE_IB1_BIND_VPM);
	ib1 |= FIELD_PREP(AIROHA_FOE_IB1_BIND_VLAN_LAYER, vn) | 
					FIELD_PREP(AIROHA_FOE_IB1_BIND_VPM, !!vn);
	hwe->ib1 = ib1;

	if (IS_IPV4_GRP(hwe)) {
		hwe->ipv4.l2.common.vlan1 = vid1;
		hwe->ipv4.l2.common.vlan2 = vid2;
	}
	else if(IS_IPV6_GRP(hwe)){
		hwe->ipv6.l2.vlan1 = vid1;
		hwe->ipv6.l2.vlan2 = vid2;
	}
	else if(IS_L2_RRIDGE(hwe)){
		hwe->bridge.l2.common.vlan1 = vid1;
		hwe->bridge.l2.common.vlan2 = vid2;
	}

	return;
	
}

void airoha_ppe_foe_get_vlan_vpm(struct sk_buff *skb, u16 *vpm)
{
	u16 tmp = *(u16 *)(skb->data+12);

	if(airoha_ppe_is_vlan_proto(tmp)){
		if(tmp == htons(0x88a8))
			*vpm = 2;
		else
			*vpm = 1;
	}
	else
	{
		*vpm = 0;
	}
}

static int airoha_ppe_is_wifi_dev(struct net_device *dev)
{
	struct net_device *real_dev = dev;

	if (!real_dev)
		return 0;

	if (is_vlan_dev(real_dev))
		real_dev = vlan_dev_real_dev(real_dev);
	if (!real_dev)
		return 0;

#if IS_ENABLED(CONFIG_CFG80211_HEADERS)
	if (real_dev->ieee80211_ptr)
		return 1;
#endif
#ifdef CONFIG_WIRELESS_EXT
	if (real_dev->wireless_handlers)
		return 1;
#endif

	return 0;
}

static void arht_set_ppe_lanif(struct sk_buff *skb,u32 hash)
{
	unsigned int foe_entry_idx = FOE_ENTRY_NUM(skb);

	if (foe_entry_idx >= glb_eth->soc->ppe_sram_etry_num)
		return;
	if (!skb->skb_iif)
		return;

	foe_ext[foe_entry_idx].lan_ifindex = skb->skb_iif;
}

static inline void set_ppe_foe_entry_meter_grp2(u16 *meter_ptr, u32 meter1_idx)
{
	*meter_ptr &= ~AIROHA_FOE_METER_GRP2;
	*meter_ptr |= FIELD_PREP(AIROHA_FOE_METER_GRP2, meter1_idx);
}

static bool arht_ppe_l4s_apply(struct airoha_foe_entry *hwe, int type, u8 dscp)
{
	u32 *data, *ib2, *meter;
	u8 ecn, nbq;
	u32 val, pse_port;

	if (!AIROHA_L4S_FLAG)
		return false;

	if (type == PPE_PKT_TYPE_BRIDGE) {
		data = &hwe->bridge.data;
		ib2 = &hwe->bridge.ib2;
		meter = (u32 *)&hwe->bridge.l2.meter;
	} else if (type >= PPE_PKT_TYPE_IPV6_ROUTE_3T) {
		data = &hwe->ipv6.data;
		ib2 = &hwe->ipv6.ib2;
		meter = (u32 *)&hwe->ipv6.meter;
	} else {
		data = &hwe->ipv4.data;
		ib2 = &hwe->ipv4.ib2;
		meter = (u32 *)&hwe->ipv4.l2.meter;
	}

	AIROHA_L4S_LOG(AIROHA_L4S_DEBUG, "L4S original ib2: 0x%x\n", *ib2);
	ecn = dscp & 0x3;
	AIROHA_L4S_LOG(AIROHA_L4S_DEBUG, "L4S check ecn: %u\n", ecn);

	if (ecn != 0x1)
		return false;

	/* Backup channel+qid into ACTDP */
	val = FIELD_GET(AIROHA_FOE_CHANNEL | AIROHA_FOE_QID, *data);
	*data = (*data & ~AIROHA_FOE_ACTDP) |
		FIELD_PREP(AIROHA_FOE_ACTDP, val);

	/* Backup original ib2 control bits (NBQ, PSE_PORT, PSE_QOS, FAST_PATH)
	 * into meter's TUNNEL_MTU field
	 */
	val = *ib2 & (AIROHA_FOE_IB2_NBQ | AIROHA_FOE_IB2_PSE_PORT |
		      AIROHA_FOE_IB2_PSE_QOS | AIROHA_FOE_IB2_FAST_PATH);
	*meter |= FIELD_PREP(AIROHA_FOE_TUNNEL_MTU, val);

	AIROHA_L4S_LOG(AIROHA_L4S_DEBUG,
		       "L4S backup: channel=%lu, qid=%lu, nbq=%lu, pse_port=%lu, pse_qos=%lu, fast_path=%lu\n",
		       FIELD_GET(AIROHA_FOE_CHANNEL, *data),
		       FIELD_GET(AIROHA_FOE_QID, *data),
		       FIELD_GET(AIROHA_FOE_IB2_NBQ, *ib2),
		       FIELD_GET(AIROHA_FOE_IB2_PSE_PORT, *ib2),
		       FIELD_GET(AIROHA_FOE_IB2_PSE_QOS, *ib2),
		       FIELD_GET(AIROHA_FOE_IB2_FAST_PATH, *ib2));

	/* Redirect to PSE Port 6 (NPU), set NBQ based on original PSE port */
	pse_port = FIELD_GET(AIROHA_FOE_IB2_PSE_PORT, *ib2);
	nbq = (pse_port == 1) ? 2 : 1;

	*ib2 &= ~(AIROHA_FOE_IB2_NBQ | AIROHA_FOE_IB2_PSE_PORT |
		   AIROHA_FOE_IB2_PSE_QOS);
	*ib2 |= FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, 6) |
		FIELD_PREP(AIROHA_FOE_IB2_NBQ, nbq);

	AIROHA_L4S_LOG(AIROHA_L4S_DEBUG, "L4S modified ib2: 0x%x\n", *ib2);
	return true;
}

static void airoha_ppe_general_bind(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe,
	struct sk_buff *skb, struct port_info *pinfo, u8 fport)
{
	u16 vn = 0, vid1 = 0, vid2 = 0, vpm = 0;	
	int dscp = 0, type = 0, fast = 0, fqos = AIROHA_FOE_IB2_PSE_QOS;
	u32 data, ib1;
	u32 meter0_idx = 0x7F, meter1_idx = 0x3F;
	struct airoha_foe_mac_info_common *l2 = NULL;
	u32 ts = airoha_ppe_get_timestamp(ppe);	
	u32 hash = FOE_ENTRY_NUM(skb);
	int rx_wlan = 0;
	struct net_device *ori_dev = NULL;

	if(FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, hwe->ib1) == AIROHA_FOE_STATE_BIND)
		return;
	if ( !is_Valid_Foe_Entry(skb) )
	{
		return;
	}

	if(arht_hook_get_crsn(skb) != PPE_CPU_REASON_HIT_UNBIND_RATE_REACHED)
	{
		return;
	}
	
	if(airoha_ppe_foe_get_vlan_info(skb, &vn, &vid1, &vid2)){
	    return;
	}
	airoha_ppe_foe_get_vlan_vpm(skb, &vpm);

	if(packet_hash_collision_check(skb, hwe) < 0)
		return;

	type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, hwe->ib1);
	airoha_set_default_acnt_meter_idx(hwe, type);
	dscp = get_dscp_from_skb(skb, type);
			
	AIROHA_LOG(AIROHA_DEBUG_LEVEL_ERR, "Packet type: %d, vn: %u, vid1: %u, vid2: %u\n",type,vn, vid1,vid2);

	meter0_idx = get_meter_idx_by_gemport(skb, pinfo, fport);
	meter1_idx = get_meter_idx_by_lan(skb, pinfo, fport);
	AIROHA_LOG(AIROHA_DEBUG_LEVEL_ERR, "%s %d meter0_idx = %u, meter1_idx = %u\n", __func__, __LINE__, meter0_idx, meter1_idx);
	if (FE_PSE_PORT_CDM4 == fport)
		fqos = 0;

	if (skb->skb_iif){
		ori_dev = dev_get_by_index(&init_net, skb->skb_iif);
		if (ori_dev && airoha_ppe_is_wifi_dev(ori_dev)) {
			rx_wlan = 1;
		}

		if (ori_dev){
			dev_put(ori_dev);
		}
	}

	data = FIELD_PREP(AIROHA_FOE_ACTDP, pinfo->udf) |
			FIELD_PREP(AIROHA_FOE_CHANNEL, pinfo->channel) |
   			FIELD_PREP(AIROHA_FOE_QID, 
				((AIROHA_NUM_QOS_QUEUES - 1) - ((pinfo->txq) % AIROHA_NUM_QOS_QUEUES))) |
   			FIELD_PREP(AIROHA_FOE_SHAPER_ID, meter0_idx);

	ib1 = hwe->ib1;
	ib1 &= ~(AIROHA_FOE_IB1_BIND_VLAN_LAYER | AIROHA_FOE_IB1_BIND_VPM |
				AIROHA_FOE_IB1_BIND_PPPOE | AIROHA_FOE_IB1_BIND_TIMESTAMP |
				AIROHA_FOE_IB1_BIND_STATE);
	ib1 |= FIELD_PREP(AIROHA_FOE_IB1_BIND_VLAN_LAYER, vn) | 
					FIELD_PREP(AIROHA_FOE_IB1_BIND_VPM, vpm) |
					FIELD_PREP(AIROHA_FOE_IB1_BIND_TIMESTAMP, ts) | 
					FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND);
	
	switch (fport){
		case FE_PSE_PORT_GDM1:
			if (ppe->eth->qdma_init.lan_fastpath == 1 || (airoha_is_7581(ppe->eth) && rx_wlan)){
				fast = AIROHA_FOE_IB2_FAST_PATH;
			}
			break;

		case FE_PSE_PORT_GDM2:
			if (ppe->eth->qdma_init.wan_fastpath == 1 || pinfo->fast == 1){
				fast = AIROHA_FOE_IB2_FAST_PATH;
			}
			break;

		case FE_PSE_PORT_GDM3:
		case FE_PSE_PORT_GDM4:
			if (ppe->eth->qdma_init.xsi_ether_fastpath == 1 || pinfo->fast == 1){
				fast = AIROHA_FOE_IB2_FAST_PATH;
			}
			break;

		default:
			break;
	}
	
	switch (type) {
		case PPE_PKT_TYPE_IPV4_HNAPT:
			hwe->ipv4.new_tuple.src_port = hwe->ipv4.orig_tuple.src_port;
			hwe->ipv4.new_tuple.dest_port = hwe->ipv4.orig_tuple.dest_port;
			fallthrough;
		case PPE_PKT_TYPE_IPV4_ROUTE:
			hwe->ipv4.data = data;
			l2 = &hwe->ipv4.l2.common;
			hwe->ipv4.ib2 = FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x7ff);
			hwe->ipv4.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, pinfo->nbq);	
			hwe->ipv4.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_DSCP, dscp);	
			hwe->ipv4.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, fport) |
			       fqos | fast;
			hwe->ipv4.new_tuple.src_ip = hwe->ipv4.orig_tuple.src_ip;
			hwe->ipv4.new_tuple.dest_ip = hwe->ipv4.orig_tuple.dest_ip;
			set_ppe_foe_entry_meter_grp2(&hwe->ipv4.l2.meter, meter1_idx);
			break;
		
		case PPE_PKT_TYPE_BRIDGE:
			hwe->bridge32.data = data;
			l2 = &hwe->bridge32.l2;
			hwe->bridge32.ib2 = FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x7ff);
			hwe->bridge32.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, pinfo->nbq);	
			hwe->bridge32.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, fport) |
		       fqos | fast;		
			set_ppe_foe_entry_meter_grp2(&hwe->bridge32.meter, meter1_idx);
			break;
		
		case PPE_PKT_TYPE_IPV6_ROUTE_3T:
		case PPE_PKT_TYPE_IPV6_ROUTE_5T:
			hwe->ipv6.data = data;
			l2 = &hwe->ipv6.l2;
			hwe->ipv6.ib2 = FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x7ff);
			hwe->ipv6.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, pinfo->nbq);	
			hwe->ipv6.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_DSCP, dscp);
			hwe->ipv6.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, fport) |
		       fqos | fast;				
			set_ppe_foe_entry_meter_grp2(&hwe->ipv6.meter, meter1_idx);
			break;

		default:
			break;
	}

	arht_ppe_l4s_apply(hwe, type, dscp);

	if (NULL != l2)
	{
		l2->etype = pinfo->stag;
		l2->vlan1 = vid1;
		l2->vlan2 = vid2;
	}
	airoha_set_ppe_mac(hwe,skb->dev,skb->data+6,skb->data,0);

	arht_set_ppe_lanif(skb,hash);

	hwe->ib1 = ib1;

	/* For L2 Meter */
	if ( ra_sw_nat_update_acnt_info_hook ) {
		ra_sw_nat_update_acnt_info_hook(hwe, skb, pinfo, fport);
	}

	if (hash < ppe->eth->soc->ppe_sram_etry_num) {
		airoha_ppe_foe_commit_entry_ptr(ppe, hwe, hash,rx_wlan);
	}
	
	return;
}

static void airoha_ppe_pon_sfu_bind(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, 
	struct sk_buff *skb, struct port_info *pinfo, u8 fport)
{
	if (!airoha_is_pon_point_to_point_mode(skb)) {
		//if not point to ponit mode, need to check mac table in kernel
	    if (!airoha_check_flood_packet(skb, 0, pinfo->stag)) {
	        return;
	    }
	}

	return airoha_ppe_general_bind(ppe, hwe, skb, pinfo, fport);
}

static int arht_general_offload_bind_ring(unsigned short type, u32 foe_entry_idx)
{
	int ring = 1;
	
	switch (type){
		case PPE_UDF_LOCAL_IN:
		case PPE_UDF_LOCAL_IN_NS:
			ring = airoha_get_free_lro_ring(foe_entry_idx);
			break;

		default:
			break;
	}

	return ring;
}

/******************************************************************************
 Descriptor: This is for hwnat binding, in case of no NAT/VLAN/pppoe opteration.
 Input Args:	
 Ret Value: 
******************************************************************************/
int arht_general_offload_bind(struct sk_buff * skb, unsigned short type)
{
	int ret = 0, ptype = 0;
	u32 foe_entry_idx= 0;
	struct airoha_foe_entry *hwe;
	u32 data;
	int ring;

	foe_entry_idx = FOE_ENTRY_NUM(skb);
	if ( foe_entry_idx >= glb_eth->soc->ppe_sram_etry_num || !skb->l4_hash || skb->sw_hash != false )
		return ret;
	
	spin_lock_bh(&ppe_lock);
	hwe = airoha_ppe_foe_get_entry_locked(glb_eth->ppe, foe_entry_idx);
	if (!hwe)
		goto unlock;

	if(FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, hwe->ib1) == AIROHA_FOE_STATE_BIND)
		goto unlock;

	ptype = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, hwe->ib1);
	data = FIELD_PREP(AIROHA_FOE_SHAPER_ID, 0x7F);

	ring = arht_general_offload_bind_ring(type, foe_entry_idx);
	switch (ptype) {
		case PPE_PKT_TYPE_IPV4_HNAPT:
			hwe->ipv4.new_tuple.src_port = hwe->ipv4.orig_tuple.src_port;
			hwe->ipv4.new_tuple.dest_port = hwe->ipv4.orig_tuple.dest_port;
			hwe->ipv4.data = data;
			hwe->ipv4.ib2 = 0;
			if(ring <= LRO_RING_END){
			    hwe->ipv4.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, ring);	
			    hwe->ipv4.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_CDM1);
			}else{
			    hwe->ipv4.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, ring - LRO_RING_NUM);
			    hwe->ipv4.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_CDM2);
			}
			hwe->ipv4.new_tuple.src_ip = hwe->ipv4.orig_tuple.src_ip;
			hwe->ipv4.new_tuple.dest_ip = hwe->ipv4.orig_tuple.dest_ip;
			hwe->ipv4.l2.common.etype = type;
			break;
		
		case PPE_PKT_TYPE_IPV6_ROUTE_5T:
			hwe->ipv6.data = data;
			hwe->ipv6.ib2 = 0;	
			if(ring <= LRO_RING_END){
			    hwe->ipv6.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, ring);	
			    hwe->ipv6.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_CDM1);
			}else{
			    hwe->ipv6.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, ring - LRO_RING_NUM);	
			    hwe->ipv6.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_CDM2);
			}
			hwe->ipv6.l2.etype = type;
			break;

		default:
			break;
	}

	if(skb_mac_header_was_set(skb)){
		unsigned char *mac_h = skb_mac_header(skb);
		airoha_set_ppe_mac(hwe,skb->dev,mac_h+6,mac_h,0);
	}

	airoha_ppe_foe_commit_entry_ptr(glb_eth->ppe, hwe, foe_entry_idx, 0);

unlock:	
	spin_unlock_bh(&ppe_lock);

	return ret;
}
EXPORT_SYMBOL(arht_general_offload_bind);

inline static int airoha_is_local_out(struct sk_buff *skb)
{
	return (skb->inner_protocol == PPE_MAGIC_LOCAL_OUT || skb->inner_protocol == PPE_MAGIC_DYNAMIC_IFC);
}

static unsigned int airoha_get_magic_from_fport(u8 fport)
{
	int magic = -1;
	switch (fport)
	{
		case FE_PSE_PORT_GDM3:
			magic = FOE_MAGIC_XSI;
			break;
		case FE_PSE_PORT_GDM4:
			magic = FOE_MAGIC_XSI_GDM4;;
			break;
		case FE_PSE_PORT_GDM1:
			magic = FOE_MAGIC_GE;
			break;
		default:
			break;
	}
	return magic;
}

static int bit_to_num(unsigned int mask)
{
	int num = 0;
	while((mask & 1) == 0 && mask != 0)
	{
		mask >>= 1;
		num++;
	}
	return num;
}

int airoha_is_bridge_mode(struct sk_buff * skb)
{
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	//const struct nf_conntrack_tuple *orig_tuple = NULL;
	ct = nf_ct_get(skb, &ctinfo);
	if(ct)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

static int arht_ppe_soe_offload_get_valid(struct sk_buff* skb)
{
	unsigned int foe_index = FOE_ENTRY_NUM(skb);

	if(arht_soe_offload_get_valid_hook)
	{
		if(foe_index < glb_eth->soc->ppe_sram_etry_num)
		{
			return arht_soe_offload_get_valid_hook(foe_index);
		}
	}
	return 0;
}

int airoha_ppe_tx_handler
(struct sk_buff *skb, struct port_info *pinfo, u8 fport)
{
	u32 hash = FOE_ENTRY_NUM(skb);
	struct airoha_foe_entry *hwe;
	unsigned int temp_magic = 0;
	int pkt_type = 0;
	unsigned short udf;
	
	if(pinfo == NULL)
	{
		AIROHA_LOG(AIROHA_DEBUG_LEVEL_ERR, "pinfo == NULL!!!\n");
		return 0;
	}

	if (pinfo->magic == PPE_MAGIC_LOCAL_IN || pinfo->magic == PPE_MAGIC_LOCAL_IN_NS)
	{
		if ( hash >= glb_eth->soc->ppe_sram_etry_num || !skb->l4_hash || skb->sw_hash != false )
			return 0;

		if (((skb->hash & AIROHA_PPE_CPU_MASK) >> AIROHA_PPE_CPU_REASON_BIT) != PPE_CPU_REASON_HIT_UNBIND_RATE_REACHED)
			return 0;

		if(pinfo->magic == PPE_MAGIC_LOCAL_IN){
			udf = PPE_UDF_LOCAL_IN;
		}else {
			udf = PPE_UDF_LOCAL_IN_NS;
		}

		arht_general_offload_bind(skb, udf);

		return 1;
	}

	if ( !is_Valid_Foe_Entry(skb) )
	{
		return 0;
	}
	if(arht_hook_get_crsn(skb) != PPE_CPU_REASON_HIT_UNBIND_RATE_REACHED)
	{
		return 0;
	}

	if(arht_multicast_handler_for_sfu(skb))
	{
		return 1;
	}

	if(fport == 2)
	{
		if(airoha_tunnel_hook_tx){
			pinfo->udf = fport;
			if(airoha_tunnel_hook_tx(skb,glb_eth->ppe,pinfo) == 1)
				return 1;
		}

	}
	else
	{
		if(airoha_tunnel_hook_tx && skb->mark == FOE_MAGIC_GRE_HWDOWN_2){
			// pinfo.stag = tag;
			pinfo->udf = fport;
			pinfo->magic = FOE_MAGIC_GRE_HWDOWN_2;
			if(airoha_tunnel_hook_tx(skb,glb_eth->ppe,pinfo) == 1)
				return 1;
		}
		else if(airoha_tunnel_hook_tx && arht_ppe_soe_offload_get_valid(skb))
		{
			//pinfo.stag = tag;
			//pinfo.channel = channel;
			temp_magic = airoha_get_magic_from_fport(fport);
			/* struct port_info { ..., unsigned long int magic:16;} */
			if (temp_magic > 0xffff)
			{
				printk("airoha_get_magic_from_fport num is too largr.\n");
				temp_magic = 0xffff;
			}
			pinfo->magic = temp_magic;
			//only support switch & eth_serdes
			pinfo->nbq = bit_to_num(pinfo->stag);

			if(airoha_tunnel_hook_tx(skb,glb_eth->ppe,pinfo) == 1)
				return 1;
		}

		hwe = airoha_ppe_foe_get_entry(glb_eth->ppe, hash);
		if (!hwe){
			return 0;
		}
		
		pkt_type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, hwe->ib1);
		if(pkt_type == PPE_PKT_TYPE_IPV4_DSLITE || pkt_type == PPE_PKT_TYPE_IPV6_6RD)
		{
			if(airoha_tunnel_hook_tx)
			{
				pinfo->udf = fport;
				if(airoha_tunnel_hook_tx(skb,glb_eth->ppe,pinfo) == 1){
					return 1;
				}
			}
		}
	}

	spin_lock_bh(&ppe_lock);
	hwe = airoha_ppe_foe_get_entry_locked(glb_eth->ppe, hash);
	if (!hwe)
	{
		spin_unlock_bh(&ppe_lock);
		return 0;
	}

	if (ppe_is_multicast_entry(hwe)) {
		spin_unlock_bh(&ppe_lock);
		return 1;
	}

	if(airoha_is_local_out(skb))
	{
		pinfo->fast = 1;
		airoha_ppe_general_bind(glb_eth->ppe, hwe, skb, pinfo, fport);
		spin_unlock_bh(&ppe_lock);
		return 1;
	}
		
	if(airoha_is_pon_sfu_mode())
	{
		airoha_ppe_pon_sfu_bind(glb_eth->ppe, hwe, skb, pinfo, fport);
		spin_unlock_bh(&ppe_lock);
		return 1;
	}

	//not flood packet, for bridge wan mode
	if (airoha_check_flood_packet(skb, 0, pinfo->stag)) {
        airoha_ppe_general_bind(glb_eth->ppe, hwe, skb, pinfo, fport);
		spin_unlock_bh(&ppe_lock);
		return 1;
    }

	spin_unlock_bh(&ppe_lock);
	return 0;
}
EXPORT_SYMBOL(airoha_ppe_tx_handler);

static int InitShrinkTable(void)
{
    int index = 0;
    for (index = 0; index < UPDMEM_NUM; index++) {
        memset(&shnkTbl[index], 0, sizeof(shnkTbl[index]));
	}

	return 0;
}

static void airoha_ppe_parse_skb_vlan_count(struct sk_buff *skb)
{
	unsigned int foe_entry_idx = FOE_ENTRY_NUM(skb);
	struct ethhdr *eth_hdr = NULL;
    struct vlan_hdr *vh = NULL;
    unsigned short proto = 0;
    int offset = 0;
    unsigned char vlan_count = 0;

	if(foe_entry_idx >= glb_eth->soc->ppe_sram_etry_num){
		return;
	}
	
    if(skb->len < sizeof(struct ethhdr)){
    	foe_ext[foe_entry_idx].vlan_count = vlan_count;
    	return;
    }

    skb_push(skb, ETH_HLEN);
	eth_hdr = (struct ethhdr *)skb->data;
    proto = eth_hdr->h_proto;
    offset += sizeof(struct ethhdr);
    
    while(vlan_count < MAX_VLAN_DEPTH && airoha_ppe_is_vlan_proto(proto))
    {
        if(skb->len < offset + sizeof(struct vlan_hdr)){
            break;
        }

        vlan_count += 1;
        vh = (struct vlan_hdr *)(skb->data + offset);
        proto = vh->h_vlan_encapsulated_proto;
        offset += sizeof(struct vlan_hdr);
    }
    skb_pull_inline(skb, ETH_HLEN);

	foe_ext[foe_entry_idx].vlan_count = vlan_count;
	AIROHA_LOG(AIROHA_DEBUG_LEVEL_WARN, "%s %d vlan_count = %d\n", __func__, __LINE__, vlan_count);

    return;
}

int airoha_ppe_rxinfo_handler(struct sk_buff *skb, int magic, char *data, int data_length)
{
	if((magic == FOE_MAGIC_EPON) || (magic == FOE_MAGIC_GPON) || (magic == FOE_MAGIC_AE_WAN) || 
	   (magic == FOE_MAGIC_ATM) || (magic == FOE_MAGIC_PTM))
	{
		airoha_ppe_parse_skb_vlan_count(skb);
	}

    return 0;
}

void arht_ppe_general_init(struct airoha_ppe *ppe)
{
	//7581 & 7583 use vmalloc
	foe_ext = (struct FoeEntryExt*)vmalloc((ppe->eth->soc->ppe_sram_etry_num + PPE_DRAM_NUM_ENTRIES) * sizeof(struct FoeEntryExt));
	if (foe_ext == NULL){
		printk("HWNAT: alloc Lan & Wan Info Fail! \n");
		return ;
	}
	memset(foe_ext, 0, (ppe->eth->soc->ppe_sram_etry_num + PPE_DRAM_NUM_ENTRIES) * sizeof(struct FoeEntryExt));
	
	InitShrinkTable();

	rcu_assign_pointer(set_entry_reason_hook, set_entry_cpu_reason);
	rcu_assign_pointer(arht_hook_get_crsn, get_entry_cpu_reason);
	rcu_assign_pointer(ra_sw_nat_hook_rxinfo, airoha_ppe_rxinfo_handler);

	return;
}
EXPORT_SYMBOL(arht_ppe_general_init);

void arht_ppe_general_exit(void)
{
	if (foe_ext != NULL){
		//7581 & 7583 uses vfree
		vfree(foe_ext);
	}
	foe_ext = NULL;
	
	rcu_assign_pointer(set_entry_reason_hook, NULL);
	rcu_assign_pointer(arht_hook_get_crsn, NULL);
	rcu_assign_pointer(ra_sw_nat_hook_rxinfo, NULL);

	return;
}
EXPORT_SYMBOL(arht_ppe_general_exit);

static int airoha_ppe_drop_packet_handler(struct sk_buff *skb)
{
	u32 hash = FOE_ENTRY_NUM(skb);
	struct airoha_foe_entry *hwe;
	struct airoha_ppe *ppe;
	u32 val;
	int type, ret = 0;
	struct airoha_foe_entry local_hwe;

	if(glb_eth == NULL)
		return 0;
	ppe = glb_eth->ppe;

	if(!airoha_is_pon_sfu_mode()){
		return 0;
	}

	if ( !is_Valid_Foe_Entry(skb) ) {
		return 0;
	}

	spin_lock_bh(&ppe_lock);
	hwe = airoha_ppe_foe_get_entry_locked(ppe, hash);

	if (!hwe)
	{
		spin_unlock_bh(&ppe_lock);
		return 0;
	}

	if(ppe_is_multicast_entry(hwe))
	{
		if(arht_multicast_list_add_hook) {
			memcpy(&local_hwe, hwe, sizeof(struct airoha_foe_entry));
			spin_unlock_bh(&ppe_lock);
			arht_multicast_list_add_hook(&local_hwe, skb);
			spin_lock_bh(&ppe_lock);
			
			hwe = airoha_ppe_foe_get_entry_locked(ppe, hash);
			if (!hwe) {
				spin_unlock_bh(&ppe_lock);
				return 0;
			}
		}
		//transparent mode is for single port, no need learn drop
		if(packet_is_transparent_mode) {
			spin_unlock_bh(&ppe_lock);
			return 0;
		}
	}

	hwe->ib1 &= ~AIROHA_FOE_IB1_BIND_STATE;
	hwe->ib1 |= FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND);


	val = FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x1f) |
		  FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_DROP);
	
	type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, hwe->ib1);

	switch (type) {
		case PPE_PKT_TYPE_IPV4_ROUTE:
		case PPE_PKT_TYPE_IPV4_HNAPT:
			hwe->ipv4.ib2 = val;
			break;
		
		case PPE_PKT_TYPE_BRIDGE:
			hwe->bridge.ib2 = val;
			break;
		
		case PPE_PKT_TYPE_IPV6_ROUTE_3T:
		case PPE_PKT_TYPE_IPV6_ROUTE_5T:
		case PPE_PKT_TYPE_IPV6_6RD:
			hwe->ipv6.ib2 = val;
			break;
			
		case PPE_PKT_TYPE_IPV4_DSLITE:
			hwe->dslite.ib2 = val;
			break;
			
		default:
			break;
	}
	ret = 1;

	airoha_ppe_foe_commit_entry_ptr(ppe, hwe, hash,1);
	spin_unlock_bh(&ppe_lock);

	return ret;

}

static void delete_conntrack_by_tuple(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, u8 l4proto)
{
	struct nf_conntrack_tuple tuple;
	struct nf_conn *ct;
	struct nf_conntrack_tuple_hash *thash;
	
	memset(&tuple, 0, sizeof(tuple));
	tuple.src.l3num = AF_INET;
	tuple.src.u3.ip = src_ip;
	tuple.dst.u3.ip = dst_ip;
	tuple.src.u.all = src_port;
	tuple.dst.u.all = dst_port;
	tuple.dst.protonum = l4proto;

	thash = nf_conntrack_find_get(&init_net, &nf_ct_zone_dflt, &tuple);
	if (thash) {
		ct = nf_ct_tuplehash_to_ctrack(thash);
		nf_ct_delete(ct, 0, 0);
		nf_ct_put(ct);
	}
}

static void delete_conntrack_by_tuple6(const u32 *src_ip, const u32 *dst_ip,
                                       __be16 src_port, __be16 dst_port, u8 l4proto)
{
    struct nf_conntrack_tuple tuple;
    struct nf_conntrack_tuple_hash *thash;
    struct nf_conn *ct;

    memset(&tuple, 0, sizeof(tuple));
    tuple.src.l3num = AF_INET6;

    tuple.src.u3.ip6[0] = htonl(src_ip[0]);
    tuple.src.u3.ip6[1] = htonl(src_ip[1]);
    tuple.src.u3.ip6[2] = htonl(src_ip[2]);
    tuple.src.u3.ip6[3] = htonl(src_ip[3]);

    tuple.dst.u3.ip6[0] = htonl(dst_ip[0]);
    tuple.dst.u3.ip6[1] = htonl(dst_ip[1]);
    tuple.dst.u3.ip6[2] = htonl(dst_ip[2]);
    tuple.dst.u3.ip6[3] = htonl(dst_ip[3]);

    tuple.src.u.all = src_port;
    tuple.dst.u.all = dst_port;
    tuple.dst.protonum = l4proto;

    thash = nf_conntrack_find_get(&init_net, &nf_ct_zone_dflt, &tuple);
    if (thash) {
        ct = nf_ct_tuplehash_to_ctrack(thash);
        nf_ct_delete(ct, 0, 0);
        nf_ct_put(ct);
    }
}

static void airoha_ppe_delete_conntrack(struct airoha_foe_entry *hwe)
{
	int type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, hwe->ib1);
	u8 is_udp = FIELD_GET(AIROHA_FOE_IB1_BIND_UDP, hwe->ib1);
	u8 l4proto = is_udp ? IPPROTO_UDP : IPPROTO_TCP;

	if (type == PPE_PKT_TYPE_IPV4_HNAPT || type == PPE_PKT_TYPE_IPV4_ROUTE) {
		delete_conntrack_by_tuple(htonl(hwe->ipv4.orig_tuple.src_ip),
					  htonl(hwe->ipv4.orig_tuple.dest_ip),
					  htons(hwe->ipv4.orig_tuple.src_port),
					  htons(hwe->ipv4.orig_tuple.dest_port),
					  l4proto);
	} else if (type == PPE_PKT_TYPE_IPV6_ROUTE_5T) {
		delete_conntrack_by_tuple6(hwe->ipv6.src_ip,
					   hwe->ipv6.dest_ip,
					   htons(hwe->ipv6.src_port),
					   htons(hwe->ipv6.dest_port),
					   l4proto);
	}
}

int airoha_ppe_clean_entry_by_gemport(unsigned int gemport_id)
{
	struct airoha_foe_entry *foe_entry;
	u32 ppe_num_entries = airoha_ppe_get_total_num_entries(glb_eth->ppe);
	unsigned int idx = 0, ptype = 0, ib2 = 0;
	struct airoha_foe_mac_info_common *l2;
	int fpidx = 0;
	int delete_count = 0;

	for (idx = 0; idx < ppe_num_entries;idx++)
	{
        foe_entry = airoha_ppe_foe_get_entry(glb_eth->ppe, idx);

		if(foe_entry == NULL){
			continue;
		}

		if (FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, foe_entry->ib1) != AIROHA_FOE_STATE_BIND){
			continue;
		}

		ptype = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1);

		if (ptype >= PPE_PKT_TYPE_IPV6_ROUTE_3T) {
			ib2 = foe_entry->ipv6.ib2;
			l2 = &foe_entry->ipv6.l2;
		} else if(ptype == PPE_PKT_TYPE_BRIDGE){
			ib2 = foe_entry->bridge32.ib2;
			l2 = &foe_entry->bridge32.l2;
		} else if(ptype == PPE_PKT_TYPE_IPV4_DSLITE){
			ib2 = foe_entry->dslite.ib2;
			l2 = &foe_entry->dslite.l2.common;
		} else {
			ib2 = foe_entry->ipv4.ib2;
			l2 = &foe_entry->ipv4.l2.common;
		}

        fpidx = FIELD_GET(AIROHA_FOE_IB2_PSE_PORT, ib2);

		if (fpidx != FE_PSE_PORT_GDM2){
			continue;
		}

		if (l2->etype != gemport_id){
			continue;
		}

        AIROHA_LOG(AIROHA_DEBUG_LEVEL_WARN, "%s: gemport_id(%d): %u\n", __func__, idx, l2->etype);

		if (delete_count < PPE_MAX_CT_DELETE_PER_CLEAN) {
			airoha_ppe_delete_conntrack(foe_entry);
			delete_count++;
		}

        spin_lock_bh(&ppe_lock);
		airoha_ppe_delete_entry(glb_eth->ppe, foe_entry, idx);
	    spin_unlock_bh(&ppe_lock);
	}

	return 0;
}

static int airoha_ppe_clean_entry_by_channel(int channelIdx)   /* clean entry by tcont */
{
	struct airoha_foe_entry *foe_entry;
	u32 ppe_num_entries = airoha_ppe_get_total_num_entries(glb_eth->ppe);
	unsigned int idx = 0, ptype = 0, ib2 = 0, data = 0;
	int cur_channel = 0, fpidx = 0;
	int delete_count = 0;

	for (idx = 0; idx < ppe_num_entries;idx++)
	{
        foe_entry = airoha_ppe_foe_get_entry(glb_eth->ppe, idx);

		if(foe_entry == NULL){
			continue;
		}

		if (FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, foe_entry->ib1) != AIROHA_FOE_STATE_BIND){
			continue;
		}

		ptype = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1);

		if (ptype >= PPE_PKT_TYPE_IPV6_ROUTE_3T) {
			data = foe_entry->ipv6.data;
			ib2 = foe_entry->ipv6.ib2;
		} else if(ptype == PPE_PKT_TYPE_BRIDGE){
			data = foe_entry->bridge32.data;
			ib2 = foe_entry->bridge32.ib2;
		} else if(ptype == PPE_PKT_TYPE_IPV4_DSLITE){
			data = foe_entry->dslite.data;
			ib2 = foe_entry->dslite.ib2;
		} else {
			data = foe_entry->ipv4.data;
			ib2 = foe_entry->ipv4.ib2;
		}

        cur_channel = FIELD_GET(AIROHA_FOE_CHANNEL, data);
        fpidx = FIELD_GET(AIROHA_FOE_IB2_PSE_PORT, ib2);

		if (fpidx != FE_PSE_PORT_GDM2){
			continue;
		}

		if (cur_channel != channelIdx){
			continue;
		}

        AIROHA_LOG(AIROHA_DEBUG_LEVEL_WARN, "%s: channel(%d): %d \n", __func__, idx, cur_channel);

		if (delete_count < PPE_MAX_CT_DELETE_PER_CLEAN) {
			airoha_ppe_delete_conntrack(foe_entry);
			delete_count++;
		}

        spin_lock_bh(&ppe_lock);
		airoha_ppe_delete_entry(glb_eth->ppe, foe_entry, idx);
	    spin_unlock_bh(&ppe_lock);
	}

	return 0;
}

/* Clean downstream entries by fport and channel (called from workqueue) */
static int airoha_ppe_clean_entry_by_fport_and_channel(int target_fport, int channelIdx)
{
	struct airoha_foe_entry *foe_entry;
	u32 ppe_num_entries;
	unsigned int idx = 0, ptype = 0, ib2 = 0, data = 0;
	int cur_channel = 0, fpidx = 0;

	if (!glb_eth || !glb_eth->ppe)
		return -EINVAL;

	/* Validate channel index range */
	if (channelIdx < 0 || channelIdx > 31)
		return -EINVAL;

	/* Validate fport range */
	if (target_fport < 0 || target_fport > FE_PSE_PORT_DROP)
		return -EINVAL;

	ppe_num_entries = airoha_ppe_get_total_num_entries(glb_eth->ppe);

	for (idx = 0; idx < ppe_num_entries; idx++)
	{
		foe_entry = airoha_ppe_foe_get_entry(glb_eth->ppe, idx);

		if(foe_entry == NULL){
			continue;
		}

		if (FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, foe_entry->ib1) != AIROHA_FOE_STATE_BIND){
			continue;
		}

		ptype = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1);

		if (ptype >= PPE_PKT_TYPE_IPV6_ROUTE_3T) {
			data = foe_entry->ipv6.data;
			ib2 = foe_entry->ipv6.ib2;
		} else if(ptype == PPE_PKT_TYPE_BRIDGE){
			data = foe_entry->bridge32.data;
			ib2 = foe_entry->bridge32.ib2;
		} else if(ptype == PPE_PKT_TYPE_IPV4_DSLITE){
			data = foe_entry->dslite.data;
			ib2 = foe_entry->dslite.ib2;
		} else {
			data = foe_entry->ipv4.data;
			ib2 = foe_entry->ipv4.ib2;
		}

		cur_channel = FIELD_GET(AIROHA_FOE_CHANNEL, data);
		fpidx = FIELD_GET(AIROHA_FOE_IB2_PSE_PORT, ib2);

		/* Check if target fport matches */
		if (fpidx != target_fport){
			continue;
		}

		if (cur_channel != channelIdx){
			continue;
		}

		AIROHA_LOG(AIROHA_DEBUG_LEVEL_WARN, "%s: downstream fport(%d) channel(%d): idx=%d, fpidx: %d \n", __func__, target_fport, channelIdx, idx, fpidx);

		spin_lock_bh(&ppe_lock);
		airoha_ppe_delete_entry(glb_eth->ppe, foe_entry, idx);
		spin_unlock_bh(&ppe_lock);
	}

	return 0;
}

static int airoha_ppe_clean_entry_by_mac_common(const unsigned char *mac, unsigned char mac_type)
{
	struct airoha_foe_entry *foe_entry;
	u32 ppe_num_entries = airoha_ppe_get_total_num_entries(glb_eth->ppe);
	unsigned int idx, type;
	struct airoha_foe_mac_info_common *l2;
    unsigned char h_source[ETH_ALEN] = {0};
    unsigned char h_dest[ETH_ALEN] = {0};
    bool del_flag = false;
	int index = 0, i=0;

	if(mac == NULL){
		return 0;
	}

	for (idx = 0; idx < ppe_num_entries; idx++)
	{
		foe_entry = airoha_ppe_foe_get_entry(glb_eth->ppe, idx);

		if(foe_entry == NULL){
			return -1;
		}

		if (FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, foe_entry->ib1) != AIROHA_FOE_STATE_BIND){
			continue;
		}

		type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1);

		if (type >= PPE_PKT_TYPE_IPV6_ROUTE_3T) {
			l2 = &foe_entry->ipv6.l2;
		} else if(type == PPE_PKT_TYPE_BRIDGE){
			l2 = &foe_entry->bridge32.l2;
		} else if(type == PPE_PKT_TYPE_IPV4_DSLITE){
			l2 = &foe_entry->dslite.l2.common;
		} else {
			l2 = &foe_entry->ipv4.l2.common;
			*((__be16 *)&h_source[4]) = cpu_to_be16(foe_entry->ipv4.l2.src_mac_lo);
		}

		if(type ==PPE_PKT_TYPE_BRIDGE){
			*((__be32 *)h_dest) = cpu_to_be32(foe_entry->bridge32.dest_mac_hi);
			*((__be16 *)&h_dest[4]) = cpu_to_be16(foe_entry->bridge32.dest_mac_lo);
			*((__be32 *)h_source) = cpu_to_be32(foe_entry->bridge32.src_mac_hi);
			*((__be16 *)&h_source[4]) = cpu_to_be16(foe_entry->bridge32.src_mac_lo);
		}else {
			*((__be32 *)h_dest) = cpu_to_be32(l2->dest_mac_hi);
			*((__be16 *)&h_dest[4]) = cpu_to_be16(l2->dest_mac_lo);
			*((__be32 *)h_source) = cpu_to_be32(l2->src_mac_hi);
		}

		if((PPE_PKT_TYPE_IPV6_ROUTE_3T == type) || (PPE_PKT_TYPE_IPV6_ROUTE_5T == type) || (PPE_PKT_TYPE_IPV6_6RD == type))
		{
			index = get_ppe_entry_smac_index(foe_entry, PPE_PKT_TYPE_IPV6_ROUTE_5T);
			if(index != 0x10) 
			{
				spin_lock_bh(&shnk_tbl_lock);
				for(i = 0; i < UPDMEM_SMAC_CNT; i++)
				{
					if(index < UPDMEM_NUM)
						h_source[i] = shnkTbl[index].smac[i];
				}
				spin_unlock_bh(&shnk_tbl_lock);
			}
		}

		switch(mac_type)
		{
    		case SRC_MAC:
    		    if(ether_addr_equal(h_source, mac)){
    		        del_flag = true;
    		        AIROHA_LOG(AIROHA_DEBUG_LEVEL_WARN, "airoha_ppe_clean_entry_by_src_mac, line:%d foe_idx = %d\n", __LINE__, idx);
    		    }
    		    break;
    		case DST_MAC:
    			if(ether_addr_equal(h_dest, mac)){
    		        del_flag = true;
    		        AIROHA_LOG(AIROHA_DEBUG_LEVEL_WARN, "airoha_ppe_clean_entry_by_dst_mac, line:%d foe_idx = %d\n", __LINE__, idx);    		        
    		    }
    			break;
    		case SRC_DST_MAC:
    			if (ether_addr_equal(h_source, mac) || ether_addr_equal(h_dest, mac)){
    		        del_flag = true;
    		        AIROHA_LOG(AIROHA_DEBUG_LEVEL_WARN, "airoha_ppe_clean_entry_by_mac, line:%d foe_idx = %d\n", __LINE__, idx);
    			}
    			break;
    		default:
    			break;
    	}

		if (del_flag)
		{
		    spin_lock_bh(&ppe_lock);
			airoha_ppe_clear_sram_table_flow(glb_eth->ppe, idx);
	        spin_unlock_bh(&ppe_lock);
		}
		del_flag = false;
	}

	return 0;
}

static int airoha_ppe_clean_entry_by_mac(const unsigned char *mac)
{
    airoha_ppe_clean_entry_by_mac_common(mac, SRC_DST_MAC);

	return 0;
}

static int airoha_ppe_clean_entry_by_src_mac(const unsigned char *mac)
{
    airoha_ppe_clean_entry_by_mac_common(mac, SRC_MAC);

	return 0;
}

static int airoha_ppe_clean_entry_by_dst_mac(const unsigned char *mac)
{
    airoha_ppe_clean_entry_by_mac_common(mac, DST_MAC);

	return 0;
}

static int airoha_ppe_clean_entry_by_type(unsigned char type)
{
	struct airoha_foe_entry foe_entry_local;
	struct airoha_foe_entry *foe_entry;
	u32 ppe_num_entries = airoha_ppe_get_total_num_entries(glb_eth->ppe);
	unsigned int idx, ptype;
	struct airoha_foe_mac_info_common *l2;
    unsigned char h_dest[ETH_ALEN];
	int delete_count = 0;
	
	for (idx = 0; idx < ppe_num_entries; idx++)
	{
		foe_entry = &foe_entry_local;
		foe_entry = airoha_ppe_foe_get_entry(glb_eth->ppe, idx);

		if(foe_entry == NULL){
			continue;
		}

		if (FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, foe_entry->ib1) != AIROHA_FOE_STATE_BIND){
			continue;
		}

		ptype = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1);

		if (ptype >= PPE_PKT_TYPE_IPV6_ROUTE_3T) {
			l2 = &foe_entry->ipv6.l2;
		} else if(ptype == PPE_PKT_TYPE_BRIDGE){
			l2 = &foe_entry->bridge32.l2;
		} else {
			l2 = &foe_entry->ipv4.l2.common;
		}

		if(ptype ==PPE_PKT_TYPE_BRIDGE){
			*((__be32 *)h_dest) = cpu_to_be32(foe_entry->bridge32.dest_mac_hi);
			*((__be16 *)&h_dest[4]) = cpu_to_be16(foe_entry->bridge32.dest_mac_lo);
		}else {
			*((__be32 *)h_dest) = cpu_to_be32(l2->dest_mac_hi);
			*((__be16 *)&h_dest[4]) = cpu_to_be16(l2->dest_mac_lo);
		}

		if (airoha_debug_level > 0)
			printk("dmac(%d): %pM\n", idx, h_dest);

		if (type == HWNAT_OFF_UNI  && (h_dest[0] & 0x01) != 0x0){
			continue;
		}

		if (type == HWNAT_OFF_MUL4  && (!(h_dest[0] == 0x01 && h_dest[1] == 0x0 && h_dest[2] == 0x5e))){
			continue;
		}

		if (type == HWNAT_OFF_MUL6  && (!(h_dest[0] == 0x33 && h_dest[1] == 0x33))){
			continue;
		}

		if (delete_count < PPE_MAX_CT_DELETE_PER_CLEAN) {
			airoha_ppe_delete_conntrack(foe_entry);
			delete_count++;
		}

		spin_lock_bh(&ppe_lock);
		airoha_ppe_delete_entry(glb_eth->ppe, foe_entry, idx);
        spin_unlock_bh(&ppe_lock);
	}

	return 0;
}

static int airoha_ppe_clean_entry_by_ip(unsigned int ip_addr)
{
	struct airoha_foe_entry *foe_entry = NULL;
	u32 ppe_num_entries = airoha_ppe_get_total_num_entries(glb_eth->ppe);
	int index = 0;
	unsigned int idx = 0, ptype = 0;
	unsigned int ip1 = 0, ip2 = 0, ip3 = 0, ip4 = 0;
	int delete_count = 0;

	for (idx = 0; idx < ppe_num_entries; idx++)
	{
		foe_entry = airoha_ppe_foe_get_entry(glb_eth->ppe, idx);
		if(foe_entry == NULL){
			continue;
		}

		if (FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, foe_entry->ib1) != AIROHA_FOE_STATE_BIND){
			continue;
		}

		ptype = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1);

		switch (ptype)
		{
			case PPE_PKT_TYPE_IPV4_HNAPT:
			case PPE_PKT_TYPE_IPV4_ROUTE:
				ip1 = foe_entry->ipv4.orig_tuple.src_ip;
				ip2 = foe_entry->ipv4.orig_tuple.dest_ip;
				ip3 = foe_entry->ipv4.new_tuple.src_ip;
				ip4 = foe_entry->ipv4.new_tuple.dest_ip;
				break;

			case PPE_PKT_TYPE_IPV4_DSLITE:
				ip1 = foe_entry->dslite.ip4.src_ip;
				ip2 = foe_entry->dslite.ip4.dest_ip;
				ip3 = ip4 = 0;
				break;

			case PPE_PKT_TYPE_IPV6_6RD:
				ip1 = ip2 = 0;
				index =	get_ppe_entry_tunnel_ip_index(foe_entry, PPE_PKT_TYPE_IPV6_6RD);
				/* CID:1118891 */
				if ((index >= 0) && (index < UPDMEM_NUM))
				{
					spin_lock_bh(&shnk_tbl_lock);
					ip3 = shnkTbl[index].eg_ipv4[0];
					ip4 = shnkTbl[index].eg_ipv4[1];
					spin_unlock_bh(&shnk_tbl_lock);
				}
				break;

			case PPE_PKT_TYPE_BRIDGE:
			case PPE_PKT_TYPE_IPV6_ROUTE_3T:
			case PPE_PKT_TYPE_IPV6_ROUTE_5T:
			default:
				continue;
		}

		if ((ip1 != ip_addr) && (ip2 != ip_addr) && (ip3 != ip_addr) && (ip4 != ip_addr)){
			continue;
		}

		if (airoha_debug_level > 0)
		{
			ip1 = htonl(ip1);
			ip2 = htonl(ip2);
			ip3 = htonl(ip3);
			ip4 = htonl(ip4);
			printk("current entry(%d): %pI4->%pI4 => %pI4->%pI4 \n", idx, &ip1, &ip2, &ip3, &ip4);
		}

		if (delete_count < PPE_MAX_CT_DELETE_PER_CLEAN) {
			airoha_ppe_delete_conntrack(foe_entry);
			delete_count++;
		}

		spin_lock_bh(&ppe_lock);
		airoha_ppe_delete_entry(glb_eth->ppe, foe_entry, idx);
        spin_unlock_bh(&ppe_lock);
	}

	return 0;
}

static int airoha_ppe_clean_entry_by_port(u16 src_port, u16 dest_port)
{
    struct airoha_foe_entry *foe_entry = NULL;
    u32 ppe_num_entries = 0;
    unsigned int idx = 0, ptype = 0;
    u16 sp1 = 0, dp1 = 0, sp2 = 0, dp2 = 0;
    bool matched = false;
	int delete_count = 0;

    if (src_port == 0 && dest_port == 0){
        return -EINVAL;
    }

    if (!glb_eth || !glb_eth->ppe){
        return -EINVAL;
    }

    ppe_num_entries = airoha_ppe_get_total_num_entries(glb_eth->ppe);
    for (idx = 0; idx < ppe_num_entries; idx++)
    {
        foe_entry = airoha_ppe_foe_get_entry(glb_eth->ppe, idx);
        if (foe_entry == NULL) {
            continue;
        }

        if (FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, foe_entry->ib1) != AIROHA_FOE_STATE_BIND) {
            continue;
        }

        ptype = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1);
        sp1 = dp1 = sp2 = dp2 = 0;

        switch (ptype)
        {
            case PPE_PKT_TYPE_IPV4_HNAPT:
                sp1 = foe_entry->ipv4.orig_tuple.src_port;
                dp1 = foe_entry->ipv4.orig_tuple.dest_port;
                sp2 = foe_entry->ipv4.new_tuple.src_port;
                dp2 = foe_entry->ipv4.new_tuple.dest_port;
                break;

            case PPE_PKT_TYPE_IPV4_DSLITE:
                sp1 = foe_entry->dslite.ip4.src_port;
                dp1 = foe_entry->dslite.ip4.dest_port;
                sp2 = dp2 = 0;
                break;

            case PPE_PKT_TYPE_IPV6_ROUTE_5T:
            case PPE_PKT_TYPE_IPV6_6RD:
                sp1 = foe_entry->ipv6.src_port;
                dp1 = foe_entry->ipv6.dest_port;
                sp2 = dp2 = 0;
                break;

            case PPE_PKT_TYPE_IPV4_ROUTE:
            case PPE_PKT_TYPE_BRIDGE:
            case PPE_PKT_TYPE_IPV6_ROUTE_3T:
            default:
                continue;
        }

        /* Check if any extracted port matches the target port(s) */
        matched = false;
        if (dest_port != 0) {
            if (dp1 == dest_port || dp2 == dest_port)
                matched = true;
        }
        if (src_port != 0) {
            if (sp1 == src_port || sp2 == src_port)
                matched = true;
        }

        if (!matched) {
            continue;
        }

        if (airoha_debug_level > 0)
        {
			printk("clean_entry_by_port: entry(%u), ptype=%u, orig[sp=%u, dp=%u], new[sp=%u, dp=%u]\n",
                   idx, ptype, sp1, dp1, sp2, dp2);
        }

		if (delete_count < PPE_MAX_CT_DELETE_PER_CLEAN) {
			airoha_ppe_delete_conntrack(foe_entry);
			delete_count++;
		}

        spin_lock_bh(&ppe_lock);
        airoha_ppe_delete_entry(glb_eth->ppe, foe_entry, idx);
        spin_unlock_bh(&ppe_lock);
    }

    return 0;
}

static int airoha_ppe_clean_multicast_entry(void)
{
	airoha_ppe_clean_entry_by_type(HWNAT_OFF_MUL4);
	airoha_ppe_clean_entry_by_type(HWNAT_OFF_MUL6);

	return 0;
}

static int airoha_ppe_clean_entry_by_landev(struct net_device *dev)
{
	struct airoha_foe_entry *foe_entry;
	struct airoha_foe_entry foe_entry_copy;
	unsigned int idx = 0;
	u32 ppe_num_entries = 0;
	int delete_count = 0;
  
	if(!dev || !glb_eth || !glb_eth->ppe)
		return -EINVAL;

	ppe_num_entries = airoha_ppe_get_total_num_entries(glb_eth->ppe);

	for (idx = 0; idx < ppe_num_entries; idx++)
	{
		foe_entry = airoha_ppe_foe_get_entry(glb_eth->ppe, idx);
		if (foe_entry == NULL) {
			continue;
		}

		spin_lock_bh(&ppe_lock);
		if (FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, foe_entry->ib1) != AIROHA_FOE_STATE_BIND) {
			spin_unlock_bh(&ppe_lock);
			continue;
		}

		if (foe_ext[idx].lan_ifindex != dev->ifindex) {
			spin_unlock_bh(&ppe_lock);
			continue;
		}

		/*
		 * Copy the entry while holding the lock to avoid TOCTOU race
		 * condition. The foe_entry content may be modified by other
		 * threads after we release the lock, but airoha_ppe_delete_conntrack
		 * needs to read tuple data (src/dst ip/port) outside the lock
		 * since nf_conntrack_find_get may sleep or acquire other locks.
		 */
		foe_entry_copy = *foe_entry;
		spin_unlock_bh(&ppe_lock);

		AIROHA_LOG(AIROHA_DEBUG_LEVEL_WARN, "[%s] lan_dev(%d): %s \n", __func__, idx, dev->name);

		if (delete_count < PPE_MAX_CT_DELETE_PER_CLEAN) {
			airoha_ppe_delete_conntrack(&foe_entry_copy);
			delete_count++;
		}

		spin_lock_bh(&ppe_lock);
		airoha_ppe_delete_entry(glb_eth->ppe, foe_entry, idx);
		spin_unlock_bh(&ppe_lock);
	}

	return 0;
}

int arht_hwnat_delete_ppe_entry(unsigned int foe_index)
{
	struct airoha_foe_entry *hwe;
	if(glb_eth == NULL)
		return 0;

	spin_lock_bh(&ppe_lock);
	hwe = airoha_ppe_foe_get_entry_locked(glb_eth->ppe, foe_index);
	if(hwe == NULL)
	{
		spin_unlock_bh(&ppe_lock);
		return 0;
	}
	airoha_ppe_delete_entry(glb_eth->ppe,hwe,foe_index);
	spin_unlock_bh(&ppe_lock);

	return 0;
}
EXPORT_SYMBOL(arht_hwnat_delete_ppe_entry);

static int airoha_ppe_foe_entry_handler(void *inputvalue, int operation)
{
	int ret = -1;

	switch(operation)
	{
		case FOE_OPE_GETENTRYNUM:
			ret = FOE_ENTRY_NUM((struct sk_buff *)inputvalue);
			break;

		case FOE_OPE_CLEARENTRY:
			ret = arht_hwnat_delete_ppe_entry(*((unsigned int*)inputvalue));
			break;

		default:
			printk("\r\n %s %d Not support such operation(%d)", __func__, __LINE__, operation);
			break;
	}

	return ret;
}

static int airoha_ppe_delete_foe_entry_unlock(int index)
{
	struct airoha_foe_entry *foe_entry = NULL;

	if (index <0 || index >= airoha_ppe_get_total_num_entries(glb_eth->ppe)){
		return 0;
	}

	if (airoha_debug_level >1)
		printk("\n=====>airoha_ppe_delete_foe_entry_unlock(): index = %d", index);
	
	/*clear entry*/
	foe_entry = airoha_ppe_foe_get_entry(glb_eth->ppe, index);
	if(foe_entry == NULL){
		return -1;
	}

	spin_lock_bh(&ppe_lock);
	airoha_ppe_clear_sram_table_flow(glb_eth->ppe, index);
    spin_unlock_bh(&ppe_lock);
	
	return 0;
}

static uint32_t airoha_ppe_set_bind_threshold(uint32_t threshold)
{
    int i;
	uint32_t old_threshold;

	old_threshold = airoha_fe_rr(glb_eth, REG_PPE_BIND_RATE(0));

	/* Set reach bind rate for unbind state */
	for (i = 0; i < glb_eth->soc->num_ppe; i++) {
        airoha_fe_rmw(glb_eth, REG_PPE_BIND_RATE(i), PPE_BIND_RATE_L2B_BIND_MASK | PPE_BIND_RATE_BIND_MASK,
                      FIELD_PREP(PPE_BIND_RATE_L2B_BIND_MASK, threshold) | FIELD_PREP(PPE_BIND_RATE_BIND_MASK, threshold));
    }

	printk("%s %d hwnat bind threshold = %u\n", __func__, __LINE__, threshold);
	
	return old_threshold;
}

static int airoha_ppe_set_multicast_vlan(int index, int vid, int vpm)
{
	struct airoha_foe_entry *foe_entry = NULL;
	struct airoha_foe_mac_info_common *l2;
    unsigned char ptype = 0;

	if (index < 0 || index >= airoha_ppe_get_total_num_entries(glb_eth->ppe)){
		return 0;
	}

	if((vid <= 0) || (vid > 4095)){
		return 0;
	}

    spin_lock_bh(&ppe_lock);
    foe_entry = airoha_ppe_foe_get_entry_locked(glb_eth->ppe, index);

    if(foe_entry == NULL){
	    spin_unlock_bh(&ppe_lock);
        return -1;
    }

    ptype = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1);
    if (ptype >= PPE_PKT_TYPE_IPV6_ROUTE_3T) {
        l2 = &foe_entry->ipv6.l2;
    } else if(ptype == PPE_PKT_TYPE_BRIDGE){
        l2 = &foe_entry->bridge32.l2;
    } else if(ptype == PPE_PKT_TYPE_IPV4_DSLITE){
		l2 = &foe_entry->dslite.l2.common;
	} else {
        l2 = &foe_entry->ipv4.l2.common;
    }

	l2->etype &= ~(0x3 << 8);
	l2->etype |= (0x3 & vpm) << 8;
	l2->vlan1 &= 0xf000;
	l2->vlan1 |= (0xfff & vid);

    if (index < glb_eth->soc->ppe_sram_etry_num) {
        airoha_ppe_foe_commit_entry_ptr(glb_eth->ppe, foe_entry, index, 0);
    }

	spin_unlock_bh(&ppe_lock);
	
	return 0;
}

static int airoha_ppe_is_multicast_entry(int index, unsigned char *grp_addr, unsigned char *src_addr, int type)
{
	struct airoha_foe_entry *foe_entry = NULL;
	unsigned char h_dest[ETH_ALEN] = {0};
	unsigned int ip4_dst_ip = 0;
	unsigned int ip4_src_ip = 0;
	unsigned int ip6_dst_ip[4] = {0};
	unsigned int ip6_src_ip[4] = {0};
    unsigned char ptype = 0;
    int i = 0;

	if (index <0 || index >= airoha_ppe_get_total_num_entries(glb_eth->ppe)){
		return 0;
	}

    foe_entry = airoha_ppe_foe_get_entry(glb_eth->ppe, index);
	if(foe_entry == NULL){
		return -1;
	}

	if (FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, foe_entry->ib1) != AIROHA_FOE_STATE_BIND){
		return 0;
	}

	ptype = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1);
	if (ptype < PPE_PKT_TYPE_BRIDGE)
	{
	    ip4_dst_ip = htonl(foe_entry->ipv4.orig_tuple.dest_ip);
	    ip4_src_ip = htonl(foe_entry->ipv4.orig_tuple.src_ip);
		if (memcmp(grp_addr, &ip4_dst_ip, 4)){
			return 0;
		}
		if (memcmp(src_addr, &ip4_src_ip, 4)){
			return 0;
		}
		return 1;
	}
	else if (ptype == PPE_PKT_TYPE_BRIDGE)
	{
        *((__be32 *)h_dest) = cpu_to_be32(foe_entry->bridge32.dest_mac_hi);
        *((__be16 *)&h_dest[4]) = cpu_to_be16(foe_entry->bridge32.dest_mac_lo);

		if(h_dest[0] == 0x01 && h_dest[1] == 0x00 && h_dest[2] == 0x5E) {
			return 1;
		} else if(h_dest[0] == 0x33 && h_dest[1] == 0x33) {
			return 1;
		} else {
			return 0;
		}
	}else{
	    for(i = 0; i < 4; i++){
	        ip6_dst_ip[i] = htonl(foe_entry->ipv6.dest_ip[i]);
	        ip6_src_ip[i] = htonl(foe_entry->ipv6.src_ip[i]);
	    }
		if (memcmp(grp_addr, ip6_dst_ip, 16)){
			return 0;
		}
		if (memcmp(src_addr, ip6_src_ip, 16)){
			return 0;
		}
		return 1;
	}
	
	return 0;
}

static int airoha_ppe_is_drop_entry(int index, unsigned char *grp_addr, unsigned char *src_addr, int type)
{
	if (airoha_ppe_is_multicast_entry(index, grp_addr, src_addr, type) < 1){
		return 0;
	}

	return 1;
}

static int airoha_ppe_set_special_tag(int index, int tag)
{
	struct airoha_foe_entry foe_entry_local;
    struct airoha_foe_entry *foe_entry = &foe_entry_local;    
	struct airoha_foe_mac_info_common *l2;
    unsigned char ptype = 0;

	if (index <0 || index >= airoha_ppe_get_total_num_entries(glb_eth->ppe))
		return 0;

	foe_entry = airoha_ppe_foe_get_entry(glb_eth->ppe, index);
	if(foe_entry == NULL){
		return -1;
	}

	ptype = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1);
    if (ptype >= PPE_PKT_TYPE_IPV6_ROUTE_3T) {
        l2 = &foe_entry->ipv6.l2;
    } else if(ptype == PPE_PKT_TYPE_BRIDGE){
        l2 = &foe_entry->bridge32.l2;
    } else if(ptype == PPE_PKT_TYPE_IPV4_DSLITE){
		l2 = &foe_entry->dslite.l2.common;
	} else {
        l2 = &foe_entry->ipv4.l2.common;
    }

    l2->etype &= 0xff00;
    l2->etype |= (0xff & tag);

    spin_lock_bh(&ppe_lock);
    if (index < glb_eth->soc->ppe_sram_etry_num) {
        airoha_ppe_foe_commit_entry_ptr(glb_eth->ppe, foe_entry, index, 0);
    }
    spin_unlock_bh(&ppe_lock);

	return 0;
}

static int airoha_ppe_check_entry_is_bind(int index)
{
    struct airoha_foe_entry *foe_entry = NULL;

    if (index <0 || index >= airoha_ppe_get_total_num_entries(glb_eth->ppe))
        return 0;

    foe_entry = airoha_ppe_foe_get_entry(glb_eth->ppe, index);
	if(foe_entry == NULL){
		return -1;
	}

    if (FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, foe_entry->ib1) != AIROHA_FOE_STATE_BIND){
		return 0;
	}
    
    return 1;
}

void airoha_ppe_foe_flow_update_eth_offload(struct airoha_ppe *ppe, 
	struct sk_buff *skb, struct port_info *pinfo, u8 fport)
{
	u32 hash = FOE_ENTRY_NUM(skb);
	int type;
	struct airoha_flow_table_entry *e;
	struct airoha_foe_entry *hwe;
	struct hlist_node *n;
	u32 index, meter0_idx = 0x7F, meter1_idx = 0x3F, data = 0;
	int dscp=0;
	int flow_table_enable = 0;
	
	AIROHA_LOG(AIROHA_DEBUG_LEVEL_INFO, "hash at qdma_lan_tx: %u\n", hash);
	if ( !is_Valid_Foe_Entry(skb) ) {
		AIROHA_LOG(AIROHA_DEBUG_LEVEL_INFO, "Incorrect hash:%u\n", hash);
		return;
	}

	
	spin_lock_bh(&ppe_lock);
	hwe = airoha_ppe_foe_get_entry_locked(ppe, hash);
	if (!hwe)
	{
		goto unlock;
	}

	/* update fe_resource_mark down_stream	*/
	if ( fe_resource_mark_acnt_hook ) {
		fe_resource_mark_acnt_hook(skb, DOWN_STREAM);
	}
	if ( fe_resource_mark_meter_hook ) {
		fe_resource_mark_meter_hook(skb, DOWN_STREAM);
	}
	
	if(skb->mark == DP_SPEED_UP)
	{
		speedtest_tx_offload(skb,hwe, ppe, pinfo);
	}
	
	index = airoha_ppe_foe_get_entry_hash(ppe, hwe);
	hlist_for_each_entry_safe(e, n, &ppe->foe_flow[index], list) {
		if (airoha_ppe_foe_compare_entry(e, hwe)) {
			flow_table_enable = 1;
			if(e->tx_modified){
				goto unlock;
			}
			type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, e->data.ib1);
			airoha_set_default_acnt_meter_idx(&e->data, type);
			dscp = get_dscp_from_skb(skb, type);
			
			meter0_idx = get_meter_idx_by_gemport(skb, pinfo, fport);
			meter1_idx = get_meter_idx_by_lan(skb, pinfo, fport);
			AIROHA_LOG(AIROHA_DEBUG_LEVEL_ERR, "%s %d meter0_idx = %u, meter1_idx = %u\n", __func__, __LINE__, meter0_idx, meter1_idx);
			data = (e->data.ipv4.data & ~(AIROHA_FOE_SHAPER_ID | AIROHA_FOE_QID)) |
					FIELD_PREP(AIROHA_FOE_QID, 
					((AIROHA_NUM_QOS_QUEUES - 1) - ((pinfo->txq) % AIROHA_NUM_QOS_QUEUES))) |
					FIELD_PREP(AIROHA_FOE_SHAPER_ID, meter0_idx);

			switch (type) {
				case PPE_PKT_TYPE_IPV4_ROUTE:
				case PPE_PKT_TYPE_IPV4_HNAPT:
					e->data.ipv4.data = data;
					e->data.ipv4.ib2 &= ~AIROHA_FOE_IB2_DSCP;
					e->data.ipv4.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_DSCP, dscp);	
					set_ppe_foe_entry_meter_grp2(&e->data.ipv4.l2.meter, meter1_idx);
					break;
				
				case PPE_PKT_TYPE_BRIDGE:
					break;
				
				case PPE_PKT_TYPE_IPV6_ROUTE_3T:
				case PPE_PKT_TYPE_IPV6_ROUTE_5T:
				case PPE_PKT_TYPE_IPV6_6RD:
					e->data.ipv6.data = data;
					e->data.ipv6.ib2 &= ~AIROHA_FOE_IB2_DSCP;
					e->data.ipv6.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_DSCP, dscp);
					set_ppe_foe_entry_meter_grp2(&e->data.ipv6.meter, meter1_idx);
					break;
					
				case PPE_PKT_TYPE_IPV4_DSLITE:
					e->data.dslite.data = data;
					e->data.dslite.ib2 &= ~AIROHA_FOE_IB2_DSCP;
					e->data.dslite.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_DSCP, dscp);
					set_ppe_foe_entry_meter_grp2(&e->data.dslite.l2.meter, meter1_idx);
					break;
					
				default:
					break;
			}

			arht_ppe_l4s_apply(&e->data, type, dscp);

			if ( ra_sw_nat_update_acnt_info_hook ) {
				ra_sw_nat_update_acnt_info_hook(&e->data, skb, pinfo, fport);
			}

			e->tx_modified = true;
			
			AIROHA_LOG(AIROHA_DEBUG_LEVEL_ERR, "Eth upstream hash %u set modified_bit %u at tx\n"
					, hash, e->tx_modified);
			break;
		}
	}
	
unlock:
	spin_unlock_bh(&ppe_lock);

	if(flow_table_enable == 0)
	{
		airoha_ppe_tx_handler(skb, pinfo, fport);
	}
}

static void airoha_ppe_foe_get_pppoe_info(struct sk_buff *skb, u16 vl, u16 *pppid)
{
	u16 tmp;
	struct pppoe_hdr *ppph = NULL;

	tmp = *(u16 *)(skb->data+12 + vl*4);
	if(tmp == htons(ETH_P_PPP_SES)){
		ppph = pppoe_hdr(skb);
		if(!ppph)
			return;
		*pppid = ntohs(ppph->sid);
	}
}

void airoha_ppe_foe_flow_update_pon_offload(struct airoha_ppe *ppe, struct sk_buff *skb, struct port_info *pinfo, u8 fport)
{
	u32 hash = FOE_ENTRY_NUM(skb);
	int type = 0;
	struct airoha_flow_table_entry *e = NULL;
	struct airoha_foe_entry *hwe = NULL;
	struct hlist_node *n = NULL;
	struct airoha_foe_mac_info_common *l2 = NULL;
	u32 index = 0, data = 0, meter0_idx = 0x7F, meter1_idx = 0x3F;
	u16 vn = 0, vid1 = 0, vid2 = 0, pppid = 0;	
	struct ethhdr* eth = NULL;
	int dscp=0;
	 
	/* PON offload path  flow_table_enable is initialized to 1 because
	* airoha_ppe_tx_handler() is not applicable here (packets on this
	* path are already in BIND state, not UNBIND_RATE_REACHED).
	* The fallback to airoha_ppe_tx_handler() caused a race condition
	* during reboot when flow table entry was not yet populated.
	*/
	int flow_table_enable = 1;
	
	AIROHA_LOG(AIROHA_DEBUG_LEVEL_INFO, "hash at qdma_wan_tx: %u\n", hash);
	if ( !is_Valid_Foe_Entry(skb) ) {
		AIROHA_LOG(AIROHA_DEBUG_LEVEL_INFO, "Incorrect hash:%u\n", hash);
		return;
	}
	
	spin_lock_bh(&ppe_lock);
	hwe = airoha_ppe_foe_get_entry_locked(ppe, hash);
	if (!hwe)
	{
		goto unlock;
	}

	if ( fe_resource_mark_meter_hook ) {
		fe_resource_mark_meter_hook(skb, UP_STREAM);
	}
		
	index = airoha_ppe_foe_get_entry_hash(ppe, hwe);
	hlist_for_each_entry_safe(e, n, &ppe->foe_flow[index], list) {
		if (airoha_ppe_foe_compare_entry(e, hwe)) {
			
			/*remove flow_table_enable = 1 in loop because it will be dead code if the default is 1 already*/
			//flow_table_enable = 1;
			
			if(e->tx_modified){
				goto unlock;
			}
			airoha_ppe_foe_get_vlan_info(skb, &vn, &vid1, &vid2);
			airoha_ppe_foe_get_pppoe_info(skb, vn, &pppid);

			type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, e->data.ib1);
			airoha_set_default_acnt_meter_idx(&e->data, type);
			dscp = get_dscp_from_skb(skb, type);
			
			meter0_idx = get_meter_idx_by_gemport(skb, pinfo, 2);
			meter1_idx = get_meter_idx_by_lan(skb, pinfo, 2);
			AIROHA_LOG(AIROHA_DEBUG_LEVEL_ERR, "%s %d meter0_idx = %u, meter1_idx = %u\n", __func__, __LINE__, meter0_idx, meter1_idx);
			
			AIROHA_LOG(AIROHA_DEBUG_LEVEL_ERR, "Packet type:%d vid1 %d vid2 %d pppid %d\n"
					,type,vid1,vid2,pppid);
			data = FIELD_PREP(AIROHA_FOE_CHANNEL, pinfo->channel) |
	       			FIELD_PREP(AIROHA_FOE_QID, 
						((AIROHA_NUM_QOS_QUEUES - 1) - ((pinfo->txq) % AIROHA_NUM_QOS_QUEUES))) |
	       			FIELD_PREP(AIROHA_FOE_SHAPER_ID, meter0_idx);

			e->data.ib1 |= FIELD_PREP(AIROHA_FOE_IB1_BIND_VLAN_LAYER, !!vn) | 
							FIELD_PREP(AIROHA_FOE_IB1_BIND_VPM, !!vn) | 
							FIELD_PREP(AIROHA_FOE_IB1_BIND_PPPOE, !!pppid);
			switch (type) {
				case PPE_PKT_TYPE_IPV4_ROUTE:
				case PPE_PKT_TYPE_IPV4_HNAPT:
					e->data.ipv4.data = data;
					l2 = &e->data.ipv4.l2.common;
					e->data.ipv4.ib2 &= ~AIROHA_FOE_IB2_NBQ;
					e->data.ipv4.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, pinfo->channel);	
					e->data.ipv4.ib2 &= ~AIROHA_FOE_IB2_DSCP;
					e->data.ipv4.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_DSCP, dscp);	
					set_ppe_foe_entry_meter_grp2(&e->data.ipv4.l2.meter, meter1_idx);
					break;
				
				case PPE_PKT_TYPE_BRIDGE:
					e->data.bridge.data = data;
					l2 = &e->data.bridge.l2.common;
					e->data.bridge.ib2 &= ~AIROHA_FOE_IB2_NBQ;
					e->data.bridge.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, pinfo->channel);	
					break;
				
				case PPE_PKT_TYPE_IPV6_ROUTE_3T:
				case PPE_PKT_TYPE_IPV6_ROUTE_5T:
				case PPE_PKT_TYPE_IPV6_6RD:
					e->data.ipv6.data = data;
					l2 = &e->data.ipv6.l2;
					e->data.ipv6.ib2 &= ~AIROHA_FOE_IB2_NBQ;
					e->data.ipv6.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, pinfo->channel);	
					e->data.ipv6.ib2 &= ~AIROHA_FOE_IB2_DSCP;
					e->data.ipv6.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_DSCP, dscp);
					set_ppe_foe_entry_meter_grp2(&e->data.ipv6.meter, meter1_idx);
					break;
					
				case PPE_PKT_TYPE_IPV4_DSLITE:
					e->data.dslite.data = data;		
					l2 = &e->data.dslite.l2.common;
					e->data.dslite.ib2 &= ~AIROHA_FOE_IB2_NBQ;
					e->data.dslite.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, pinfo->channel);
					e->data.dslite.ib2 &= ~AIROHA_FOE_IB2_DSCP;
					e->data.dslite.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_DSCP, dscp);
					set_ppe_foe_entry_meter_grp2(&e->data.dslite.l2.meter, meter1_idx);
					break;
					
				default:
					break;
			}

			arht_ppe_l4s_apply(&e->data, type, dscp);

			/* CID:897190 */
			if (NULL != l2)
			{
				l2->etype = pinfo->stag;
				l2->vlan1 = vid1;
				l2->vlan2 = vid2;
			}
			
			/*Set smac value when mac tx based on bridge /route mode */
			eth = (struct ethhdr *)skb_mac_header(skb);
			
			airoha_set_ppe_mac(&e->data,skb->dev,eth->h_source,eth->h_dest,pppid);

			if ( ra_sw_nat_update_acnt_info_hook ) {
				ra_sw_nat_update_acnt_info_hook(&e->data, skb, pinfo, fport);
			}
			
			e->tx_modified = true;
			AIROHA_LOG(AIROHA_DEBUG_LEVEL_ERR, "PON upstream hash %u set modified_bit %u at tx\n"
					, hash, e->tx_modified);
			
			break;
		}
	}

unlock:
	spin_unlock_bh(&ppe_lock);

	/* This block is intentionally kept for symmetry but will not be
     * triggered since flow_table_enable is always 1 in this function. */
	if(flow_table_enable == 0)
	{
		airoha_ppe_tx_handler(skb, pinfo, 2);
	}
}

static void clean_entry_work_func(struct work_struct *work)
{
    struct clean_entry_work *cew = container_of(work, struct clean_entry_work, work);

    switch (cew->type) {
    case CLEAN_BY_GEMPORT:
        airoha_ppe_clean_entry_by_gemport(*(unsigned int *)cew->data);
        break;
    case CLEAN_BY_CHANNEL:
        airoha_ppe_clean_entry_by_channel(*(int *)cew->data);
        break;
    case CLEAN_BY_MAC:
        airoha_ppe_clean_entry_by_mac((const unsigned char *)cew->data);
        break;
    case CLEAN_BY_SRC_MAC:
        airoha_ppe_clean_entry_by_src_mac((const unsigned char *)cew->data);
        break;
    case CLEAN_BY_DST_MAC:
        airoha_ppe_clean_entry_by_dst_mac((const unsigned char *)cew->data);
        break;
    case CLEAN_BY_TYPE:
        airoha_ppe_clean_entry_by_type(*(unsigned char *)cew->data);
        break;
    case CLEAN_BY_IP:
        airoha_ppe_clean_entry_by_ip(*(unsigned int *)cew->data);
        break;
    case CLEAN_MULTICAST:
        airoha_ppe_clean_multicast_entry();
        break;
    case CLEAN_TABLE:
        airoha_ppe_clean_sram_table();
        break;
	case CLEAN_BY_LANDEV:
		airoha_ppe_clean_entry_by_landev(*(struct net_device **)cew->data);
		break;
	case CLEAN_BY_FPORT_AND_CHANNEL:
		{
			struct clean_lan_params *params = (struct clean_lan_params *)cew->data;
			airoha_ppe_clean_entry_by_fport_and_channel(params->fport, params->channel);
		}
		break;
    case CLEAN_BY_PORT:
    {
        struct clean_port_params *pp = (struct clean_port_params *)cew->data;
        airoha_ppe_clean_entry_by_port(pp->src_port, pp->dest_port);
    }
        break;
    default:
        break;
    }

    kfree(cew->data);
    kfree(cew);
}

static int queue_clean_entry_work(enum clean_entry_type type, const void *data, size_t data_len)
{
    struct clean_entry_work *cew;

    cew = kzalloc(sizeof(*cew), GFP_KERNEL);
    if (!cew)
        return -ENOMEM;

    INIT_WORK(&cew->work, clean_entry_work_func);
    cew->type = type;

    if (data_len > 0) {
        cew->data = kmemdup(data, data_len, GFP_KERNEL);
        if (!cew->data) {
            kfree(cew);
            return -ENOMEM;
        }
        cew->data_len = data_len;
    } else {
        cew->data = NULL;
        cew->data_len = 0;
    }

    queue_work(clean_entry_wq, &cew->work);
    return 0;
}

static int clean_entry_by_gemport_hook(unsigned int gemport_id)
{
    return queue_clean_entry_work(CLEAN_BY_GEMPORT, &gemport_id, sizeof(gemport_id));
}
static int clean_entry_by_channel_hook(int channelIdx)
{
    return queue_clean_entry_work(CLEAN_BY_CHANNEL, &channelIdx, sizeof(channelIdx));
}
static int clean_entry_by_mac_hook(const unsigned char *mac)
{
    return queue_clean_entry_work(CLEAN_BY_MAC, mac, ETH_ALEN);
}
static int clean_entry_by_src_mac_hook(const unsigned char *mac)
{
    return queue_clean_entry_work(CLEAN_BY_SRC_MAC, mac, ETH_ALEN);
}
static int clean_entry_by_dst_mac_hook(const unsigned char *mac)
{
    return queue_clean_entry_work(CLEAN_BY_DST_MAC, mac, ETH_ALEN);
}
static int clean_entry_by_type_hook(unsigned char type)
{
    return queue_clean_entry_work(CLEAN_BY_TYPE, &type, sizeof(type));
}
static int clean_entry_by_ip_hook(unsigned int ip_addr)
{
    return queue_clean_entry_work(CLEAN_BY_IP, &ip_addr, sizeof(ip_addr));
}

static int clean_entry_by_port_hook(u16 src_port, u16 dest_port)
{
    struct clean_port_params params;

    params.src_port = src_port;
    params.dest_port = dest_port;
    return queue_clean_entry_work(CLEAN_BY_PORT, &params, sizeof(params));
}

static int clean_entry_by_landev_hook(struct net_device *dev)
{
	return queue_clean_entry_work(CLEAN_BY_LANDEV,  &dev, sizeof(struct net_device *));
}

/* Hook function that directly receives fport and channel parameters */
static int clean_entry_by_fport_and_channel_hook(int fport, int channelIdx)
{
	struct clean_lan_params params;

	/* Validate fport range */
	if (fport < 0 || fport > FE_PSE_PORT_DROP)
		return -EINVAL;

	/* Validate channel index range */
	if (channelIdx < 0 || channelIdx > 31)
		return -EINVAL;

	params.fport = fport;
	params.channel = channelIdx;
	return queue_clean_entry_work(CLEAN_BY_FPORT_AND_CHANNEL, &params, sizeof(params));
}

static int clean_multicast_entry_hook(void)
{
    return queue_clean_entry_work(CLEAN_MULTICAST, NULL, 0);
}

static int clean_entry_all_sram_table(void)
{
	return queue_clean_entry_work(CLEAN_TABLE, NULL, 0);
}

static int clean_entry_workqueue_init(void)
{
    clean_entry_wq = alloc_workqueue("clean_entry_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
    if (!clean_entry_wq)
        return -ENOMEM;
    return 0;
}

static void clean_entry_workqueue_exit(void)
{
    if (clean_entry_wq)
        destroy_workqueue(clean_entry_wq);
}

void airoha_ppe_hook_init(void)
{
	clean_entry_workqueue_init();

	rcu_assign_pointer(ra_sw_nat_hook_drop_packet, airoha_ppe_drop_packet_handler);
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_gemport, clean_entry_by_gemport_hook);
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_channel, clean_entry_by_channel_hook);
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_mac, clean_entry_by_mac_hook);
	rcu_assign_pointer(hwnat_clean_entry_by_src_mac_hook, clean_entry_by_src_mac_hook);
	rcu_assign_pointer(hwnat_clean_entry_by_dst_mac_hook, clean_entry_by_dst_mac_hook);
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_ip, clean_entry_by_ip_hook);
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_type, clean_entry_by_type_hook);
	rcu_assign_pointer(ra_sw_nat_hook_clean_multicast_entry, clean_multicast_entry_hook);
	rcu_assign_pointer(ra_sw_nat_hook_foeentry, airoha_ppe_foe_entry_handler);
	rcu_assign_pointer(hwnat_delete_foe_entry_hook_unlock, airoha_ppe_delete_foe_entry_unlock);
	rcu_assign_pointer(hwnat_set_bind_threshold_hook, airoha_ppe_set_bind_threshold);
	rcu_assign_pointer(hwnat_set_multicast_vlan_hook, airoha_ppe_set_multicast_vlan);
	rcu_assign_pointer(hwnat_is_multicast_entry_hook, airoha_ppe_is_multicast_entry);
	rcu_assign_pointer(hwnat_is_drop_entry_hook, airoha_ppe_is_drop_entry);
	rcu_assign_pointer(hwnat_set_special_tag_hook, airoha_ppe_set_special_tag);
	rcu_assign_pointer(multicast_flood_is_bind_hook, airoha_ppe_check_entry_is_bind);
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_landev, clean_entry_by_landev_hook);    
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_fport_and_channel, clean_entry_by_fport_and_channel_hook);
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_port, clean_entry_by_port_hook);
    
	return ;
}

void airoha_ppe_hook_exit(void)
{
	rcu_assign_pointer(ra_sw_nat_hook_drop_packet, NULL);
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_gemport, NULL);
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_channel, NULL);
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_mac, NULL);
	rcu_assign_pointer(hwnat_clean_entry_by_src_mac_hook, NULL);
	rcu_assign_pointer(hwnat_clean_entry_by_dst_mac_hook, NULL);
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_ip, NULL);
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_type, NULL);
	rcu_assign_pointer(ra_sw_nat_hook_clean_multicast_entry, NULL);	
	rcu_assign_pointer(ra_sw_nat_hook_foeentry, NULL);
	rcu_assign_pointer(hwnat_delete_foe_entry_hook_unlock, NULL);
	rcu_assign_pointer(hwnat_set_bind_threshold_hook, NULL);
	rcu_assign_pointer(hwnat_set_multicast_vlan_hook, NULL);
	rcu_assign_pointer(hwnat_is_multicast_entry_hook, NULL);
	rcu_assign_pointer(hwnat_is_drop_entry_hook, NULL);
	rcu_assign_pointer(hwnat_set_special_tag_hook, NULL);
	rcu_assign_pointer(multicast_flood_is_bind_hook, NULL);
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_landev, NULL);
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_fport_and_channel, NULL);
	rcu_assign_pointer(ra_sw_nat_hook_clean_entry_by_port, NULL);

	clean_entry_workqueue_exit();
	return ;
}

void PpeClearEntryInfo(struct airoha_foe_entry *foe_entry)
{
	char *foe_entry_point = (char *)foe_entry;

	if (FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1) == PPE_PKT_TYPE_BRIDGE)
	{	
		memset(foe_entry_point+PPE_CLEAR_OFFSET4, 0, SIZE_OF_FOE_ENTRY-PPE_CLEAR_OFFSET4);
	}
	else if (FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1) == PPE_PKT_TYPE_IPV4_DSLITE)
	{	
		memset(foe_entry_point+PPE_CLEAR_OFFSET1, 0, SIZE_OF_FOE_ENTRY-PPE_CLEAR_OFFSET4);
	}
	else if ((FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1) == PPE_PKT_TYPE_IPV4_HNAPT) ||
		(FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1) == PPE_PKT_TYPE_IPV4_ROUTE) ||
		(FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1) == PPE_PKT_TYPE_BRIDGE))
	{	
		memset(foe_entry_point+PPE_CLEAR_OFFSET1, 0, SIZE_OF_FOE_ENTRY-PPE_CLEAR_OFFSET1);
	}
	else if((FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1) == PPE_PKT_TYPE_IPV6_ROUTE_3T) ||
		(FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1) == PPE_PKT_TYPE_IPV6_ROUTE_5T))
	{
		memset(foe_entry_point+PPE_CLEAR_OFFSET2, 0, SIZE_OF_FOE_ENTRY-PPE_CLEAR_OFFSET2);
	}
	else if((FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1) == PPE_PKT_TYPE_IPV4_DSLITE) ||
		(FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1) == PPE_PKT_TYPE_IPV6_6RD))
	{
        memset(foe_entry_point+PPE_CLEAR_OFFSET3, 0, SIZE_OF_FOE_ENTRY-PPE_CLEAR_OFFSET3);
	}
	else
	{
		printk("HNAT: unknow packet type\n");
	}
}

int ppe_entry_is_valid(u32 foe_entry_idx, int ring_idx)
{
	struct airoha_foe_entry *hwe = NULL;
    int ptype = 0, cur_state = 0, cur_nbq = 0;

	hwe = airoha_ppe_foe_get_entry_locked(glb_eth->ppe, foe_entry_idx);;
	if(hwe == NULL){
		return -1;
	}

    ptype = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, hwe->ib1);
    cur_state = FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, hwe->ib1);

    if (PPE_PKT_TYPE_IPV4_HNAPT == ptype){
        cur_nbq = FIELD_GET(AIROHA_FOE_IB2_NBQ, hwe->ipv4.ib2);
    }else if (PPE_PKT_TYPE_IPV6_ROUTE_5T == ptype){
        cur_nbq = FIELD_GET(AIROHA_FOE_IB2_NBQ, hwe->ipv6.ib2);
    }else{
        return -1;
    }
    
    if((cur_state == AIROHA_FOE_STATE_INVALID) || (cur_nbq != (ring_idx <= LRO_RING_END ? ring_idx : ring_idx - LRO_RING_NUM)))
        return 1;
    else
        return 0;
}

void npu_get_entry_bind(struct sk_buff *skb, u32 hash, u32 reason)
{
	AIROHA_LOG(AIROHA_DEBUG_LEVEL_INFO, "Hash: %u\n", hash);
	if (hash < glb_eth->soc->ppe_sram_etry_num)
		skb_set_hash(skb, hash,
				 PKT_HASH_TYPE_L4);

	AIROHA_LOG(AIROHA_DEBUG_LEVEL_INFO, "CPU_REASON: %u\n", reason);
	if (reason == PPE_CPU_REASON_HIT_UNBIND_RATE_REACHED){
		struct airoha_flow_table_entry *flow_e = airoha_flow_table_entry_get_by_hash(glb_eth->ppe, hash);
		if(flow_e)
			flow_e->ingress_dev_idx = WIFI_DEV;			
		airoha_ppe_check_skb(&glb_eth->ppe->dev, skb, hash, false);
	}
}

void airoha_ppe_foe_flow_update_wifi_npu_offload(struct airoha_ppe *ppe, struct sk_buff *skb, struct port_info *pinfo)
{
	u32 hash = FOE_ENTRY_NUM(skb);
	int type;
	struct airoha_flow_table_entry *e;
	struct airoha_foe_entry *hwe;
	struct hlist_node *n;
	u32 index, data;
	unsigned int dscp = 0;
	unsigned int dscp_tmp = 0;
	int flow_table_enable = 0;

	AIROHA_LOG(AIROHA_DEBUG_LEVEL_INFO, "hash at wifi_tx: %u\n", hash);
	if ( !is_Valid_Foe_Entry(skb) ) {
		AIROHA_LOG(AIROHA_DEBUG_LEVEL_INFO, "Incorrect hash:%u\n", hash);
		return;
	}
	
	spin_lock_bh(&ppe_lock);
	hwe = airoha_ppe_foe_get_entry_locked(ppe, hash);
	if (!hwe)
	{
		goto unlock;
	}
	if ( fe_resource_mark_if_meter_hook ) {
		fe_resource_mark_if_meter_hook(skb, DOWN_STREAM);
	}
	
	type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, hwe->ib1);
	AIROHA_LOG(AIROHA_DEBUG_LEVEL_INFO, "Packet type:%d\n", type);
	index = airoha_ppe_foe_get_entry_hash(ppe, hwe);

	if(pinfo->magic == FOE_MAGIC_WLAN){
		switch (skb->protocol){
		case htons(ETH_P_IP):
			/* Fix NULL_RETURNS: validate network header is set and skb has
			 * enough data before calling ip_hdr(skb). ip_hdr() returns a
			 * pointer into skb data based on skb->network_header offset;
			 * if network_header is not properly set, this accesses wrong memory.
			 */
			if (skb_network_header_len(skb) >= sizeof(struct iphdr)) {
			dscp_tmp = ipv4_get_dsfield(ip_hdr(skb)) & 0xfc;
			dscp = dscp_tmp >> 2;
			}
			break;
		case htons(ETH_P_IPV6):
			/* Fix NULL_RETURNS: validate network header length for IPv6 header */
			if (skb_network_header_len(skb) >= sizeof(struct ipv6hdr)) {
			dscp_tmp = ipv6_get_dsfield(ipv6_hdr(skb)) & 0xfc;
			dscp = dscp_tmp >> 2;
			}
			break;
		default:
			break;
		}
	}

	hlist_for_each_entry_safe(e, n, &ppe->foe_flow[index], list) {
		if (airoha_ppe_foe_compare_entry(e, hwe)) {
			flow_table_enable = 1;
			if(e->tx_modified){
				goto unlock;
			}

			if(pinfo->magic == FOE_MAGIC_WLAN){
				/* Fix TAINTED_SCALAR: mask pinfo->udf and pinfo->tsid to their
				 * respective field widths (AIROHA_FOE_ACTDP = bits[31:24] = 8 bits,
				 * AIROHA_FOE_SHAPER_ID = bits[23:16] = 8 bits) before FIELD_PREP,
				 * preventing unexpected results if external values exceed field width.
				 */
				data = FIELD_PREP(AIROHA_FOE_ACTDP, (pinfo->udf & 0xFF)) |
				       FIELD_PREP(AIROHA_FOE_SHAPER_ID, (pinfo->tsid & 0xFF));

				switch (type) {
					case PPE_PKT_TYPE_IPV4_ROUTE:
					case PPE_PKT_TYPE_IPV4_HNAPT:
						e->data.ipv4.data = data;
						e->data.ipv4.l2.common.etype = pinfo->stag;
						e->data.ipv4.ib2 &= ~AIROHA_FOE_IB2_PSE_QOS;
						e->data.ipv4.ib2 &= ~AIROHA_FOE_IB2_NBQ;
						e->data.ipv4.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, pinfo->nbq);
						e->data.ipv4.ib2 &= ~AIROHA_FOE_IB2_DSCP;
						e->data.ipv4.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_DSCP, dscp);
						e->data.ipv4.ib2 &= ~AIROHA_FOE_IB2_PSE_PORT;
						e->data.ipv4.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_CDM4);		//TDMA
						break;
					
					case PPE_PKT_TYPE_BRIDGE:
						e->data.bridge.data = data;
						e->data.bridge.l2.common.etype = pinfo->stag;
						e->data.bridge.ib2 &= ~AIROHA_FOE_IB2_PSE_QOS;
						e->data.bridge.ib2 &= ~AIROHA_FOE_IB2_NBQ;
						e->data.bridge.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, pinfo->nbq);
						e->data.bridge.ib2 &= ~AIROHA_FOE_IB2_DSCP;
						e->data.bridge.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_DSCP, dscp);
						e->data.bridge.ib2 &= ~AIROHA_FOE_IB2_PSE_PORT;
						e->data.bridge.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_CDM4);
						break;
					
					case PPE_PKT_TYPE_IPV6_ROUTE_3T:
					case PPE_PKT_TYPE_IPV6_ROUTE_5T:
					case PPE_PKT_TYPE_IPV6_6RD:
						e->data.ipv6.data = data;
						e->data.ipv6.l2.etype = pinfo->stag;
						e->data.ipv6.ib2 &= ~AIROHA_FOE_IB2_PSE_QOS;
						e->data.ipv6.ib2 &= ~AIROHA_FOE_IB2_NBQ;
						e->data.ipv6.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, pinfo->nbq);
						e->data.ipv6.ib2 &= ~AIROHA_FOE_IB2_DSCP;
						e->data.ipv6.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_DSCP, dscp);
						e->data.ipv6.ib2 &= ~AIROHA_FOE_IB2_PSE_PORT;
						e->data.ipv6.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_CDM4);
						break;
						
					case PPE_PKT_TYPE_IPV4_DSLITE:
						e->data.dslite.data = data;
						e->data.dslite.l2.common.etype = pinfo->stag;
						e->data.dslite.ib2 &= ~AIROHA_FOE_IB2_PSE_QOS;
						e->data.dslite.ib2 &= ~AIROHA_FOE_IB2_NBQ;
						e->data.dslite.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, pinfo->nbq);
						e->data.dslite.ib2 &= ~AIROHA_FOE_IB2_DSCP;
						e->data.dslite.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_DSCP, dscp);
						e->data.dslite.ib2 &= ~AIROHA_FOE_IB2_PSE_PORT;
						e->data.dslite.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_CDM4);
						break;
						
					default:
						break;
				}
				{
					u32 pkt_type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, e->data.ib1);
					struct airoha_foe_mac_info_common *l2;
	
					if (pkt_type == PPE_PKT_TYPE_BRIDGE)
						l2 = &e->data.bridge.l2.common;
					else if (pkt_type >= PPE_PKT_TYPE_IPV6_ROUTE_3T)
						l2 = &e->data.ipv6.l2;
					else
						l2 = &e->data.ipv4.l2.common;
	
				}

				/* Fix OVERRUN: verify skb linear data contains at least 2*ETH_ALEN
				 * (12) bytes before passing skb->data and skb->data+ETH_ALEN as
				 * src/dst MAC address pointers to airoha_set_ppe_mac(), which reads
				 * 6 bytes from each pointer via get_unaligned_be32/be16.
				 */
				if (skb_headlen(skb) < 2 * ETH_ALEN) {
					AIROHA_LOG(AIROHA_DEBUG_LEVEL_ERR,
						"wifi npu offload: skb headlen %u too short for MAC read (need %u)\n",
						skb_headlen(skb), 2 * ETH_ALEN);
					goto unlock;
				}
					airoha_set_ppe_mac(&e->data,skb->dev,skb->data+ETH_ALEN,skb->data,0);
			}
			if ( ra_sw_nat_update_acnt_info_hook ) {
				ra_sw_nat_update_acnt_info_hook(&e->data, skb, pinfo, FE_PSE_PORT_CDM4);
			}
			e->tx_modified = true;
		}
	}

unlock:
	spin_unlock_bh(&ppe_lock);

	if(flow_table_enable == 0)
	{
		airoha_ppe_tx_handler(skb, pinfo, FE_PSE_PORT_CDM4);
	}
}

struct airoha_flow_table_entry *airoha_flow_table_entry_get_by_hash(struct airoha_ppe *ppe, u32 hash)
{
	struct airoha_flow_table_entry *e;
	struct airoha_foe_entry *hwe = NULL;
	struct hlist_node *n;
	u32 index = 0;
	if (hash > PPE_HASH_MASK)
		return NULL;

	hwe = airoha_ppe_foe_get_entry(ppe, hash);
	if (!hwe)
		return NULL;
	index = airoha_ppe_foe_get_entry_hash(ppe, hwe);
	hlist_for_each_entry_safe(e, n, &ppe->foe_flow[index], list) {
		if(airoha_ppe_foe_compare_entry(e, hwe))
			return e;
	}
	return NULL;
}

int __airoha_ppe_foe_commit_entry(struct airoha_ppe *ppe, u32 hash)
{
	int ret = -1;
	int sram_entries_num = ppe->eth->soc->ppe_sram_etry_num;
	
	lockdep_assert_held(&ppe_lock);
	spin_lock_bh(&ppe_sram_access_lock);
        if (likely(hash < sram_entries_num)) {
			u32 *hwe = ppe->foe + hash * sizeof(struct airoha_foe_entry);
			struct airoha_eth *eth = ppe->eth;
			bool ppe2;
			u32 val;
			int i;

			ppe2 = (eth->soc->num_ppe == 2) &&  hash >= PPE_SRAM_NUM_ENTRIES;

			for (i = 0; i < sizeof(struct airoha_foe_entry) / 4; i++)
				airoha_fe_wr(eth, REG_PPE_RAM_ENTRY(ppe2, i), hwe[i]);

			wmb();
			airoha_fe_wr(ppe->eth, REG_PPE_RAM_CTRL(ppe2),
									FIELD_PREP(PPE_SRAM_CTRL_ENTRY_MASK, hash) |
						PPE_SRAM_CTRL_WR_MASK |
									PPE_SRAM_CTRL_REQ_MASK);
			ret = read_poll_timeout_atomic(airoha_fe_rr, val,
													val & PPE_SRAM_CTRL_ACK_MASK,
													10, 100, false, eth,
													REG_PPE_RAM_CTRL(ppe2));
	}

	spin_unlock_bh(&ppe_sram_access_lock);
	return ret;
}

void airoha_set_flow_destination(struct net_device *dev, struct airoha_flow_table_entry *e)
{
        if(!dev || !e){
                return;
        }
        AIROHA_LOG(AIROHA_DEBUG_LEVEL_ERR, "device is %s\n",dev->name);

        if(airoha_ppe_is_pon_dev(dev)){
                AIROHA_LOG(AIROHA_DEBUG_LEVEL_ERR, "destination set to PON\n");
                e->e_magic = PON;
        }
		
		if(airoha_get_lan_id(dev))
		{
			AIROHA_LOG(AIROHA_DEBUG_LEVEL_ERR, "destination set to ETH\n");
            e->e_magic = airoha_get_lan_id(dev);
		}

        return;
}

void airoha_ppe_clear_sram_table_flow(struct airoha_ppe *ppe,uint entry_idx)
{
	int sram_num_entries = ppe->eth->soc->ppe_sram_etry_num;
	struct airoha_foe_entry *hwe = ppe->foe;
	
	if(entry_idx >= sram_num_entries){
		printk("\n Clear specific sram ppe rule - Over PPE_SRAM_NUM_ENTRIES:%d / entry_idx: %u \n",PPE_SRAM_NUM_ENTRIES,entry_idx);
		return;
	}else{

		printk("\n Clear specific sram ppe rule - entry_idx: %u Clear hwe rule\n",entry_idx);
		memset(&hwe[entry_idx], 0, sizeof(*hwe));
		printk("\n Clear specific sram ppe rule - entry_idx: %u Clear SRAM rule\n",entry_idx);
		__airoha_ppe_foe_commit_entry(ppe,entry_idx);
		return;
	}
	return;

}

void airoha_ppe_clear_sram_table_all(struct airoha_ppe *ppe)
{
	int i, sram_num_entries = ppe->eth->soc->ppe_sram_etry_num;
	struct airoha_foe_entry *hwe = ppe->foe;

	for (i = 0; i < sram_num_entries; i++){
		memset(&hwe[i], 0, sizeof(*hwe));
		
		if (foe_ext)
			foe_ext[i].fe_resource_mark = 0;
		
		__airoha_ppe_foe_commit_entry(ppe, i);
	}

	return;

}

void airoha_ppe_clean_sram_table(void)
{
	if(glb_eth == NULL){
		return;
	}

	spin_lock_bh(&ppe_lock);
	airoha_ppe_clear_sram_table_all(glb_eth->ppe);
	spin_unlock_bh(&ppe_lock);
	
	return;
}

void airoha_ppe_delete_entry(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, uint entry_idx)
{
	hwe->ib1 &= ~AIROHA_FOE_IB1_BIND_STATE;
	hwe->ib1 |= FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_INVALID);
	
	airoha_ppe_foe_commit_entry(ppe, hwe, entry_idx, false);
	foe_ext[entry_idx].lan_ifindex = 0;
	return;
}

int airoha_get_foe_from_skb(struct sk_buff * skb)
{
	u32 foe_entry_idx= 0;
	foe_entry_idx = FOE_ENTRY_NUM(skb);
	if ( !is_Valid_Foe_Entry(skb) ) {
		return -1;
	}
	return foe_entry_idx;
}


static void airoha_pon_ppe_init_upd_mem(const u8 *addr)
{
	u32 val;
	struct airoha_eth *eth = glb_eth;
	
	val = (addr[2] << 24) | (addr[3] << 16) | (addr[4] <<8) | addr[5];
	airoha_fe_wr(eth, REG_UPDMEM_DATA(0), val);
	airoha_fe_wr(eth, REG_UPDMEM_CTRL(0),
		     FIELD_PREP(PPE_UPDMEM_ADDR_MASK,SMAC_PON_IDX) |
		     PPE_UPDMEM_WR_MASK | PPE_UPDMEM_REQ_MASK);
	val = (addr[0] << 8) | addr[1];
	airoha_fe_wr(eth, REG_UPDMEM_DATA(0), val);
	airoha_fe_wr(eth, REG_UPDMEM_CTRL(0),
		     FIELD_PREP(PPE_UPDMEM_ADDR_MASK, SMAC_PON_IDX) |
		     FIELD_PREP(PPE_UPDMEM_OFFSET_MASK, 1) |
		     PPE_UPDMEM_WR_MASK | PPE_UPDMEM_REQ_MASK);
	UpdateShrinkTable(SMAC_PON_IDX,addr);
}

void airoha_pon_set_macaddr(const u8 *addr)
{
	u32 val, reg;
	struct airoha_eth *eth = glb_eth;

	reg = REG_FE_WAN_MAC_H;
	val = (addr[0] << 16) | (addr[1] << 8) | addr[2];
	airoha_fe_wr(eth, reg, val);

	val = (addr[3] << 16) | (addr[4] << 8) | addr[5];
	airoha_fe_wr(eth, REG_FE_MAC_LMIN(reg), val);
	airoha_fe_wr(eth, REG_FE_MAC_LMAX(reg), val + AIROHA_MAC_ADDR_NUM);
	airoha_pon_ppe_init_upd_mem(addr);
}
EXPORT_SYMBOL(airoha_pon_set_macaddr);

int arht_ppe_multicast_set_valid(struct sk_buff* skb)
{
	unsigned int foe_index = FOE_ENTRY_NUM(skb);

	if(arht_multicast_hwnat_set_valid_hook)
	{
		if(foe_index < glb_eth->soc->ppe_sram_etry_num)
		{
			arht_multicast_hwnat_set_valid_hook(foe_index);
		}
	}
	return 0;
}
EXPORT_SYMBOL(arht_ppe_multicast_set_valid);

int airoha_get_ppe_entry_state(unsigned int foe_index)
{
	if(glb_eth == NULL)
		return 0;
	
	struct airoha_ppe *ppe = glb_eth->ppe;
	struct airoha_foe_entry *hwe = NULL;
	
	hwe = airoha_ppe_foe_get_entry_locked(ppe, foe_index);

	if(hwe == NULL)
		return 0;
	
	return FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, hwe->ib1);
}
EXPORT_SYMBOL(airoha_get_ppe_entry_state);

static int arht_ppe_multicast_get_valid(unsigned int foe_index)
{
	if(arht_multicast_hwnat_get_valid_hook)
	{
		return arht_multicast_hwnat_get_valid_hook(foe_index);
	}
	return 0;
}

static int arht_multicast_match_foe_flow(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe)
{
	struct airoha_flow_table_entry *e;
	struct hlist_node *n;
	int i;

	for (i = 0; i < PPE_NUM_ENTRIES; i++) {
		hlist_for_each_entry_safe(e, n, &ppe->foe_flow[i], list) {
			int type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, e->data.ib1);
			switch (type) {
			case PPE_PKT_TYPE_IPV4_HNAPT:
				if(hwe->ipv4.orig_tuple.src_ip == e->data.ipv4.orig_tuple.src_ip &&
					hwe->ipv4.orig_tuple.dest_ip == e->data.ipv4.orig_tuple.dest_ip)
					return 1;
				break;
			case PPE_PKT_TYPE_IPV6_ROUTE_5T:
				if(0 == memcmp(&hwe->ipv6, &e->data.ipv6, 32))
					return 1;
				break;
			default:
				break;
			}
		}
	}

	return 0;
}

int arht_ppe_multicast_check_valid(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, unsigned int foe_index)
{
	if(arht_ppe_multicast_get_valid(foe_index) == HWNAT_MCAST_VALID)
		return 1;

	return arht_multicast_match_foe_flow(ppe, hwe);
}

static int setMcastDstMacv4(unsigned char *mac_hdr, struct airoha_foe_entry *foe_entry)
{
	mac_hdr[0] = 0x01;
	mac_hdr[1] = 0x00;
	mac_hdr[2] = 0x5e;
	mac_hdr[3] = ((foe_entry->ipv4.orig_tuple.dest_ip & 0xff0000) >> 16);
	mac_hdr[4] = ((foe_entry->ipv4.orig_tuple.dest_ip & 0xff00) >> 8);
	mac_hdr[5] = (foe_entry->ipv4.orig_tuple.dest_ip & 0xff);

	return 0;
}

static int setMcastDstMacv6(unsigned char *mac_hdr, struct airoha_foe_entry *foe_entry)
{
	mac_hdr[0] = 0x33;
	mac_hdr[1] = 0x33;
	mac_hdr[2] = ((foe_entry->ipv6.dest_ip[3] & 0xff000000) >> 24);
	mac_hdr[3] = ((foe_entry->ipv6.dest_ip[3] & 0xff0000) >> 16);
	mac_hdr[4] = ((foe_entry->ipv6.dest_ip[3] & 0xff00) >> 8);
	mac_hdr[5] = (foe_entry->ipv6.dest_ip[3] & 0xff);

	return 0;
}

static void FoeSetEntrySrcMac(uint8_t * Dst, u32 * Src_hi, u16 * Src_lo)
{
	*Src_hi = (Dst[6] << 24) | (Dst[7] << 16) | (Dst[8] << 8) | Dst[9];
    *Src_lo = (Dst[10] << 8) | Dst[11];
}

int32_t PpeFillInL2Info(struct sk_buff * skb, struct airoha_foe_entry *foe_entry)
{
	unsigned char *mac_hdr;
    //int pkt_type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1);
	//if this entry is already in binding state, skip it 
	if (FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, foe_entry->ib1) == AIROHA_FOE_STATE_BIND) {
		return 1;
	}

	if (skb_mac_header_was_set(skb)) {
		mac_hdr = skb_mac_header(skb);
	} else {
		skb_reset_mac_header(skb);
		mac_hdr = skb_mac_header(skb);
	}
    
	/* Set VLAN Info - VLAN1/VLAN2 */
	/* Set Layer2 Info - DMAC, SMAC */
	if (IS_IPV4_GRP(foe_entry)) {
		setMcastDstMacv4(mac_hdr,foe_entry);
		if(FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, foe_entry->ib1) == PPE_PKT_TYPE_IPV4_DSLITE) { //DS-Lite WAN->LAN
            FoeSetEntrySrcMac(mac_hdr, &(foe_entry->dslite.l2.common.src_mac_hi),&(foe_entry->dslite.l2.src_mac_lo));
            FoeSetEntryMac(mac_hdr,&(foe_entry->dslite.l2.common.dest_mac_hi),&(foe_entry->dslite.l2.common.dest_mac_lo));
		}else { //IPv4 WAN<->LAN
            FoeSetEntryMac(mac_hdr, &(foe_entry->ipv4.l2.common.dest_mac_hi), &(foe_entry->ipv4.l2.common.dest_mac_lo));
            FoeSetEntrySrcMac(mac_hdr, &(foe_entry->ipv4.l2.common.src_mac_hi), &(foe_entry->ipv4.l2.src_mac_lo));
		}
		if(airoha_is_pon_sfu_mode()){
			ppe_set_vlan_info(foe_entry,skb);
		}
	}
	else if(IS_IPV6_GRP(foe_entry)){
		setMcastDstMacv6(mac_hdr,foe_entry);
		// if smac doesn't change,then smac_idx[4]=1; else, smac_idx[3:0] =0~15
		set_ppe_entry_smac_index(foe_entry, PPE_PKT_TYPE_IPV6_ROUTE_5T, 0x10);
		
        FoeSetEntryMac(mac_hdr,&(foe_entry->ipv6.l2.dest_mac_hi), &(foe_entry->ipv6.l2.dest_mac_lo));

		if(airoha_is_pon_sfu_mode()){
			ppe_set_vlan_info(foe_entry,skb);
		}
	}

	return 0;
}

int32_t PpeFillInL3Info(struct sk_buff * skb, struct airoha_foe_entry *foe_entry)
{
	/* IPv4 */
	if (IS_IPV4_GRP(foe_entry)) {
		foe_entry->ipv4.new_tuple.src_ip = foe_entry->ipv4.orig_tuple.src_ip;
		foe_entry->ipv4.new_tuple.dest_ip = foe_entry->ipv4.orig_tuple.dest_ip;
	}
	else {
		//do nothing
		return 1;
	}

	return 0;
}

u32 arht_ppe_foe_entry_set_qdata(struct airoha_gdm_dev *dev, struct net_device *netdev, u32 qdata, u32 priority,int dsa_port)
{
	u32 qid, channel;
	u32 tag = 0;

	if (dsa_port >= 0 && dsa_port < 32)
		tag = 1U << dsa_port;

	channel = dev->qdma->eth->extra_ops.get_qdma_channel(dev, tag);
	channel = channel % AIROHA_MAX_NUM_CHANNELS;

	priority = priority % AIROHA_NUM_QOS_QUEUES;
	qid = (AIROHA_NUM_QOS_QUEUES - 1) - priority;
	qdata |= FIELD_PREP(AIROHA_FOE_CHANNEL, channel) |
			FIELD_PREP(AIROHA_FOE_QID, qid);
	return qdata;
}

u32 arht_ppe_foe_entry_set_fastpath(struct airoha_eth *eth,struct airoha_gdm_dev *dev,u32 val,int dsa_port)
{
	int id = dev->qdma - &eth->qdma[0];
	if (dsa_port >= 0) {
		if (eth->qdma_init.lan_fastpath == 1) {
			val |= AIROHA_FOE_IB2_FAST_PATH;
		} else {
			val &= ~AIROHA_FOE_IB2_FAST_PATH;
		}
	}
	else {
		if(id == 0) {
			if(eth->qdma_init.xsi_ether_fastpath == 1) {
				val |= AIROHA_FOE_IB2_FAST_PATH;
			} else {
				val &= ~AIROHA_FOE_IB2_FAST_PATH;
			}
		}
		else if (id == 1) {
			if(eth->qdma_init.wan_fastpath == 1) {
				val |= AIROHA_FOE_IB2_FAST_PATH;
			} else {
				val &= ~AIROHA_FOE_IB2_FAST_PATH;
			}
		}
	}
	return val;
}

void arht_modified_ppe_entry(struct airoha_foe_entry *hwe, struct net_device *netdev,
						struct airoha_flow_data *data, u32 priority, int dsa_port)
{
	u32 *qdata, *val;

	if (!hwe || !netdev || !data) {
		return;
	}
	if (!glb_eth) {
		return;
	}

	if (airoha_ppe_is_wifi_dev(netdev)) {
	    airoha_set_ppe_mac(hwe, netdev, data->eth.h_source, data->eth.h_dest, data->pppoe.sid);
	    return; 
	}

	struct airoha_gdm_dev *dev = airoha_ppe_get_gdm_dev(glb_eth, netdev);
	if (!dev || !airoha_is_valid_gdm_dev(glb_eth, dev)) {
		return;
	}

	if (!dev->qdma || !dev->qdma->eth || !dev->qdma->eth->extra_ops.get_qdma_channel || !dev->port) {
		return;
	}

	int type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, hwe->ib1);
	if (type == PPE_PKT_TYPE_BRIDGE) {
		qdata = &hwe->bridge.data;
		val = &hwe->bridge.ib2;
	} else if (type >= PPE_PKT_TYPE_IPV6_ROUTE_3T) {
		qdata = &hwe->ipv6.data;
		val = &hwe->ipv6.ib2;
	} else {
		qdata = &hwe->ipv4.data;
		val = &hwe->ipv4.ib2;
	}

	if (priority > 0xFFFF) {
		return;
	}

	*qdata = arht_ppe_foe_entry_set_qdata(dev, netdev, *qdata, priority, dsa_port);
	*val = arht_ppe_foe_entry_set_fastpath(glb_eth, dev, *val, dsa_port);

	airoha_set_ppe_mac(hwe, netdev, data->eth.h_source, data->eth.h_dest, data->pppoe.sid);
}
int arht_tx_modified(struct airoha_flow_table_entry *e, u32 hash){
	if(!(e->tx_modified))
		return 1;

	return 0;

}


/************************************************************************
 *                  L2B Ether Type Configuration Functions
 ************************************************************************/

/**
 * ppe_get_l2b_ether_type() - Read L2 bridge ether type value at given index
 * @index: Index of the ether type entry (0-15)
 *
 * This function reads the ether type value at the specified index.
 * Each register holds two 16-bit ether type values.
 *
 * Return: The 16-bit ether type value, or 0 on error
 */
static u16 ppe_get_l2b_ether_type(unsigned int index)
{
	unsigned int val, shift;

	if (!glb_eth || index > 15)
		return 0;

	shift = 16 * (index % 2);
	val = airoha_fe_rr(glb_eth, REG_PPE_L2B_ETYPE_N(0, index));

	return (val >> shift) & 0xffff;
}

/**
 * ppe_is_l2b_ether_type_enabled() - Check if L2B ether type entry is enabled
 * @index: Index of the ether type entry (0-15)
 *
 * REG_PPE_L2B_ETYPE_EN register format:
 *   bit[15:0]  = enable bits (one per index)
 *   bit[31:16] = pppoe bits (one per index, indicates if entry is PPPoE type)
 *
 * Return: true if enabled (bit[index] is set), false otherwise
 */
static bool ppe_is_l2b_ether_type_enabled(unsigned int index)
{
	unsigned int val;

	if (!glb_eth || index > 15)
		return false;

	val = airoha_fe_rr(glb_eth, REG_PPE_L2B_ETYPE_EN(0));

	return !!(val & BIT(index));
}

/**
 * ppe_is_l2b_ether_type_pppoe() - Check if L2B ether type entry is PPPoE type
 * @index: Index of the ether type entry (0-15)
 *
 * Return: true if PPPoE bit is set (bit[index+16]), false otherwise
 */
static bool ppe_is_l2b_ether_type_pppoe(unsigned int index)
{
	unsigned int val;

	if (!glb_eth || index > 15)
		return false;

	val = airoha_fe_rr(glb_eth, REG_PPE_L2B_ETYPE_EN(0));

	return !!(val & BIT(index + 16));
}

/**
 * ppe_find_l2b_ether_type_index() - Find index of existing ether type value
 * @etype: The ether type value to search for (e.g., 0x0800, 0x86dd)
 * @is_pppoe: Whether to search PPPoE (1) or regular Ethernet (0) entries
 *
 * Searches all L2B ether type entries to find if the specified value
 * already exists and is enabled with matching PPPoE type.
 *
 * Return: Index (0-15) if found and enabled, -ENOENT if not found
 */
static int ppe_find_l2b_ether_type_index(u16 etype, unsigned int is_pppoe)
{
	int i;

	for (i = 0; i < L2B_ETYPE_MAX_INDEX; i++) {
		if (ppe_is_l2b_ether_type_enabled(i) &&
		    ppe_get_l2b_ether_type(i) == etype &&
		    ppe_is_l2b_ether_type_pppoe(i) == !!is_pppoe)
			return i;
	}

	return -ENOENT;
}

/**
 * ppe_find_free_l2b_ether_type_index() - Find a free L2B ether type index
 * @is_pppoe: Whether to find free index for PPPoE (1) or regular Ethernet (0)
 *            (unused, kept for API compatibility)
 *
 * Searches from index 0 to find an unused L2B ether type entry.
 * An entry is considered free only if:
 * 1. The enable bit is NOT set, AND
 * 2. The ether type value is 0
 *
 * This ensures we don't overwrite hardware default values (e.g., 0x8100, 0x88a8)
 * that may exist in registers even when not enabled.
 *
 * Return: Free index (0-15) on success, -ENOSPC if no free entry
 */
static int ppe_find_free_l2b_ether_type_index(unsigned int is_pppoe)
{
	int i;

	for (i = 0; i < L2B_ETYPE_MAX_INDEX; i++) {
		/* Entry is free only if not enabled AND has zero value */
		if (!ppe_is_l2b_ether_type_enabled(i) &&
		    ppe_get_l2b_ether_type(i) == 0)
			return i;
	}

	return -ENOSPC;
}

/**
 * ppe_set_l2b_ether_type() - Configure L2 bridge ether type filtering
 * @index: Index of the ether type entry (0-15)
 * @enable: Enable (1) or disable (0) this ether type filter
 * @is_pppoe: Whether this is a PPPoE ether type (1) or regular Ethernet (0)
 * @value: The ether type value to configure
 *
 * This function configures the L2 bridge ether type filtering in the PPE.
 * REG_PPE_L2B_ETYPE_EN register format:
 *   bit[15:0]  = enable bits (one per index, controls if entry is active)
 *   bit[31:16] = pppoe bits (one per index, indicates if entry is PPPoE type)
 *
 * For PPPoE entries, both enable bit and pppoe bit must be set.
 * Each L2B_ETYPE register holds two 16-bit ether type values.
 *
 * Return: 0 on success, negative error code on failure
 */
static int ppe_set_l2b_ether_type(unsigned int index, unsigned int enable,
			   unsigned int is_pppoe, unsigned int value)
{
	unsigned int val, type, shift;
	unsigned int enable_bit, pppoe_bit;

	if (!glb_eth)
		return -ENODEV;

	if (index > 15) {
		pr_err("%s: invalid index %u, must be 0-15\n", __func__, index);
		return -EINVAL;
	}

	enable_bit = BIT(index);        /* bit[index] for enable */
	pppoe_bit = BIT(index + 16);    /* bit[index+16] for pppoe flag */

	/* Update enable register */
	val = airoha_fe_rr(glb_eth, REG_PPE_L2B_ETYPE_EN(0));
	if (enable) {
		val |= enable_bit;          /* Always set enable bit */
		if (is_pppoe)
			val |= pppoe_bit;   /* Set pppoe bit if PPPoE type */
		else
			val &= ~pppoe_bit;  /* Clear pppoe bit if not PPPoE */
	} else {
		val &= ~enable_bit;         /* Clear enable bit */
		val &= ~pppoe_bit;          /* Clear pppoe bit */
	}

	airoha_fe_wr(glb_eth, REG_PPE_L2B_ETYPE_EN(0), val);
	if (airoha_is_7581(glb_eth))
		airoha_fe_wr(glb_eth, REG_PPE_L2B_ETYPE_EN(1), val);

	/* Update ether type value: each register holds two 16-bit values */
	shift = 16 * (index % 2);
	type = airoha_fe_rr(glb_eth, REG_PPE_L2B_ETYPE_N(0, index));
	type &= ~(0xffff << shift);
	type |= (value & 0xffff) << shift;

	airoha_fe_wr(glb_eth, REG_PPE_L2B_ETYPE_N(0, index), type);
	if (airoha_is_7581(glb_eth))
		airoha_fe_wr(glb_eth, REG_PPE_L2B_ETYPE_N(1, index), type);

	return 0;
}

/**
 * ppe_set_l2b_ether_type_auto() - Auto-configure L2B ether type with free index
 * @etype: The ether type value to configure (e.g., 0x0800 for IPv4, 0x86dd for IPv6)
 * @is_pppoe: Whether this is a PPPoE ether type (1) or regular Ethernet (0)
 * @existed: Pointer to return whether the entry already existed (can be NULL)
 *
 * This function automatically finds an appropriate index for the ether type:
 * 1. First checks if the ether type already exists and is enabled
 * 2. If not found, searches for a free entry from index 0
 * 3. Configures the entry if a free slot is found
 *
 * Return: The index used (>= 0) on success, negative error code on failure
 *         -ENODEV: Device not initialized
 *         -ENOSPC: No free entry available
 */
int ppe_set_l2b_ether_type_auto(u16 etype, unsigned int is_pppoe, bool *existed)
{
	int idx, ret;
	bool entry_existed = false;

	if (!glb_eth)
		return -ENODEV;

	/* First check if this ether type already exists and is enabled */
	idx = ppe_find_l2b_ether_type_index(etype, is_pppoe);
	if (idx >= 0) {
		entry_existed = true;
		pr_info("L2B etype 0x%04x (pppoe=%u) already exists at index %d, skip configuration\n",
			etype, is_pppoe, idx);
		goto out;
	}

	/* Find a free entry */
	idx = ppe_find_free_l2b_ether_type_index(is_pppoe);
	if (idx < 0) {
		pr_err("No free L2B ether type entry for 0x%04x (pppoe=%u)\n",
		       etype, is_pppoe);
		return -ENOSPC;
	}

	/* Configure the entry */
	ret = ppe_set_l2b_ether_type(idx, 1, is_pppoe, etype);
	if (ret)
		return ret;

	pr_info("L2B etype 0x%04x (pppoe=%u) configured at index %d\n",
		etype, is_pppoe, idx);

out:
	if (existed)
		*existed = entry_existed;
	return idx;
}

/**
 * ppe_clear_l2b_ether_type_auto() - Clear L2B ether type entry by value
 * @etype: The ether type value to clear (e.g., 0x0800 for IPv4, 0x86dd for IPv6)
 * @is_pppoe: Whether this is a PPPoE ether type (1) or regular Ethernet (0)
 *
 * This function finds and clears the L2B ether type entry matching the given value.
 * If the ether type is not found in the blacklist, it returns success (idempotent).
 *
 * Return: 0 on success, negative error code on failure
 *         -ENODEV: Device not initialized
 */
int ppe_clear_l2b_ether_type_auto(u16 etype, unsigned int is_pppoe)
{
	int idx, ret;

	if (!glb_eth)
		return -ENODEV;

	/* Find the entry with this ether type */
	idx = ppe_find_l2b_ether_type_index(etype, is_pppoe);
	if (idx < 0) {
		/* Entry not found, nothing to clear - this is OK (idempotent) */
		pr_debug("L2B etype 0x%04x (pppoe=%u) not found, nothing to clear\n",
			 etype, is_pppoe);
		return 0;
	}

	/* Clear the entry */
	ret = ppe_set_l2b_ether_type(idx, 0, is_pppoe, 0);
	if (ret) {
		pr_warn("Failed to clear L2B etype 0x%04x (pppoe=%u) at index %d\n",
			etype, is_pppoe, idx);
		return ret;
	}

	pr_info("L2B etype 0x%04x (pppoe=%u) cleared from index %d\n",
		etype, is_pppoe, idx);
	return 0;
}

static int airoha_ppe_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	if(!dev)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UNREGISTER:
		airoha_ppe_clean_entry_by_landev(dev);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block airoha_ppe_netdev_nb = {
	.notifier_call = airoha_ppe_netdev_event,
};

void arht_ppe_init(struct airoha_ppe *ppe)
{
	/*clear all sram ppe table*/
	airoha_ppe_clear_sram_table_all(ppe);

	rcu_assign_pointer(offload_eth_fast_tx_hook, airoha_eth_fast_tx);
	rcu_assign_pointer(ra_sw_nat_hook_sendto_ppe, SendToPpe);
	rcu_assign_pointer(hwnat_skb_to_foe_hook, airoha_get_foe_from_skb);
	rcu_assign_pointer(hwnat_delete_foe_entry_hook, airoha_ppe_delete_entry);
	rcu_assign_pointer(ra_sw_nat_hook_clean_table, clean_entry_all_sram_table);
	rcu_assign_pointer(get_tr471_rx_msg_hook,qdma_get_tr471_rxmsg);
	airoha_ppe_hook_init();
	arht_ppe_general_init(ppe);
	airoha_hwnat_loopback_init();

	register_netdevice_notifier(&airoha_ppe_netdev_nb);
}

void arht_ppe_deinit(void)
{
	rcu_assign_pointer(offload_eth_fast_tx_hook, NULL);
	rcu_assign_pointer(ra_sw_nat_hook_sendto_ppe, NULL);
	rcu_assign_pointer(hwnat_skb_to_foe_hook, NULL);
	rcu_assign_pointer(hwnat_delete_foe_entry_hook, NULL);
	rcu_assign_pointer(get_tr471_rx_msg_hook,NULL);
	rcu_assign_pointer(ra_sw_nat_hook_clean_table, NULL);
	airoha_ppe_hook_exit();
	arht_ppe_general_exit();
	airoha_hwnat_loopback_exit();

	unregister_netdevice_notifier(&airoha_ppe_netdev_nb);
}