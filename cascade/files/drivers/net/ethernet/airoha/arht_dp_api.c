// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 AIROHA Inc
 * Author:  2024 AIROHA Inc
 */

#include <linux/proc_fs.h>
#include <net/ip.h>
#include <net/dsfield.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_bridge.h>
#include <linux/rhashtable.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <linux/rculist_nulls.h>
#include <linux/inet.h>
#include <net/netfilter/nf_flow_table.h>
#include <../net/bridge/br_private.h>
#include <../net/dsa/tag.h>
#include <linux/bitops.h>
#include <linux/regmap.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <net/dsa.h>
#include <arht_hook/ecnt_hook_gen_offload.h>
#include <net/tcp.h>
#include <linux/nvmem-consumer.h>
#include <linux/kprobes.h>
#include <net/sock.h>

#include "airoha_eth.h"
#include "airoha_regs.h"
#include "airoha_function.h"
#include "arht_fe.h"

#include <arht_hook/ecnt_hook_fe_type.h>

/************************************************************************
*                  P U B L I C   D A T A
*************************************************************************
*/
int eth_proc_init(void);
int eth_proc_exit(void);
int arht_multicast_hwnat_state_handler_lan_only(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, unsigned int foe_index, unsigned int  port_mask, int priority);
int arht_multicast_hwnat_state_handler_wlan_only(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, unsigned int foe_index, unsigned int  port_mask, int priority);
int arht_multicast_hwnat_state_handler_xsi_only(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, unsigned int foe_index, unsigned int  port_mask, int priority);
int arht_multicast_hwnat_state_handler_lan_hsgmii_1toN(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, unsigned int foe_index, unsigned int  port_mask, int priority);
int arht_multicast_hwnat_state_handler_unknown(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, unsigned int foe_index, unsigned int  port_mask, int priority);
extern int (*arht_xpon_igmp_sfu_enable_hook)(struct net_device *port_dev);

unsigned short get_meter_idx_by_gemport(struct sk_buff *skb, struct port_info *pinfo, u8 fport);
unsigned short get_meter_idx_by_lan(struct sk_buff *skb, struct port_info *pinfo, u8 fport);

extern struct airoha_eth *glb_eth;
extern int (*airoha_ppe_foe_commit_entry_ptr)(struct airoha_ppe *ppe,struct airoha_foe_entry *e,u32 hash,bool rx_wlan);
extern int airoha_ppe_offload_setup(struct airoha_eth *eth);
extern int (*ra_sw_nat_hook_clean_entry_by_fport_and_channel)(int fport, int channelIdx);
extern int (*dynamic_ifc_pingpong_hook)(struct sk_buff*);

extern spinlock_t ppe_lock, flow_offload_lock;
extern unchar ethmac_addr[6];

extern void EphyMonitor(void);
extern int g_pon_serdes_eth;

/* airoha pon onu type
 * 0 --> unknown
 * 1 --> SFU
 * 2 --> HGU
 * */
int airoha_pon_onu_type = 0;
EXPORT_SYMBOL(airoha_pon_onu_type);

int gemport_ratelimit_enable[32] = {0};
int lan_ratelimit_enable[AIROHA_MAX_NUM_QDMA][32] = {0};

int gemport_ratelimit_flag = 1;
EXPORT_SYMBOL(gemport_ratelimit_flag);

#define PPE_MULTICAST_STATE_HANDLER_NUM (sizeof(state_handler)/sizeof(PPE_MULTICAST_FWD_STATE_HANDLER))
#define MULTICAST_GSW_EXIST(port_mask)		(port_mask & 0xF)
#define MULTICAST_HSGMII_EXIST(port_mask)	(port_mask & 0xF0)
#define MULTICAST_WLAN_EXIST(port_mask)		(port_mask & 0x80000000)

static struct delayed_work  airoha_eth_monitor_workqueue;
static struct work_struct  airoha_sfu_flow_offload_workqueue;
static atomic_t airoha_sfu_offload_scheduled = ATOMIC_INIT(0);

u32 gsw_speed[4] = {0};
u32 xsi_speed[SERDES_MAX_IDX] = {0};
bool eth_lastlinks[ARHT_ETH_PORT_MAX] = {0};
unsigned int fast_path_speed_threshold = 0;
bool switch_set_mfc_enable = 0;

#define SK_MARK_LOCAL_OFFLOAD   0xAE000001

enum {
	RX_PON_SUCCESS=0,
	RX_PON_SUCCESS_GRO,
	RX_PON_FAIL,
};

int (*arht_xpon_igmp_get_fwd_ports_hook)(struct br_ip* addr,struct net_device* ports[],int nport) = NULL;
EXPORT_SYMBOL(arht_xpon_igmp_get_fwd_ports_hook);
int (*ra_sw_nat_hook_set_soe_info) (struct sk_buff * skb, unsigned char sa_index, unsigned char hop0, unsigned char hop1, unsigned char hop2) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_set_soe_info);
int (*arht_multicast_hwnat_clear_all_entry_hook) (void) = NULL;
EXPORT_SYMBOL(arht_multicast_hwnat_clear_all_entry_hook);
int (*arht_multicast_bind_to_cpu)(struct sk_buff* skb) = NULL;
EXPORT_SYMBOL(arht_multicast_bind_to_cpu);
int (*arht_tunnel_hook_get_crsn) (struct sk_buff * skb) = NULL;
EXPORT_SYMBOL(arht_tunnel_hook_get_crsn);
int (*arht_switch_set_mfc_hook)(void) = NULL;
EXPORT_SYMBOL(arht_switch_set_mfc_hook);


/*QDMA Multicast*/
#define MULTICAST_SPTAG_KEEP_HI_EN_SHIFT			(31)
#define MULTICAST_SPTAG_KEEP_HI_EN_MASK				(0x1<<MULTICAST_SPTAG_KEEP_HI_EN_SHIFT)
#define MULTICAST_SPTAG_KEEP_HI_ENABLE				(1)
#define MULTICAST_SPTAG_KEEP_HI_DISABLE				(0)
#define MULTICAST_SPTAG_SHIFT						(0)
#define MULTICAST_SPTAG_MASK						(0xFFFF<<MULTICAST_SPTAG_SHIFT)
#define MULTICAST_FPORT_SHIFT						(16)
#define MULTICAST_FPORT_MASK						(0x1FF<<MULTICAST_FPORT_SHIFT)

#define QDMA_CSR_MULTICAST_MODIFY_FPORT(chnl)		(0x0880+(chnl<<2))

#define qdmaSetMulticastFport(qdma, chnl, val)				airoha_qdma_rmw(qdma, QDMA_CSR_MULTICAST_MODIFY_FPORT(chnl), MULTICAST_FPORT_MASK, (val<<MULTICAST_FPORT_SHIFT))
#define qdmaSetMulticastSptag(qdma, chnl, val)				airoha_qdma_rmw(qdma, QDMA_CSR_MULTICAST_MODIFY_FPORT(chnl), MULTICAST_SPTAG_MASK, (val<<MULTICAST_SPTAG_SHIFT))
#define qdmaEnableMulticastSptagKeepHi(qdma, chnl)			airoha_qdma_set(qdma, QDMA_CSR_MULTICAST_MODIFY_FPORT(chnl), (MULTICAST_SPTAG_KEEP_HI_ENABLE << MULTICAST_SPTAG_KEEP_HI_EN_SHIFT))
#define qdmaDisableMulticastSptagKeepHi(qdma, chnl)			airoha_qdma_clear(qdma, QDMA_CSR_MULTICAST_MODIFY_FPORT(chnl), (MULTICAST_SPTAG_KEEP_HI_ENABLE << MULTICAST_SPTAG_KEEP_HI_EN_SHIFT))

#define MULTICAST_MAX_CHANNEL					(16)

static u32 lro_ring_reserve[2 * LRO_RING_NUM][2] = {{0}};

#define QDMA1_CHN_EN_BASE     (0x40a0)
#define QDMA2_CHN_EN_BASE     (0x60a0)
#define QDMA1_CHN_VLD_BASE    (0x5280)
#define QDMA2_CHN_VLD_BASE    (0x7280)

/*software hook defines*/
int (*pwan_cb_rx_hook)(void *pMsg, uint msgLen, struct sk_buff *skb, uint pktLen)=NULL;
EXPORT_SYMBOL(pwan_cb_rx_hook);

int (*ra_sw_nat_hook_rx) (struct sk_buff * skb) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_rx);

#ifdef TCSUPPORT_MT7510_FE
int (*ra_sw_nat_hook_tx) (struct sk_buff * skb, struct port_info * pinfo, int magic);
#else
int (*ra_sw_nat_hook_tx) (struct sk_buff * skb, int gmac_no) = NULL;
#endif
EXPORT_SYMBOL(ra_sw_nat_hook_tx);

int is_hwnat_dont_clean = 0;
EXPORT_SYMBOL(is_hwnat_dont_clean);

int (*ra_sw_nat_hook_rxinfo) (struct sk_buff * skb, int magic, char *data, int data_length) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_rxinfo);

int (*ra_sw_nat_hook_magic) (struct sk_buff * skb, int magic) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_magic);

int (*ra_sw_nat_hook_xfer) (struct sk_buff *skb, const struct sk_buff *prev_p) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_xfer);

int (*ra_sw_nat_hook_clean_table) (void) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_clean_table);

int (*ra_sw_nat_hook_tls_vtag_handle_hook)(struct sk_buff** pskb) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_tls_vtag_handle_hook);

int (*wan_speed_test_hook)(struct sk_buff*) = NULL;
EXPORT_SYMBOL(wan_speed_test_hook);

int (*wan_tr471_hook)(struct sk_buff*) = NULL;
EXPORT_SYMBOL(wan_tr471_hook);

int (*tr471_rx_hook)(struct sk_buff*, int sport,u32 hash) = NULL;
EXPORT_SYMBOL(tr471_rx_hook);

void (*get_tr471_rx_msg_hook)(int rx_ring, unsigned int * rx_byte_cnt_l, unsigned int * rx_byte_cnt_h, unsigned int * err_cnt,unsigned int * drop_cnt)=NULL;
EXPORT_SYMBOL(get_tr471_rx_msg_hook);

int (*ra_sw_nat_hook_set_magic) (struct sk_buff * skb, int magic) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_set_magic);

int (*ra_sw_nat_hook_sendto_ppe)(struct sk_buff *skb) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_sendto_ppe);

int (*offload_eth_fast_tx_hook)(struct sk_buff *skb, int channel) = NULL;
EXPORT_SYMBOL(offload_eth_fast_tx_hook);

int (*wan_speed_test_tso_hook)(struct sk_buff*) = NULL;
EXPORT_SYMBOL(wan_speed_test_tso_hook);

int (*wan_speed_test_pinpong_handle_hook)(struct sk_buff*) = NULL;
EXPORT_SYMBOL(wan_speed_test_pinpong_handle_hook);
int (*airoha_tunnel_hook_tx) (struct sk_buff * skb,struct airoha_ppe *ppe,struct port_info *pinfo) =NULL;
EXPORT_SYMBOL(airoha_tunnel_hook_tx);
int (*airoha_tunnel_pingpong_hook)(struct sk_buff * skb, unsigned short sptag, unsigned short udf, bool ipv6) = NULL;

EXPORT_SYMBOL(airoha_tunnel_pingpong_hook);
int (*set_entry_reason_hook)(struct sk_buff *skb,u32 reason)=NULL;
EXPORT_SYMBOL(set_entry_reason_hook);
int (*arht_hook_get_crsn) (struct sk_buff * skb) = NULL;
EXPORT_SYMBOL(arht_hook_get_crsn);

int (*ra_sw_nat_hook_ifc_hit_info) (struct sk_buff* skb, unsigned char hit, unsigned int ifc_id) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_ifc_hit_info);

int (*hwnat_multicast_set_info_for_sfu_hook)(int index, int tag) = NULL;
EXPORT_SYMBOL(hwnat_multicast_set_info_for_sfu_hook);

int  (*multicast_speed_learn_flow_hook)(struct sk_buff* skb) = NULL;
EXPORT_SYMBOL(multicast_speed_learn_flow_hook);

int  (*hwnat_set_rule_according_to_state_hook)(int index, int state,unsigned long mask) = NULL;
EXPORT_SYMBOL(hwnat_set_rule_according_to_state_hook);

int  (*xpon_igmp_learn_flow_hook)(struct sk_buff* skb) = NULL;
EXPORT_SYMBOL(xpon_igmp_learn_flow_hook);

int  (*multicast_hwnat_drop_entry_hook)(struct sk_buff* skb) = NULL;
EXPORT_SYMBOL(multicast_hwnat_drop_entry_hook);


int (*wan_multicast_drop_hook)(struct sk_buff* skb) = NULL;
EXPORT_SYMBOL(wan_multicast_drop_hook);

int (*wan_multicast_undrop_hook)(void) = NULL;
EXPORT_SYMBOL(wan_multicast_undrop_hook);

int (*wan_multicast_undrop_by_grpip_hook)(unsigned char is_ipv6,unsigned char* grp_ip) = NULL;
EXPORT_SYMBOL(wan_multicast_undrop_by_grpip_hook);

int (*wan_mvlan_change_hook)(void) = NULL;
EXPORT_SYMBOL(wan_mvlan_change_hook);

void (*restore_offload_info_hook)(struct sk_buff *skb, struct port_info *pinfo, int magic) = NULL;
EXPORT_SYMBOL(restore_offload_info_hook);

int (*sw_upstream_nat_tx_hook)(struct sk_buff * skb, uint msg0, uint msg1, struct port_info* qdma_info)= NULL;
EXPORT_SYMBOL(sw_upstream_nat_tx_hook);

int (*sw_downstream_nat_rx_hook) (struct sk_buff * skb) = NULL;
EXPORT_SYMBOL(sw_downstream_nat_rx_hook);

int (*ra_sw_nat_cds_all_ratelimit_hook) (struct sk_buff* skb) = NULL;
EXPORT_SYMBOL(ra_sw_nat_cds_all_ratelimit_hook);

int (*multicast_flood_find_entry_hook)(int index) = NULL;
EXPORT_SYMBOL(multicast_flood_find_entry_hook);

int (*multicast_speed_find_entry_hook)(int index) = NULL;
EXPORT_SYMBOL(multicast_speed_find_entry_hook);

int (*ra_sw_nat_hook_rx_set_l2lu)(struct sk_buff * skb, unsigned int direction, int PpeIndex) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_rx_set_l2lu);

int (*ra_sw_nat_hook_free) (struct sk_buff * skb) = NULL;
EXPORT_SYMBOL(ra_sw_nat_hook_free);

int (*arht_soe_ipsec_rcv_packek_from_soe)(struct sk_buff *skb, unsigned int rx_len, unsigned int sa_index, unsigned int hop_flags) = NULL;
EXPORT_SYMBOL(arht_soe_ipsec_rcv_packek_from_soe);

int (*arht_soe_wireguard_rcv_packet_from_soe)(struct sk_buff *skb, unsigned int rx_len, unsigned int sa_index, unsigned int hop_flags) = NULL;
EXPORT_SYMBOL(arht_soe_wireguard_rcv_packet_from_soe);

int (*airoha_pon_sfu_point_to_point_transmit_hook)(struct sk_buff *skb, u32 sptag) = NULL;
EXPORT_SYMBOL(airoha_pon_sfu_point_to_point_transmit_hook);

int (*airoha_pon_is_sfu_point_to_point_mode_hook)(struct sk_buff *skb) = NULL;
EXPORT_SYMBOL(airoha_pon_is_sfu_point_to_point_mode_hook);

int (*arht_force_to_cpu_hook)(struct sk_buff*, unsigned short stag) = NULL;
EXPORT_SYMBOL(arht_force_to_cpu_hook);

int (*local_out_pingpong_hook)(struct sk_buff*) = NULL;
EXPORT_SYMBOL(local_out_pingpong_hook);

int (*arht_force_to_cpu_prepare_gro_hook)(struct sk_buff*, bool ipv6) = NULL;
EXPORT_SYMBOL(arht_force_to_cpu_prepare_gro_hook);

int (*arht_xpon_sfu_ds_vlan_act_hook)(struct sk_buff **pskb, uint32_t tag) = NULL;
EXPORT_SYMBOL(arht_xpon_sfu_ds_vlan_act_hook);
int (*fe_resource_mark_acnt_hook)( struct sk_buff *skb, int dir) = NULL;
EXPORT_SYMBOL(fe_resource_mark_acnt_hook);
int (*fe_resource_mark_meter_hook)( struct sk_buff *skb, int dir) = NULL;
EXPORT_SYMBOL(fe_resource_mark_meter_hook);
int (*fe_resource_mark_if_meter_hook)( struct sk_buff *skb, int dir) = NULL;
EXPORT_SYMBOL(fe_resource_mark_if_meter_hook);
int (*xsi_mac_set_ratelimit_hook)(uint hsgmii_index, unsigned int type, uint rate, uint mode) = NULL;
EXPORT_SYMBOL(xsi_mac_set_ratelimit_hook);

int (*arht_conntrack_get_cnt_hook)(u32 hash, u64 *bytes, u64 *packets) = NULL;
EXPORT_SYMBOL(arht_conntrack_get_cnt_hook);
void (*arht_conntrack_free_cnt_hook)(u32 hash) = NULL;
EXPORT_SYMBOL(arht_conntrack_free_cnt_hook);


#define CR_FE_PPE_PHY_RANGE		(0x4000)
#define CR_FE_PPE_PHY_END		(CR_FE_PPE_PHY_BASE + CR_FE_PPE_PHY_RANGE)
#define CR_FE_PPE_PHY_BASE		(0x1fb50000)
u32 get_fe_ppe_data(u32 reg)
{
    return readl(glb_eth->fe_regs + reg);
}

void set_fe_ppe_data(u32 reg, u32 val)
{
    writel(val, glb_eth->fe_regs + reg); 
}

#define CR_QDMA_LAN_PHY_RANGE		(0x2000)
#define CR_QDMA_LAN_PHY_BASE		(0x1fb54000)
#define CR_QDMA_LAN_PHY_END		(CR_QDMA_LAN_PHY_BASE + CR_QDMA_LAN_PHY_RANGE)
#define CR_QDMA_WAN_PHY_RANGE		(0x2000)
#define CR_QDMA_WAN_PHY_BASE		(0x1fb56000)
#define CR_QDMA_WAN_PHY_END		(CR_QDMA_WAN_PHY_BASE + CR_QDMA_WAN_PHY_RANGE)

static u32 get_qdma_lan_data(u32 reg)
{
    return readl(glb_eth->qdma[0].regs + reg);
}

static void set_qdma_lan_data(u32 reg, u32 val)
{
    writel(val, glb_eth->qdma[0].regs + reg); 
}

static u32 get_qdma_wan_data(u32 reg)
{
    return readl(glb_eth->qdma[1].regs + reg);
}

static void set_qdma_wan_data(u32 reg, u32 val)
{
    writel(val, glb_eth->qdma[1].regs + reg); 
}

#define CR_XSIF_PCIE0_BASE 0x1fa04000
#define CR_XSIF_PCIE1_BASE 0x1fa05000
#define CR_XSIF_USB_BASE   0x1fa07000
#define CR_XSIF_PON_BASE   0x1fa08000
#define CR_XSIF_ETH_BASE   0x1fa09000
#define CR_XSI_RANGE       0x800
#define CR_XSI_BASE        CR_XSIF_PCIE0_BASE
#define CR_XSI_END         CR_XSIF_ETH_BASE + CR_XSI_RANGE

static struct airoha_gdm_dev *get_xsi_eth_dev(void)
{
	int port_idx = 0, nbq_idx = 0;
	struct airoha_gdm_port *port = NULL;
	struct airoha_gdm_dev *dev = NULL;

	port_idx = glb_eth->soc->gdm[SERDES_ETH_IDX];
		
	if ((port_idx >= 0) && (port_idx < AIROHA_MAX_NUM_GDM_PORTS))
	{
		nbq_idx = glb_eth->soc->nbq[SERDES_ETH_IDX];
		port = glb_eth->ports[port_idx];
		if(airoha_is_7581(glb_eth) && port->id == AIROHA_GDM3_IDX)
			nbq_idx -= 4;
		
		if((nbq_idx >= 0) && nbq_idx < ARRAY_SIZE(port->devs))
			dev = port->devs[nbq_idx];
	}

	return dev;
}

static u32 get_xsi_data(u32 reg)
{
	u32 val = 0;
	struct airoha_gdm_dev *dev = NULL;

	if(reg >= CR_XSIF_ETH_BASE && reg < CR_XSIF_ETH_BASE + CR_XSI_RANGE)
	{
		dev = get_xsi_eth_dev();
		reg = reg - CR_XSIF_ETH_BASE;
	}

	if(dev && dev->xfi_mac){
		regmap_read(dev->xfi_mac,reg,&val);
	}
	return val;
}

static void set_xsi_data(u32 reg, u32 val)
{
	struct airoha_gdm_dev *dev = NULL;

	if(reg >= CR_XSIF_ETH_BASE && reg < CR_XSIF_ETH_BASE + CR_XSI_RANGE)
	{
		dev = get_xsi_eth_dev();
		reg = reg - CR_XSIF_ETH_BASE;
	}

	if(dev && dev->xfi_mac){
		regmap_write(dev->xfi_mac,reg,val);
	}
}

u32 get_frame_engine_data(u32 reg)
{
	u32 reg_phy = 0;
	u32 reg_offset = 0;

	/* translate addr to physical addr */
	if( reg > 0xa0000000)
		reg_phy = (reg & 0x1fffffff);
	else
		reg_phy = reg;
	
	reg_offset = reg_phy % 4;
	if(reg_offset != 0){
		printk("\nDatapath(%s) get reg error, reg=0x%08X\n", __func__, reg);
		return 0;
	}
	
	if( (CR_FE_PPE_PHY_BASE <= reg_phy) && (reg_phy < CR_FE_PPE_PHY_END) )
		return get_fe_ppe_data(reg_phy - CR_FE_PPE_PHY_BASE);
	else if( (CR_QDMA_LAN_PHY_BASE <= reg_phy) && (reg_phy < CR_QDMA_LAN_PHY_END))
		return get_qdma_lan_data(reg_phy - CR_QDMA_LAN_PHY_BASE);
	else if( (CR_QDMA_WAN_PHY_BASE <= reg_phy) && (reg_phy < CR_QDMA_WAN_PHY_END))
		return get_qdma_wan_data(reg_phy - CR_QDMA_WAN_PHY_BASE);
	else if( (CR_XSI_BASE <= reg_phy) && (reg_phy < CR_XSI_END))
		return get_xsi_data(reg_phy);
	else
		printk("\nDatapath(%s) get reg error, reg=0x%08X\n", __func__, reg);

	return 0;
}
EXPORT_SYMBOL(get_frame_engine_data);
void set_frame_engine_data(u32 reg, u32 val)
{
	u32 reg_phy = 0;
	u32 reg_offset = 0;

	/* translate addr to physical addr */
	if( reg > 0xa0000000)
		reg_phy = (reg & 0x1fffffff);
	else
		reg_phy = reg;

	reg_offset = reg_phy % 4;
	if(reg_offset != 0){
		printk("\nDatapath(%s) set reg error, reg=0x%08X\n", __func__, reg);
		return ;
	}

	if( (CR_FE_PPE_PHY_BASE <= reg_phy) && (reg_phy < CR_FE_PPE_PHY_END) )
		set_fe_ppe_data(reg_phy - CR_FE_PPE_PHY_BASE, val); 
	else if((CR_QDMA_LAN_PHY_BASE <= reg_phy) && (reg_phy < CR_QDMA_LAN_PHY_END))
		set_qdma_lan_data(reg_phy - CR_QDMA_LAN_PHY_BASE, val); 
	else if((CR_QDMA_WAN_PHY_BASE <= reg_phy) && (reg_phy < CR_QDMA_WAN_PHY_END))
		set_qdma_wan_data(reg_phy - CR_QDMA_WAN_PHY_BASE, val); 
	else if((CR_XSI_BASE <= reg_phy) && (reg_phy < CR_XSI_END))
		set_xsi_data(reg_phy, val); 
	else
		printk("\nDatapath(%s) set reg error, reg=0x%08X\n", __func__, reg);

}
EXPORT_SYMBOL(set_frame_engine_data);

#if 0
struct ecnt_hook_ops ecnt_fe_api_op = {
	.name = "fe_api_hook",
	.is_execute = 1,
	.hookfn = ecnt_fe_api_hook,
	.maintype = ECNT_FE,
	.subtype = ECNT_FE_API,
	.priority = 1
};
#endif


int cmpMacInfo(uint8_t* Dst, uint8_t* Src)
{
	if((Dst[0] == Src[6]) && (Dst[1] == Src[7])
	&& (Dst[2] == Src[8]) && (Dst[3] == Src[9])
	&& (Dst[4] == Src[10]) && (Dst[5] == Src[11])) {
		return HWNAT_SUCCESS;
	} else {
		return HWNAT_FAIL;
	}
}

u8 get_dscp_from_skb(struct sk_buff *skb, int type)
{
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	u32 offset = 0;
	u8 tos = 0;
	
	switch (type) {
		case PPE_PKT_TYPE_IPV4_ROUTE:
		case PPE_PKT_TYPE_IPV4_HNAPT:
		case PPE_PKT_TYPE_IPV4_DSLITE:
			iph = (struct iphdr *)(skb_network_header(skb) + offset);
			tos = iph->tos;				
			break;
	
		case PPE_PKT_TYPE_IPV6_ROUTE_3T:
		case PPE_PKT_TYPE_IPV6_ROUTE_5T:
		case PPE_PKT_TYPE_IPV6_6RD:
			ip6h = (struct ipv6hdr *)(skb_network_header(skb) + offset);
			tos = ipv6_get_dsfield(ip6h);	
			break;

		default:
			break;
	}

	return tos;
}

int airoha_get_lan_id(struct net_device *dev)
{
	if(dev == NULL)
		return 0;
	
	if((dev->name[0] == 'l') && (dev->name[1] == 'a') && (dev->name[2] == 'n'))
	{
		if(dev->name[3] == '1')
			return LAN1;
		else if(dev->name[3] == '2')
			return LAN2;
		else if(dev->name[3] == '3')
			return LAN3;
		else if(dev->name[3] == '4')
			return LAN4;
		
	}
	if((dev->name[0] == 'e') && (dev->name[1] == 't') && (dev->name[2] == 'h') && (dev->name[3] != '1') && (dev->name[3] != '0') )
		return ETH2;
	
	return 0;
}

static void u32_array_to_ip6_be(const u32 *src, __be32 *dst)
{
    int i;
    for (i = 0; i < 4; i++)
        dst[i] = ntohl(src[i]);
}

static void delete_conntrack_by_tuple6(const u32 *src_ip, const u32 *dst_ip,
                                       __be16 src_port, __be16 dst_port, u8 l4proto)
{
    struct nf_conntrack_tuple tuple;
    struct nf_conntrack_tuple_hash *thash;
    struct nf_conn *ct;

    memset(&tuple, 0, sizeof(tuple));
    tuple.src.l3num = AF_INET6;

    u32_array_to_ip6_be(src_ip, tuple.src.u3.ip6);
    u32_array_to_ip6_be(dst_ip, tuple.dst.u3.ip6);

    tuple.src.u.all = src_port;
    tuple.dst.u.all = dst_port;
    tuple.dst.protonum = l4proto;

    thash = nf_conntrack_find_get(&init_net, &nf_ct_zone_dflt, &tuple);
    if (thash) {
        ct = nf_ct_tuplehash_to_ctrack(thash);
        nf_ct_delete(ct, 0, 0);
        nf_ct_put(ct);
    } else {
        AIROHA_LOG(AIROHA_DEBUG_LEVEL_ERR, "No conntrack found for this tuple\n");
    }
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
    tuple.src.u.all = src_port; // already in network order
    tuple.dst.u.all = dst_port; // already in network order
	tuple.dst.protonum = l4proto; // TCP or UDP, etc

    thash = nf_conntrack_find_get(&init_net, &nf_ct_zone_dflt, &tuple);
    if (thash) {
        ct = nf_ct_tuplehash_to_ctrack(thash);
        nf_ct_delete(ct, 0, 0);
        nf_ct_put(ct);
        
    } else {
		AIROHA_LOG(AIROHA_DEBUG_LEVEL_ERR, "No conntrack found for this tuple\n");
    }
	
}

void airoha_flow_table_entries_lan(struct rhashtable *flow_table, struct net_device *dev)
{
    struct airoha_flow_table_entry *e = NULL;
    struct rhashtable_iter iter = {0};
    int ret = 0;
    int lan_idx = airoha_get_lan_id(dev);
    
    rhashtable_walk_enter(flow_table, &iter);
    ret = rhashtable_walk_start_check(&iter);
    if (ret) {
        goto out;
	}

	for (;;)
	{
		e = rhashtable_walk_next(&iter);
		/* CID:918536 */
		if ((NULL == e) || IS_ERR(e))
		{
			break;
		}
        if (lan_idx == e->e_magic || lan_idx == e->ingress_dev_idx) {
            int type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, e->data.ib1);
			u32 state = FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, e->data.ib1);
			u8 is_udp = FIELD_GET(AIROHA_FOE_IB1_BIND_UDP, e->data.ib1);
    		u8 l4proto = is_udp ? IPPROTO_UDP : IPPROTO_TCP;

			if (state != AIROHA_FOE_STATE_BIND)
				continue;

			AIROHA_LOG(AIROHA_DEBUG_LEVEL_ERR, "airoha_flow_table_entries_lan found flow entry: cookie=%lx ingress_dev_idx=%u, e->magic=%d and lan_idx=%d\n",
                   e->cookie, e->ingress_dev_idx, e->e_magic, lan_idx);
			
			if (type == PPE_PKT_TYPE_IPV4_HNAPT || type == PPE_PKT_TYPE_IPV4_ROUTE) {
                struct airoha_foe_ipv4_tuple *tuple = &e->data.ipv4.orig_tuple;
				
                delete_conntrack_by_tuple(ntohl(tuple->src_ip), ntohl(tuple->dest_ip),
                                         ntohs(tuple->src_port), ntohs(tuple->dest_port),l4proto);
            } else if (type == PPE_PKT_TYPE_IPV4_DSLITE) {
                struct airoha_foe_ipv4_tuple *tuple = &e->data.dslite.ip4;
                delete_conntrack_by_tuple(ntohl(tuple->src_ip), ntohl(tuple->dest_ip),
                                         ntohs(tuple->src_port), ntohs(tuple->dest_port),l4proto);
            } else if (type == PPE_PKT_TYPE_IPV6_ROUTE_3T ||
                       type == PPE_PKT_TYPE_IPV6_ROUTE_5T ||
                       type == PPE_PKT_TYPE_IPV6_6RD) {
                struct airoha_foe_ipv6 *tuple6 = &e->data.ipv6;
				delete_conntrack_by_tuple6(tuple6->src_ip, tuple6->dest_ip,
                                           ntohs(tuple6->src_port), ntohs(tuple6->dest_port),l4proto);
            } else {
				AIROHA_LOG(AIROHA_DEBUG_LEVEL_INFO, "Unsupported packet type: %d\n", type);
                continue;
            }
        }
    }

    rhashtable_walk_stop(&iter);
out:
    rhashtable_walk_exit(&iter);
}


int airoha_is_pon_sfu_mode(void)
{
	return airoha_pon_onu_type == 1;
}
EXPORT_SYMBOL(airoha_is_pon_sfu_mode);

unsigned short get_meter_idx_by_gemport(struct sk_buff *skb, struct port_info *pinfo, u8 fport)
{
	struct airoha_eth *eth = glb_eth;
	lan_port_t meter_idx = 0x7F;

    if (eth->meter_enable) 
    {
		switch (fport) 
		{
			case FE_PSE_PORT_GDM2:
				meter_idx = pinfo->tsid;
				break;
			case FE_PSE_PORT_GDM1:
			case FE_PSE_PORT_GDM3:
			case FE_PSE_PORT_GDM4:
			default:
				meter_idx = (skb->mark & AIROHA_SKB_MARK_MASK_FOR_GEMPORT_RATELIMIT) >> AIROHA_SKB_MARK_SHIFT_FOR_GEMPORT_RATELIMIT;  //meter_id_mask from (31,26) meter_is shift is 26.
				break;
		}
		/* CID:1119570 */
		if (meter_idx > AIROHA_MAX_IDX_FOR_GEMPORT_RATELIMIT) {
        	return 0x7F;
    	}
		if(gemport_ratelimit_enable[meter_idx] == 0){
		    return 0x7F;
		}
	
		if(meter_idx <= AIROHA_MAX_IDX_FOR_GEMPORT_RATELIMIT && meter_idx >= AIROHA_MIN_IDX_FOR_GEMPORT_RATELIMIT)
		{
			meter_idx = meter_idx + AIROHA_NUM_RX_RING;
		}
	}

    return meter_idx;
}

static bool arht_is_valid_gdm_dev(struct airoha_eth *eth, struct airoha_gdm_dev *dev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(eth->ports); i++) {
		struct airoha_gdm_port *port = eth->ports[i];
		int j;

		if (!port)
			continue;

		for (j = 0; j < ARRAY_SIZE(port->devs); j++) {
			if (port->devs[j] == dev)
				return true;
		}
	}

	return false;
}

unsigned short get_meter_idx_by_lan(struct sk_buff *skb, struct port_info *pinfo, u8 fport)
{
	struct airoha_eth *eth = glb_eth;
	lan_port_t meter_idx = 0x1F;
	struct net_device *lan_dev = NULL;
	bool need_put = false;
	unsigned int dir = 1;

	if (eth->meter_enable) 
	{
		switch (fport) 
		{
			case FE_PSE_PORT_GDM2:
				if (skb->skb_iif) {
					lan_dev = dev_get_by_index(&init_net, skb->skb_iif);
					if (lan_dev){
						need_put = true;
					}
				}
				break;

			case FE_PSE_PORT_GDM1:
				#if IS_ENABLED(CONFIG_NET_DSA)
				if (netdev_uses_dsa(skb->dev)){                    
					#if LINUX_VERSION_CODE < KERNEL_VERSION(6,12,0)
					lan_dev = dsa_master_find_slave(skb->dev, 0, LAN_IDX_FROM_TX_SPTAG(pinfo->stag));
					#else
					lan_dev = dsa_conduit_find_user(skb->dev, 0, LAN_IDX_FROM_TX_SPTAG(pinfo->stag));
					#endif                    
					if (lan_dev){
						need_put = true;
					}
				}
				#endif
				break;

			case FE_PSE_PORT_GDM3:
			case FE_PSE_PORT_GDM4:
				lan_dev = skb->dev;
				break;

			default:
				break;
		}
		
		if (lan_dev) 
		{
			if (skb->dev) {
				struct airoha_gdm_dev *gdm_dev = airoha_ppe_get_gdm_dev(glb_eth, skb->dev);;
				if (arht_is_valid_gdm_dev(glb_eth, gdm_dev)) {
					dir = (unsigned int)(gdm_dev->qdma - gdm_dev->eth->qdma);
					if (dir >= AIROHA_MAX_NUM_QDMA)
						dir = 0;
				}
			}
			for (int i = 0; dev_meter_map[i].dev_name != NULL; i++) 
			{
				if ((strcmp(lan_dev->name, dev_meter_map[i].dev_name) == 0) && lan_ratelimit_enable[dir][i] == 1) 
				{
					meter_idx = dev_meter_map[i].meter_idx;
					break;
				}
			}
			if (need_put){
				dev_put(lan_dev);
			}
		}
	}

	return meter_idx;

}

void airoha_set_default_acnt_meter_idx(struct airoha_foe_entry *hwe, int type)
{
	if ( NULL == hwe || type > PPE_PKT_TYPE_IPV6_6RD )
	{
		return;
	}

	if ( type == PPE_PKT_TYPE_BRIDGE ) 
	{
		hwe->bridge32.ib2 &= ~(AIROHA_FOE_IB2_PORT_AG);
		hwe->bridge32.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x7ff);
		hwe->bridge32.meter &= ~(AIROHA_FOE_ACNT_GRP3);
		hwe->bridge32.meter |= FIELD_PREP(AIROHA_FOE_ACNT_GRP3, 0x7f);
		hwe->bridge32.meter &= ~(AIROHA_FOE_METER_GRP3);
		hwe->bridge32.meter |= FIELD_PREP(AIROHA_FOE_METER_GRP3, 0xf);
		hwe->bridge32.meter &= ~(AIROHA_FOE_METER_GRP2);
		hwe->bridge32.meter |= FIELD_PREP(AIROHA_FOE_METER_GRP2, 0x1f);
	}
	else if ( type >= PPE_PKT_TYPE_IPV6_ROUTE_3T )
	{
		hwe->ipv6.ib2 &= ~(AIROHA_FOE_IB2_PORT_AG);
		hwe->ipv6.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x7ff);
		hwe->ipv6.meter &= ~(AIROHA_FOE_ACNT_GRP3);
		hwe->ipv6.meter |= FIELD_PREP(AIROHA_FOE_ACNT_GRP3, 0x7f);
		hwe->ipv6.meter &= ~(AIROHA_FOE_METER_GRP3);
		hwe->ipv6.meter |= FIELD_PREP(AIROHA_FOE_METER_GRP3, 0xf);
		hwe->ipv6.meter &= ~(AIROHA_FOE_METER_GRP2);
		hwe->ipv6.meter |= FIELD_PREP(AIROHA_FOE_METER_GRP2, 0x1f);
	}
	else
	{
		hwe->ipv4.ib2 &= ~(AIROHA_FOE_IB2_PORT_AG);
		hwe->ipv4.ib2 |= FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x7ff);
		hwe->ipv4.l2.meter &= ~(AIROHA_FOE_ACNT_GRP3);
		hwe->ipv4.l2.meter |= FIELD_PREP(AIROHA_FOE_ACNT_GRP3, 0x7f);
		hwe->ipv4.l2.meter &= ~(AIROHA_FOE_METER_GRP3);
		hwe->ipv4.l2.meter |= FIELD_PREP(AIROHA_FOE_METER_GRP3, 0xf);
		hwe->ipv4.l2.meter &= ~(AIROHA_FOE_METER_GRP2);
		hwe->ipv4.l2.meter |= FIELD_PREP(AIROHA_FOE_METER_GRP2, 0x1f);
	}

	return;
}

static int isPriorityPkt(struct sk_buff *skb)
{
	ushort etherType=0;
	unchar ipVerLen=0;
	unchar ipProtocol=0;
	unchar tcpFlags=0;
	ushort pppProtocol=0;
	unchar ipv6_protocol=0, ipv6_type=0;
	ushort dport=0, sport=0;
	unchar *cp = NULL;
#define ICMPV6_ROUTE_SOL 133
#define ICMPV6_ROUTE_ADV 134
#define ICMPV6_NEIGH_SOL 135
#define ICMPV6_NEIGH_ADV 136

	cp = skb->data;
	cp += 12;
	/* get ether type */
	etherType = *(ushort *) cp;
	/* skip ether type */
	cp += 2;

	/*parse if vlan exists*/
	if (etherType == htons(0x8100)) {
		/*skip 802.1q tag field*/
		cp += 2;
		/*re-parse ether type*/
		etherType = *(ushort *) cp;
		/* skip ether type */
		cp += 2;
	}
    	/*parse if vlan exists*/
	if (etherType == htons(0x8100)) {
		/*skip 802.1q tag field*/
		cp += 2;
		/*re-parse ether type*/
		etherType = *(ushort *) cp;
		/* skip ether type */
		cp += 2;
	}

	/*check whether PPP packets*/
	if (etherType == htons(0x8864)) {
		/* skip pppoe head */
		cp += 6; 					/* 6: PPPoE header 2: PPP protocol */
		/* get ppp protocol */
		pppProtocol = *(ushort *) cp;
		/* check if LCP protocol and ipcpv6 protocol */
		if ((pppProtocol == htons(0xc021)) || (pppProtocol == htons(0x8021)) || (pppProtocol == htons(0x8057)) 
			|| (pppProtocol == htons(0xc223)) || (pppProtocol == htons(0xc057))) {
			return 1;
		/* check if IPv6 protocol */
		} else if (pppProtocol == htons(0x0057)) {
			cp += 2;
			cp += 6;
			/* get ip protocol */
			ipProtocol = *(unchar*)cp;
			ipVerLen = 0;
			cp += 34;
         
			if (ipProtocol == 0x3a) {
    				ipv6_type = *(unchar*)cp;

			}

			goto ipv6_header;
		/* check if IP protocol */
		} else if (pppProtocol != htons(0x0021)) {
			return 0;
		}
		/* skip ppp protocol */
		cp += 2; 					/* 6: PPPoE header 2: PPP protocol */
	} else if (etherType == htons(0x8863)) {
		return 1;
	/*check whether arp packet*/	
	} else if (etherType == htons(0x0806)) {
		return 1;	
	} 
	else if (etherType == htons(0x86dd)) {
		cp += 6;
         
		ipv6_protocol = *(unchar*)cp;
		cp += 34;
		if (ipv6_protocol == 0x3a) {
			ipv6_type = *(unchar*)cp;
		}
		/* get ip protocol */
		ipProtocol = ipv6_protocol;
		if(ipProtocol == 0x11) /* udp + dns */
		{
			if(  *(ushort *)(cp + 2) == htons(0x0035) )
				return 1;
		}
		ipVerLen = 0;
		goto ipv6_header;
	}
	else {
		/* check if ip packet */
		if (etherType != htons(0x0800)) {
			return 0;
		}
	}

	pppProtocol = *(ushort *) cp;
	/* check if LCP protocol, for pppoa control packet */
	if (pppProtocol == htons(0xc021)) {
		return 1;
	} else if(pppProtocol == htons(0x0021)) {
		cp += 2; 					/* 6: PPPoE header 2: PPP protocol */
	}

	/* check if it is a ipv4 packet */
	ipVerLen = *cp;
	if ((ipVerLen & 0xf0) != 0x40) {
		return 0;
	}

	/* get ip protocol */
	ipProtocol = *(cp + 9);

	if(ipProtocol == 0x11) /* udp + dns */
	{
		ushort sport = *(ushort *)(cp + ((ipVerLen & 0x0f) << 2));
		ushort dport = *(ushort *)(cp + ((ipVerLen & 0x0f) << 2) + 2);

		if ((sport == htons(68) && dport == htons(67)) || // DHCP Discover/Request
			(sport == htons(67) && dport == htons(68)))   // DHCP Offer/Ack
		{
			return 1;
		}
		if( *(ushort *)(cp + ((ipVerLen & 0x0f) << 2) + 2) == htons(0x0035) )
			return 1;
	}

    if((ipProtocol == 2) || (ipProtocol == 1))
        return 1;

ipv6_header:

	if (ipv6_type ==ICMPV6_ROUTE_SOL || 
		ipv6_type ==ICMPV6_ROUTE_ADV ||
		ipv6_type ==ICMPV6_NEIGH_SOL ||
		ipv6_type ==ICMPV6_NEIGH_ADV) {
		return 1;
	}

	if( ipProtocol == 17 )//udp
	{
		/*get source port and dest port*/
		sport = *(ushort *)(cp + ((ipVerLen & 0x0f) << 2) );
		dport = *(ushort *)(cp + ((ipVerLen & 0x0f) << 2) + 2);
		
		if(sport ==  htons(0x0223) && dport== htons(0x0222) ){
			//printk("lalala dhcpv6 adver or reply to first queue.\n"); 
			return 1;		
		}
		if(sport ==  htons(0x0222) && dport ==  htons(0x0223) ){
			//printk("lalala dhcpv6 request or soclit to first queue.\n"); 
			return 1;
		}
	}

	/* check if TCP protocol */
	if (ipProtocol != 6) {
		return 0;
	}

	/* align to TCP header */
	cp += (ipVerLen & 0x0f) << 2;
	/* get TCP flags */
	tcpFlags = *(cp + 13);
	
	/* check if TCP fin/syn/reset */
	if (((tcpFlags & 0x01) == 0x01) || ((tcpFlags & 0x02) == 0x02) || ((tcpFlags & 0x04) == 0x04)) {
		return 1;
	}

	return 0;
}

int airoha_eth_transmit_packet(struct sk_buff *skb, u32 txmsg0, u32 txmsg1, struct port_info *pinfo){
	struct airoha_gdm_dev *dev = glb_eth->ports[0]->devs[0];
	struct net_device *netdev = dev->dev;
	struct airoha_qdma *qdma = dev->qdma;
	u32 nr_frags, len;
	struct netdev_queue *txq;
	struct airoha_queue *q;
	struct airoha_queue_entry *e;
	LIST_HEAD(tx_list);
	
	void *data;
	int i, qid;
	u16 index;
	//u8 fport;
	skb->dev = netdev;
	
	qid = skb_get_queue_mapping(skb) % ARRAY_SIZE(qdma->q_tx);
	//tag = DP_SPEED_UP;//use in sptag for pingpong stream

	txmsg0 = FIELD_PREP(QDMA_ETH_TXMSG_TCO_MASK, 1) |
		   FIELD_PREP(QDMA_ETH_TXMSG_CHAN_MASK,
			  qid / AIROHA_NUM_QOS_QUEUES) |
		   FIELD_PREP(QDMA_ETH_TXMSG_QUEUE_MASK,
			  qid % AIROHA_NUM_QOS_QUEUES) ;
	
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		txmsg0 |= FIELD_PREP(QDMA_ETH_TXMSG_TCO_MASK, 1) |
			FIELD_PREP(QDMA_ETH_TXMSG_UCO_MASK, 1) |
			FIELD_PREP(QDMA_ETH_TXMSG_ICO_MASK, 1);

	/* TSO: fill MSS info in tcp checksum field */
	if (skb_is_gso(skb)) {
		if (skb_cow_head(skb, 0))
			goto error;

		if (skb_shinfo(skb)->gso_type & (SKB_GSO_TCPV4 |
						 SKB_GSO_TCPV6)) {
			__be16 csum = cpu_to_be16(skb_shinfo(skb)->gso_size);

			tcp_hdr(skb)->check = (__force __sum16)csum;
			txmsg0 |= FIELD_PREP(QDMA_ETH_TXMSG_TSO_MASK, 1) |
					FIELD_PREP(QDMA_ETH_TXMSG_UCO_MASK, 1) |
					FIELD_PREP(QDMA_ETH_TXMSG_ICO_MASK, 1);
		}
	} 
	
	//fport = FE_PSE_PORT_PPE1;
	
//	msg1 =0x7f4007ff;
	q = &qdma->q_tx[qid];
	if (WARN_ON_ONCE(!q->ndesc))
		goto error;
	if(arht_hook_get_crsn(skb) == PPE_CPU_REASON_KEEPALIVE_WITH_DUP_OLD_PACKET)
		goto error;

	spin_lock_irq(&q->lock);

	txq = netdev_get_tx_queue(netdev, qid);
	nr_frags = 1 + skb_shinfo(skb)->nr_frags;

	if (q->queued + nr_frags >= q->ndesc) {
		/* not enough space in the queue */
		netif_tx_stop_queue(txq);
		spin_unlock_irq(&q->lock);
		return NETDEV_TX_BUSY;
	}

	len = skb_headlen(skb);
	data = skb->data;
	e = list_first_entry(&q->tx_list, struct airoha_queue_entry,
			     list);
	index = e - q->entry;

	for (i = 0; i < nr_frags; i++) {
		struct airoha_qdma_desc *desc = &q->desc[index];
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		dma_addr_t addr;
		u32 val;
		addr = dma_map_single(netdev->dev.parent, data, len,
					  DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(netdev->dev.parent, addr)))
			goto error_unmap;

		list_move_tail(&e->list, &tx_list);
		e->skb = i ? NULL : skb;
		e->dma_addr = addr;
		e->dma_len = len;

		e = list_first_entry(&q->tx_list, struct airoha_queue_entry,
				     list);
		index = e - q->entry;

		val = FIELD_PREP(QDMA_DESC_LEN_MASK, len);
		if (i < nr_frags - 1){
			val |= FIELD_PREP(QDMA_DESC_MORE_MASK, 1);
		}
		WRITE_ONCE(desc->ctrl, cpu_to_le32(val));
		WRITE_ONCE(desc->addr, cpu_to_le32(addr));

		val = FIELD_PREP(QDMA_DESC_NEXT_ID_MASK, index);
		WRITE_ONCE(desc->data, cpu_to_le32(val));
		WRITE_ONCE(desc->msg0, cpu_to_le32(txmsg0));
		WRITE_ONCE(desc->msg1, cpu_to_le32(txmsg1));

		data = skb_frag_address(frag);
		len = skb_frag_size(frag);
	}
	
	q->queued += i;

	skb_tx_timestamp(skb);
	netdev_tx_sent_queue(txq, skb->len);

	if (netif_xmit_stopped(txq) || !netdev_xmit_more())
		airoha_qdma_rmw(qdma, REG_TX_CPU_IDX(qid),
				TX_RING_CPU_IDX_MASK,
				FIELD_PREP(TX_RING_CPU_IDX_MASK, index));

	if (q->ndesc - q->queued < q->free_thr)
		netif_tx_stop_queue(txq);

	spin_unlock_irq(&q->lock);

	return NETDEV_TX_OK;

error_unmap:
	while (!list_empty(&tx_list)) {
		e = list_first_entry(&tx_list, struct airoha_queue_entry,
				     list);
		dma_unmap_single(netdev->dev.parent, e->dma_addr, e->dma_len,
				 DMA_TO_DEVICE);
		e->dma_addr = 0;
		list_move_tail(&e->list, &q->tx_list);
	}

	spin_unlock_irq(&q->lock);
error:
	dev_kfree_skb_any(skb);
	netdev->stats.tx_dropped++;

	return NETDEV_TX_OK;
}
EXPORT_SYMBOL(airoha_eth_transmit_packet);


void airoha_ppe_update_txmsg(struct sk_buff *skb, u32 *msg1, u32 *msg2)
{
	u32 fe_resource_mark = 0;
	u32 acnt0, acnt1, acnt2, meter0, meter1, meter2;

	if ( !skb || !msg1 || !msg2 )
		return;

	/* qdma_set_accout_meter_info_to_txmsg */
	fe_resource_mark = airoha_get_entry_fe_resource_mark(FOE_ENTRY_NUM(skb));
	acnt0 = (fe_resource_mark >> ACCOUNT0_ENABLE_OFFSET) & 0x1 ? (fe_resource_mark >> ACCOUNT0_OFFSET) & ACCOUNT0_MASK : ACCOUNT0_MASK;
	if ( 0 != acnt0 && ACCOUNT0_MASK != acnt0 )
	{
		acnt0 -= 1;
	}
	acnt1 = (fe_resource_mark >> ACCOUNT1_ENABLE_OFFSET) & 0x1 ? (fe_resource_mark >> ACCOUNT1_OFFSET) & ACCOUNT1_MASK : ACCOUNT1_MASK;
	if ( 0 != acnt1 && ACCOUNT1_MASK != acnt1 )
	{
		acnt1 -= 1;
	}
	acnt2 = (fe_resource_mark >> ACCOUNT2_ENABLE_OFFSET) & 0x1 ? (fe_resource_mark >> ACCOUNT2_OFFSET) & ACCOUNT2_MASK : ACCOUNT2_MASK;
	if ( 0 != acnt2 && ACCOUNT2_MASK != acnt2 )
	{
		acnt2 -= 1;
	}
	meter0 = (fe_resource_mark >> METER0_ENABLE_OFFSET) & 0x1 ? (fe_resource_mark >> ACCOUNT2_OFFSET) & METER0_MASK : METER0_MASK;
	if ( 0 != meter0 && METER0_MASK != meter0 )
	{
		meter0 -= 1;
	}
	meter1 = (fe_resource_mark >> METER1_ENABLE_OFFSET) & 0x1 ? (fe_resource_mark >> ACCOUNT0_OFFSET) & METER1_MASK : METER1_MASK;
	if ( 0 != meter1 && METER1_MASK != meter1 )
	{
		meter1 -= 1;
	}
	meter2 = (fe_resource_mark >> METER2_ENABLE_OFFSET) & 0x1 ? (fe_resource_mark >> ACCOUNT1_OFFSET) & METER2_MASK : METER2_MASK;
	if ( 0 != meter2 && METER2_MASK != meter2 )
	{
		meter2 -= 1;
	}
	AIROHA_LOG(AIROHA_DEBUG_LEVEL_INFO, "%s %d get acnt0 [0x%x] acnt1 [0x%x] acnt2 [0x%x] meter0 [0x%x] meter1 [0x%x] meter2 [0x%x]\n", __func__, __LINE__, acnt0, acnt1, acnt2, meter0, meter1, meter2);

	*msg1 = ((*msg1 & ~QDMA_ETH_TXMSG_METER_MASK) | FIELD_PREP(QDMA_ETH_TXMSG_METER_MASK, meter0));
	*msg1 = ((*msg1 & ~QDMA_ETH_TXMSG_ACNT_G1_MASK) | FIELD_PREP(QDMA_ETH_TXMSG_ACNT_G1_MASK, acnt1));
	*msg1 = ((*msg1 & ~QDMA_ETH_TXMSG_ACNT_G0_MASK) | FIELD_PREP(QDMA_ETH_TXMSG_ACNT_G0_MASK, acnt0));
	*msg2 = ((*msg2 & ~QDMA_ETH_TXMSG_ACNT_G2_MASK) | FIELD_PREP(QDMA_ETH_TXMSG_ACNT_G2_MASK, acnt2));
	*msg2 = ((*msg2 & ~QDMA_ETH_TXMSG_METER_G1_MASK) | FIELD_PREP(QDMA_ETH_TXMSG_METER_G1_MASK, meter1));
	*msg2 = ((*msg2 & ~QDMA_ETH_TXMSG_METER_G2_MASK) | FIELD_PREP(QDMA_ETH_TXMSG_METER_G2_MASK, meter2));

	return;
}

static u32 airoha_get_ppe_nbq(struct sk_buff *skb, u32 tag,u8 fport)
{
	int port_id = 0;
	struct airoha_gdm_dev *dev =(struct airoha_gdm_dev *)netdev_priv(skb->dev);

	if (fport != FE_PSE_PORT_GDM1){
		return dev->nbq;
	}
	if (tag == 0 || (tag & (tag - 1)) != 0)
        return 0;

	while ((tag & 1) == 0) {
		tag >>= 1;
		port_id++;
	}
	return port_id;
}

int airoha_qdma_lan_tx(struct sk_buff *skb,u32 tag,u8 fport,int channel,int qid, u32 *msg1, u32 *msg2)
{
	struct port_info pinfo = {0};

	if(arht_xpon_sfu_ds_vlan_act_hook){
		if(arht_xpon_sfu_ds_vlan_act_hook(&skb, tag) == -1){
			return -1;
		}
	}
	
	arht_ppe_multicast_set_valid(skb);

	if(arht_hook_get_crsn(skb) == PPE_CPU_REASON_KEEPALIVE_WITH_DUP_OLD_PACKET)
		return 1;

	pinfo.stag = tag;
	pinfo.channel = channel;
	pinfo.txq = qid;
	pinfo.nbq = airoha_get_ppe_nbq(skb,tag,fport);
	if (glb_eth)
	{
		if(fport == glb_eth->soc->fport[SERDES_ETH_IDX])
		{
			if(xsi_speed[SERDES_ETH_IDX])
				glb_eth->qdma_init.xsi_ether_fastpath =
					(xsi_speed[SERDES_ETH_IDX] > fast_path_speed_threshold);
		}
	
		airoha_ppe_foe_flow_update_eth_offload(glb_eth->ppe, skb, &pinfo, fport);

		airoha_ppe_update_txmsg(skb, msg1, msg2);
		
#if defined(CONFIG_SUPPORT_QDMALAN_TR471)
		/* TR471 qdmaLAN speedtest TX offload */
		spin_lock_bh(&ppe_lock);
		if (skb->mark == DP_SPEED_UP) {
			struct airoha_foe_entry *hwe;
			hwe = airoha_ppe_foe_get_entry_locked(glb_eth->ppe, FOE_ENTRY_NUM(skb));
			if (NULL != hwe) {
				speedtest_lan_tx_offload(skb, hwe, glb_eth->ppe, &pinfo, glb_eth->soc->fport[SERDES_ETH_IDX]);
			}
		}
		spin_unlock_bh(&ppe_lock);
#endif

	}
	return 0;
}

void airoha_sfu_flow_offload_work(struct work_struct *work)
{
	if (!glb_eth)
		return;
	if (!glb_eth->npu)
		airoha_ppe_offload_setup(glb_eth);
}

void airoha_sfu_flow_offload_workqueue_init(void)
{
	/* INIT_WORK() must only be called once on a statically allocated
	 * work_struct. Calling it again while the work is pending or running
	 * corrupts the workqueue's internal linked list and causes a calltrace.
	 * Use atomic_cmpxchg to guarantee this is scheduled only once.
	 */
	if (atomic_cmpxchg(&airoha_sfu_offload_scheduled, 0, 1) == 0) {
		INIT_WORK(&airoha_sfu_flow_offload_workqueue, airoha_sfu_flow_offload_work);
		schedule_work(&airoha_sfu_flow_offload_workqueue);
	}
}

int is_from_lan_side(struct airoha_queue *q, struct airoha_eth *eth)
{
	int qid;
	
	if ( q && eth )
	{
		qid = q->qdma - &eth->qdma[0];
		/* qid: 0 - lan, 1 - wan */
		return (qid == 0);
	}
	
	return 0;
}
static void airoha_get_entry_bind(u32 msg1, struct airoha_queue *q, struct airoha_eth *eth, u32 sptag)
{
	u32 reason;
	u32 hash = FIELD_GET(AIROHA_RXD4_FOE_ENTRY, msg1);
	struct sk_buff *skb = q->skb;

	AIROHA_LOG(AIROHA_DEBUG_LEVEL_INFO, "Hash: %u\n", hash);
	if (hash < eth->soc->ppe_sram_etry_num)
		skb_set_hash(q->skb, hash,  PKT_HASH_TYPE_L4);

	/* only for upstream, down stream action in airoha_dev_xmit() */
	if ( is_from_lan_side(q, eth) )
	{
		if ( fe_resource_mark_acnt_hook )
		{
			fe_resource_mark_acnt_hook(skb, UP_STREAM);
		}
	}

	reason = FIELD_GET(AIROHA_RXD4_PPE_CPU_REASON, msg1);

	if((set_entry_reason_hook) && (hash < eth->soc->ppe_sram_etry_num))
		set_entry_reason_hook(q->skb,reason);

	AIROHA_LOG(AIROHA_DEBUG_LEVEL_INFO, "CPU_REASON: %u\n", reason);
	if (reason == PPE_CPU_REASON_HIT_UNBIND_RATE_REACHED){
		struct airoha_flow_table_entry *flow_e = airoha_flow_table_entry_get_by_hash(eth->ppe, hash);
		if(flow_e){
			flow_e->ingress_dev_idx = LAN_IDX_FROM_SPTAG(sptag);
			if(airoha_get_lan_id(q->skb->dev)==ETH2)
				flow_e->ingress_dev_idx = ETH2;
		}
		airoha_ppe_check_skb(&eth->ppe->dev, q->skb, hash, false);
		if(arht_xpon_igmp_sfu_enable_hook == NULL){
			arht_ppe_multicast_handler(eth->ppe, q->skb);
		}

	} else {
		if (!eth->npu) {			
			airoha_sfu_flow_offload_workqueue_init();
		}
	}
}


int airoha_qdma_multicast_init(struct airoha_eth *eth)
{
	int chnl_idx = 0;
	struct airoha_qdma *qdma = &eth->qdma[0];
	uint MULTICAST_FORCE_PORT[MULTICAST_MAX_CHANNEL];
	
	if(airoha_is_7581(eth)){
		uint temp[] = { ((1<<5)|0), ((1<<5)|1), ((1<<5)|2), ((1<<5)|3), 
		((1<<5)|4), ((1<<5)|5), ((0<<5)|0), ((4<<5)|0), 
		((3<<5)|0), ((3<<5)|1), ((3<<5)|4), ((3<<5)|5),
		((9<<5)|1), ((9<<5)|0), ((2<<5)|0), ((6<<5)|0),
		};
		memcpy(MULTICAST_FORCE_PORT, temp, sizeof(temp));
	}
	else{
		uint temp[] = { ((1<<5)|0), ((1<<5)|1), ((1<<5)|2), ((1<<5)|3), 
		((1<<5)|4), ((1<<5)|5), ((0<<5)|0), ((4<<5)|0), 
		((3<<5)|0), ((3<<5)|1), ((9<<5)|0), ((9<<5)|0),
		((9<<5)|1), ((3<<5)|0), ((2<<5)|0), ((6<<5)|0),
		};
		memcpy(MULTICAST_FORCE_PORT, temp, sizeof(temp));
	}	
	uint MULTICAST_SPECIAL_TAG[MULTICAST_MAX_CHANNEL] = { 0x0001, 0x0002, 0x0004, 0x0008, 
														  0x0010, 0x0020, 0x0000, 0x0000, 
														  0x0000, 0x0000, 0x0000, 0x0000,
														  0x0000, 0x0000, 0x0000, 0x0000,
														};
	uint MULTICAST_KEEP_SPTAG_HIFIELD[MULTICAST_MAX_CHANNEL] = {
		1, 1, 1, 1, 1, 1, 0, 0, 
		0, 0, 0, 0, 0, 0, 0, 0,
	};
	
	for( chnl_idx = 0; chnl_idx < MULTICAST_MAX_CHANNEL; chnl_idx++ ){
		/* init multicast fport info */
		qdmaSetMulticastFport(qdma, chnl_idx, MULTICAST_FORCE_PORT[chnl_idx]);

		/* init multicast sp_tag info */
		qdmaSetMulticastSptag(qdma, chnl_idx, MULTICAST_SPECIAL_TAG[chnl_idx]);

		/* init multicast sp_tag hi-field keep or not */
		if( MULTICAST_KEEP_SPTAG_HIFIELD[chnl_idx] > 0 ){
			qdmaEnableMulticastSptagKeepHi(qdma, chnl_idx);
		}else{
			qdmaDisableMulticastSptagKeepHi(qdma, chnl_idx);
		}
	}

	return 0;
}

/* For lan1~4, set to slow path by default
 * For ethx (10G ETH. Pon) set path by setting value 
 * Uplink: slow by default . Downlink: Fast by default
 */
void airoha_eth_qdma_fastpath_default_cfg(struct airoha_eth *eth)
{
	eth->qdma_init.wan_fastpath = 0;
	eth->qdma_init.lan_fastpath = 0;
	eth->qdma_init.xsi_ether_fastpath = 1;
	return;
}


int is_ethmac_nvmem_cell_available(struct airoha_eth *eth)
{
	struct device * dev = eth->dev;
	struct nvmem_cell *ethmac_cell = NULL;
	ethmac_cell = nvmem_cell_get(dev, "mac");
	if(IS_ERR(ethmac_cell)) {
		dev_err(dev, "nvmem cell error uinfor: %ld\n",PTR_ERR(ethmac_cell));
		if(PTR_ERR(ethmac_cell) == -EPROBE_DEFER)
			return -EPROBE_DEFER;
	}
	
	return 0;
}

int get_ethmac_from_dts(struct airoha_eth *eth)
{
	struct nvmem_cell *ethmac_cell = NULL;
	void *ethmac_data = NULL;
	uint8_t *ethmac_byte_ptr = NULL;
	size_t ethmac_retlen = 0;
	
	struct device * dev = eth->dev;
	ethmac_cell = nvmem_cell_get(dev, "mac");
	
	if(!IS_ERR(ethmac_cell)){
		ethmac_data = nvmem_cell_read(ethmac_cell, &ethmac_retlen);
		if(!IS_ERR(ethmac_data)){
			ethmac_byte_ptr = (uint8_t *)ethmac_data;
			if(ethmac_byte_ptr[0] != 0 || ethmac_byte_ptr[1] != 0 || ethmac_byte_ptr[2] != 0 
			|| ethmac_byte_ptr[3] != 0 || ethmac_byte_ptr[4] != 0 || ethmac_byte_ptr[5] != 0){
				memcpy(ethmac_addr, ethmac_byte_ptr, 6);
				printk("get ethmac=%02x:%02x:%02x:%02x:%02x:%02x \n", ethmac_addr[0],ethmac_addr[1],ethmac_addr[2],ethmac_addr[3],ethmac_addr[4],ethmac_addr[5]);
			}
			kfree(ethmac_data);
		}else{
			printk("get ethmac data fail\n");
		}
		nvmem_cell_put(ethmac_cell);
	}
	return 0;
}


/* qdma_wan Tx API */
int qdma_wan_tx(struct sk_buff *skb, u32 msg0, u32 msg1, struct port_info *pinfo)
{
	struct skb_shared_info *sinfo = skb_shinfo(skb);
	
	struct airoha_gdm_dev *dev = glb_eth->ports[1]->devs[0];
	
	struct net_device *netdev = dev->dev;
	struct airoha_foe_entry *hwe;
	u32  len = skb_headlen(skb);
	
	struct airoha_qdma *qdma = &glb_eth->qdma[1];
	struct airoha_queue_entry *e;
	LIST_HEAD(tx_list);
	
	u32 nr_frags = 1 + sinfo->nr_frags;
	struct netdev_queue *txq;
	struct airoha_queue *q;
	void *data;
	int i, qid;
	u16 index;
	u32 msg2 = 0;
	u8 fport;

	//qid = pinfo->channel;
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		msg0 |= FIELD_PREP(QDMA_ETH_TXMSG_TCO_MASK, 1) |
			FIELD_PREP(QDMA_ETH_TXMSG_UCO_MASK, 1) |
			FIELD_PREP(QDMA_ETH_TXMSG_ICO_MASK, 1);
	if(skb->mark == DP_SPEED_DOWNLOAD_ACK)	{
		msg0 |= FIELD_PREP(QDMA_ETH_TXMSG_TCO_MASK, 1);
	}
	
	if(isPriorityPkt(skb)) {
		msg0 |= FIELD_PREP(QDMA_ETH_TXMSG_QUEUE_MASK, 7);
		skb_set_queue_mapping(skb, 7);
	}
	else{
		u8 priority = skb->priority % AIROHA_NUM_QOS_QUEUES;
		priority = (AIROHA_NUM_QOS_QUEUES - 1) - priority;
		msg0  |= FIELD_PREP(QDMA_ETH_TXMSG_QUEUE_MASK, priority);
	}
	
	qid = skb_get_queue_mapping(skb);

	airoha_ppe_update_txmsg(skb, &msg1, &msg2);
	msg2 = ((msg2 & ~QDMA_ETH_TXMSG_SW_UDF) | FIELD_PREP(QDMA_ETH_TXMSG_SW_UDF, 0xffff));

	/* TSO: fill MSS info in tcp checksum field */
	if (skb_is_gso(skb)) {
		if (skb_cow_head(skb, 0))
			goto error;
                   if (skb_shinfo(skb)->gso_type & (SKB_GSO_TCPV4 |
						 SKB_GSO_TCPV6)) {
			__be16 csum = cpu_to_be16(skb_shinfo(skb)->gso_size);

			tcp_hdr(skb)->check = (__force __sum16)csum;
			msg0 |= FIELD_PREP(QDMA_ETH_TXMSG_TSO_MASK, 1);		
		}
	}	

	q = &qdma->q_tx[qid];
	if (WARN_ON_ONCE(!q->ndesc))
		goto error;
	if(arht_hook_get_crsn(skb) == PPE_CPU_REASON_KEEPALIVE_WITH_DUP_OLD_PACKET)
		goto error;

	fport = FIELD_GET(QDMA_ETH_TXMSG_FPORT_MASK, msg1);
	airoha_ppe_foe_flow_update_pon_offload(glb_eth->ppe, skb, pinfo, fport);

	spin_lock_irq(&q->lock);
	if(skb->mark == DP_SPEED_UP)
	{
		hwe = airoha_ppe_foe_get_entry_locked(glb_eth->ppe, FOE_ENTRY_NUM(skb));
		/* CID:923153 */
		if (NULL != hwe) {
		speedtest_tx_offload(skb,hwe,glb_eth->ppe,pinfo);
		}
	}

	txq = netdev_get_tx_queue(netdev, qid);
	if (q->queued + nr_frags >= q->ndesc) {
		/* not enough space in the queue */
		netif_tx_stop_queue(txq);
		spin_unlock_irq(&q->lock);
		return -1;
	}

	data = skb->data;

	e = list_first_entry(&q->tx_list, struct airoha_queue_entry,
			     list);
	index = e - q->entry;

	for (i = 0; i < nr_frags; i++) {
		struct airoha_qdma_desc *desc = &q->desc[index];
		skb_frag_t *frag = &sinfo->frags[i];
		dma_addr_t addr;
		u32 val;

		addr = dma_map_single(netdev->dev.parent, data, len,
				      DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(netdev->dev.parent, addr)))
			goto error_unmap;

		list_move_tail(&e->list, &tx_list);
		e->skb = i ? NULL : skb;
		e->dma_addr = addr;
		e->dma_len = len;

		e = list_first_entry(&q->tx_list, struct airoha_queue_entry,
				     list);
		index = e - q->entry;

		val = FIELD_PREP(QDMA_DESC_LEN_MASK, len);
		if (i < nr_frags - 1)
			val |= FIELD_PREP(QDMA_DESC_MORE_MASK, 1);
		WRITE_ONCE(desc->ctrl, cpu_to_le32(val));
		WRITE_ONCE(desc->addr, cpu_to_le32(addr));
		val = FIELD_PREP(QDMA_DESC_NEXT_ID_MASK, index);
		WRITE_ONCE(desc->data, cpu_to_le32(val));
		WRITE_ONCE(desc->msg0, cpu_to_le32(msg0));
		WRITE_ONCE(desc->msg1, cpu_to_le32(msg1));
		WRITE_ONCE(desc->msg2, cpu_to_le32(msg2));

		data = skb_frag_address(frag);
		len = skb_frag_size(frag);
	}

	q->queued += i;

	skb_tx_timestamp(skb);
	netdev_tx_sent_queue(txq, skb->len);
	
	skb->dev = netdev;

	if (netif_xmit_stopped(txq) || !netdev_xmit_more())
		airoha_qdma_rmw(qdma, REG_TX_CPU_IDX(qid),
				TX_RING_CPU_IDX_MASK,
				FIELD_PREP(TX_RING_CPU_IDX_MASK, index));

	if (q->ndesc - q->queued < q->free_thr)
		netif_tx_stop_queue(txq);

	spin_unlock_irq(&q->lock);

	return 0;

error_unmap:
	while (!list_empty(&tx_list)) {
		e = list_first_entry(&tx_list, struct airoha_queue_entry,
				     list);
		dma_unmap_single(netdev->dev.parent, e->dma_addr, e->dma_len,
				 DMA_TO_DEVICE);
		e->dma_addr = 0;
		list_move_tail(&e->list, &q->tx_list);
	}

	spin_unlock_irq(&q->lock);
error:
	dev_kfree_skb_any(skb);
	netdev->stats.tx_dropped++;

	return 0;
}
EXPORT_SYMBOL(qdma_wan_tx);

void arht_ppe_foe_flow_update_wifi_npu_offload(struct sk_buff *skb, struct port_info *pinfo)
{
	airoha_ppe_foe_flow_update_wifi_npu_offload(glb_eth->ppe, skb, pinfo);
}
EXPORT_SYMBOL(arht_ppe_foe_flow_update_wifi_npu_offload);

int arht_ppe_is_UNBIND_RATE_REACHED(struct sk_buff *skb)
{
	if (arht_hook_get_crsn(skb) == PPE_CPU_REASON_HIT_UNBIND_RATE_REACHED)
	{
		return 1;
	}

	return 0;
}
EXPORT_SYMBOL(arht_ppe_is_UNBIND_RATE_REACHED);

typedef struct
{
	unsigned int fwd_state;
	int (*handler_func)(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, unsigned int foe_index, unsigned int port_mask, int priority);
}PPE_MULTICAST_FWD_STATE_HANDLER;

static PPE_MULTICAST_FWD_STATE_HANDLER state_handler[]=
{
	{PPE_MULTICAST_FORWARD_STATE_LAN_ONLY,arht_multicast_hwnat_state_handler_lan_only},
	{PPE_MULTICAST_FORWARD_STATE_WLAN_ONLY,arht_multicast_hwnat_state_handler_wlan_only},
	{PPE_MULTICAST_FORWARD_STATE_XSI_ONLY,arht_multicast_hwnat_state_handler_xsi_only},
	{PPE_MULTICAST_FORWARD_STATE_LAN_HSGMII_1toN,arht_multicast_hwnat_state_handler_lan_hsgmii_1toN},
	{PPE_MULTICAST_FORWARD_STATE_UNKNOWN,arht_multicast_hwnat_state_handler_unknown},
};


static unsigned int arht_muliticast_get_forward_state(unsigned int port_mask, unsigned int local)
{
	if(MULTICAST_HSGMII_EXIST(port_mask))
	{
		if(MULTICAST_GSW_EXIST(port_mask))
		{
			return PPE_MULTICAST_FORWARD_STATE_LAN_HSGMII_1toN;
		}
		else
		{
			return PPE_MULTICAST_FORWARD_STATE_XSI_ONLY;
		}
	}
	if(MULTICAST_GSW_EXIST(port_mask))
	{
		return PPE_MULTICAST_FORWARD_STATE_LAN_ONLY;
	}
	
	if(MULTICAST_WLAN_EXIST(port_mask))
	{
		return PPE_MULTICAST_FORWARD_STATE_WLAN_ONLY;
	}
	
	return PPE_MULTICAST_FORWARD_STATE_UNKNOWN;
}

/* clear all fields in foe_entry besides info1 and old info */
void clear_foe_entry(struct airoha_foe_entry *hwe)
{
	int type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, hwe->ib1);
	int offset = sizeof(hwe->ib1);

	if (type == PPE_PKT_TYPE_BRIDGE) {
		offset += offsetof(struct airoha_foe_bridge, data);
	} else if (type >= PPE_PKT_TYPE_IPV6_ROUTE_3T) {
		offset += offsetof(struct airoha_foe_ipv6, data);
	} else {
		offset += offsetof(struct airoha_foe_ipv4, ib2);
	}
	memset((char *)hwe + offset, 0, PPE_ENTRY_SIZE - offset);

	return;
}
EXPORT_SYMBOL(clear_foe_entry);


int arht_set_multicast_hwnat_info(struct sk_buff* skb, struct airoha_foe_entry *hwe)
{
	spin_lock_bh(&ppe_lock);
	/* Clear all fields in foe_entry besides info1 and old info */
	clear_foe_entry(hwe);
	
	/* Set Layer2 Info */
	if (PpeFillInL2Info(skb, hwe)) {
		spin_unlock_bh(&ppe_lock);
		return 0;
	}

	/* Set Layer3 Info */
	if (PpeFillInL3Info(skb, hwe)) {
		spin_unlock_bh(&ppe_lock);
		return 0;
	}
	spin_unlock_bh(&ppe_lock);

	return 1;
}
EXPORT_SYMBOL(arht_set_multicast_hwnat_info);


int arht_multicast_hwnat_state_handler(struct airoha_foe_entry *hwe, unsigned int foe_index,unsigned int port_mask,unsigned int local,int priority)
{
	unsigned int fwd_state = arht_muliticast_get_forward_state(port_mask, local);
	int i = 0;
    struct airoha_ppe *ppe = glb_eth->ppe;

	
	for(i = 0;i < PPE_MULTICAST_STATE_HANDLER_NUM;i++)
	{
		if(fwd_state == state_handler[i].fwd_state)
			return state_handler[i].handler_func(ppe, hwe, foe_index, port_mask,priority);
	}

	return 0;
}
EXPORT_SYMBOL(arht_multicast_hwnat_state_handler);

int arht_multicast_get_channel_by_stag(unsigned int stag_dp)
{
	int i, channel = 1, max_speed = 0;
	
	for (i = 0; i < 4; i++) {
		if(stag_dp & BIT(i+1)) {
			if(max_speed <= gsw_speed[i]) {
				max_speed = gsw_speed[i];
				channel = i+1;
			}
			if(max_speed == 1000) {
				break;
			}
		}
	}
	return channel ;
}

static void arht_multicast_hwnat_state_handler_common
	(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, unsigned int foe_index,
	u32 data, u32 val, unsigned int stag_dp)
{
	int type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, hwe->ib1);

	switch (type) {
		case PPE_PKT_TYPE_IPV4_ROUTE:
		case PPE_PKT_TYPE_IPV4_HNAPT:
			hwe->ipv4.data = data;
			hwe->ipv4.ib2 = val;
			hwe->ipv4.l2.common.etype = stag_dp;
			hwe->ipv4.new_tuple.src_ip = hwe->ipv4.orig_tuple.src_ip;
			hwe->ipv4.new_tuple.dest_ip = hwe->ipv4.orig_tuple.dest_ip;
			break;
		
		case PPE_PKT_TYPE_BRIDGE:
			hwe->bridge.data = data;
			hwe->bridge.ib2 = val;
			hwe->bridge.l2.common.etype = stag_dp;
			break;
		
		case PPE_PKT_TYPE_IPV6_ROUTE_3T:
		case PPE_PKT_TYPE_IPV6_ROUTE_5T:
		case PPE_PKT_TYPE_IPV6_6RD:
			hwe->ipv6.data = data;
			hwe->ipv6.ib2 = val;
			hwe->ipv6.l2.etype = stag_dp;
			break;
			
		case PPE_PKT_TYPE_IPV4_DSLITE:
			hwe->dslite.data = data;
			hwe->dslite.ib2 = val;
			hwe->dslite.l2.common.etype = stag_dp;
			break;
			
		default:
			break;
	}

	spin_lock_bh(&ppe_lock);
	airoha_ppe_foe_commit_entry_ptr(ppe, hwe, foe_index,1);
	spin_unlock_bh(&ppe_lock);
	
	return;
}

int arht_multicast_hwnat_state_handler_lan_only(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, unsigned int foe_index, unsigned int  port_mask, int priority)
{
	unsigned int stag_dp = 0;
	int i = 0, channel = 1;
	u32 data, val;
	int wifi_flag = !!MULTICAST_WLAN_EXIST(port_mask);

	if(!arht_ppe_multicast_check_valid(ppe, hwe, foe_index))
		return 0;
	
	hwe->ib1 &= ~AIROHA_FOE_IB1_BIND_STATE;
	hwe->ib1 |= FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND);
				
	for(i = 0;i < 4;i++)
	{
		if(port_mask&(1<<i))
		{
			stag_dp |= (1<<(i+1));
		}
	}
	
	channel = arht_multicast_get_channel_by_stag(stag_dp);
	val = FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x1f) |
		  FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_GDM1) |
			  AIROHA_FOE_IB2_PSE_QOS | FIELD_PREP(AIROHA_FOE_IB2_NBQ, channel) |
			  FIELD_PREP(AIROHA_FOE_IB2_MULTICAST, wifi_flag);
	
	data = FIELD_PREP(AIROHA_FOE_CHANNEL, channel) |
	       			FIELD_PREP(AIROHA_FOE_SHAPER_ID, 0x7F);

	arht_multicast_hwnat_state_handler_common(ppe, hwe, foe_index, data, val, stag_dp);
	
	return 0;
}

int arht_multicast_hwnat_state_handler_wlan_only
	(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, unsigned int foe_index, unsigned int  port_mask, int priority)
{
	int channel = 0;
	u32 data, val;

	if(!arht_ppe_multicast_check_valid(ppe, hwe, foe_index))
		return 0;
	
	hwe->ib1 &= ~AIROHA_FOE_IB1_BIND_STATE;
	hwe->ib1 |= FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND);
				
	val = FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x1f) |
		  FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_CDM1) |
			  FIELD_PREP(AIROHA_FOE_IB2_NBQ, 11);
	
	data = FIELD_PREP(AIROHA_FOE_CHANNEL, channel) |
	       			FIELD_PREP(AIROHA_FOE_SHAPER_ID, 0x7F);

	arht_multicast_hwnat_state_handler_common(ppe, hwe, foe_index, data, val, PPE_UDF_MULTICAST);

	return 0;
}

int arht_multicast_hwnat_state_handler_xsi_only(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, unsigned int foe_index, unsigned int  port_mask, int priority)
{
	int channel = 1;
	/* CID:897766 */
	u32 data = 0, val = 0;
	int nbq=0;
	struct airoha_eth *eth = glb_eth;
	int wifi_flag = !!MULTICAST_WLAN_EXIST(port_mask);

	if(!arht_ppe_multicast_check_valid(ppe, hwe, foe_index))
		return 0;
	
	hwe->ib1 &= ~AIROHA_FOE_IB1_BIND_STATE;
	hwe->ib1 |= FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND);

	if(port_mask & IS_ETH_SERDES)
	{
		val = FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x1f) | AIROHA_FOE_IB2_PSE_QOS | 
		  	FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, eth->soc->fport[SERDES_ETH_IDX]);
		
		nbq = eth->soc->nbq[SERDES_ETH_IDX];
		channel =eth->soc->chnl[SERDES_ETH_IDX];
	}
		
	if(port_mask & IS_USB_SERDES)
	{
		val = FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x1f) | AIROHA_FOE_IB2_PSE_QOS | 
		  	FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, eth->soc->fport[SERDES_USB_IDX]);
		nbq = eth->soc->nbq[SERDES_USB_IDX];
		channel = eth->soc->chnl[SERDES_USB_IDX];
	}

	if(port_mask & IS_PCIE0_SERDES)
	{
		val = FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x1f) | AIROHA_FOE_IB2_PSE_QOS | 
		  	FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, eth->soc->fport[SERDES_PCIE0_IDX]);
		nbq = eth->soc->nbq[SERDES_PCIE0_IDX];
		channel = eth->soc->chnl[SERDES_PCIE0_IDX];
	}

	if(port_mask & IS_PCIE1_SERDES)
	{
		val = FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x1f) | AIROHA_FOE_IB2_PSE_QOS | 
		  	FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, eth->soc->fport[SERDES_PCIE1_IDX]);
		nbq = eth->soc->nbq[SERDES_PCIE1_IDX];
		channel = eth->soc->chnl[SERDES_PCIE1_IDX];
	}
		
	data = FIELD_PREP(AIROHA_FOE_CHANNEL, channel) |
	       FIELD_PREP(AIROHA_FOE_QID, 
				((AIROHA_NUM_QOS_QUEUES - 1) - (priority % AIROHA_NUM_QOS_QUEUES))) |
	       FIELD_PREP(AIROHA_FOE_SHAPER_ID, 0x7F) ;
	val |= FIELD_PREP(AIROHA_FOE_IB2_NBQ, nbq) | 
		FIELD_PREP(AIROHA_FOE_IB2_MULTICAST, wifi_flag);

	arht_multicast_hwnat_state_handler_common(ppe, hwe, foe_index, data, val, 0);

	return 0;
}


int arht_multicast_hwnat_state_handler_lan_hsgmii_1toN(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, unsigned int foe_index, unsigned int  port_mask, int priority)
{
	unsigned int stag_dp = 0;
	int i = 0, channel = 0, nbq = 0;
	u32 data, val;
	int wifi_flag = !!MULTICAST_WLAN_EXIST(port_mask);

	if(!arht_ppe_multicast_check_valid(ppe, hwe, foe_index))
		return 0;
	
	hwe->ib1 &= ~AIROHA_FOE_IB1_BIND_STATE;
	hwe->ib1 |= FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND);
				
	for(i = 0;i < 4;i++)
	{
		if(port_mask&(1<<i))
		{
			stag_dp |= (1<<(i+1));
		}
	}

	if(port_mask & IS_ETH_SERDES){
		nbq |= (1<<2);
	}
	
	if(port_mask & IS_USB_SERDES){
		nbq |= (1<<1);
	}

	if(port_mask & IS_PCIE0_SERDES){
		channel |= (1<<4);
	}
	
	if(port_mask & IS_PCIE1_SERDES){
		nbq |= (1<<0);
	}
		
	val = FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x1f) |
		  FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_MCST) | 
		  AIROHA_FOE_IB2_PSE_QOS | FIELD_PREP(AIROHA_FOE_IB2_NBQ, nbq) |
		  FIELD_PREP(AIROHA_FOE_IB2_MULTICAST, wifi_flag);
	
	data = FIELD_PREP(AIROHA_FOE_CHANNEL, channel) |
					FIELD_PREP(AIROHA_FOE_SHAPER_ID, 0x7F);
	
	arht_multicast_hwnat_state_handler_common(ppe, hwe, foe_index, data, val, stag_dp);
	
	return 0;
	
}


int arht_multicast_hwnat_state_handler_unknown(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, unsigned int foe_index, unsigned int  port_mask, int priority)
{
	u32 val;
	int type;
	
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

	spin_lock_bh(&ppe_lock);
	airoha_ppe_foe_commit_entry_ptr(ppe, hwe, foe_index,1);
	spin_unlock_bh(&ppe_lock);
	
	return 0;
}

int arht_multicast_hwnat_clean(unsigned int foe_index)
{
	struct airoha_foe_entry *hwe;
	if(glb_eth == NULL)
		return 0;
	
	hwe = airoha_ppe_foe_get_entry_locked(glb_eth->ppe, foe_index);
	if(hwe == NULL)
		return 0;
	
	airoha_ppe_delete_entry(glb_eth->ppe,hwe,foe_index);

	return 0;
}
EXPORT_SYMBOL(arht_multicast_hwnat_clean);

int arht_multicast_hwnat_list_update(MULTICAST_HWNATENTRY_t* entry, unsigned int update_mode,unsigned int port_mask,unsigned int local)
{
	unsigned int foe_index = 0;
	struct airoha_ppe *ppe = glb_eth->ppe;
	struct airoha_foe_entry *hwe;

	
    if ((PPE_MULTICAST_HWNATENTRY_STATE_UNBIND == entry->state)
        || (entry->port_mask == port_mask))
	{
		return -1;
	}
	else
	{
		foe_index = entry->foe_index;
		entry->port_mask  = port_mask;
		local = entry->local;

		if (0 == port_mask)
			entry->state = PPE_MULTICAST_HWNATENTRY_STATE_DROP;
		else
			entry->state = PPE_MULTICAST_HWNATENTRY_STATE_BINDED;
		hwe = airoha_ppe_foe_get_entry_locked(ppe, foe_index);
		arht_multicast_hwnat_state_handler(hwe,foe_index,port_mask,local,0);
		return 0;
	}
}
EXPORT_SYMBOL(arht_multicast_hwnat_list_update);

int arht_multicast_hwnat_list_update_lan(MULTICAST_HWNATENTRY_t* entry, unsigned int update_mode,unsigned int port_mask,unsigned int local)
{
	unsigned int foe_index = 0;
	struct airoha_ppe *ppe = glb_eth->ppe;
	struct airoha_foe_entry *hwe;

	
    if ((PPE_MULTICAST_HWNATENTRY_STATE_UNBIND == entry->state)
        || (entry->port_mask == port_mask))
	{
		return -1;
	}
	else
	{
		foe_index = entry->foe_index;
		entry->port_mask  = port_mask;
		local = entry->local;

		if (0 == port_mask)
			entry->state = PPE_MULTICAST_HWNATENTRY_STATE_DROP;
		else
			entry->state = PPE_MULTICAST_HWNATENTRY_STATE_BINDED;
		hwe = airoha_ppe_foe_get_entry_locked(ppe, foe_index);
		/* CID:930107 */
		if (NULL == hwe) {
			return -1;
		}
		if (IS_IPV4_GRP(hwe)) {
			hwe->ipv4.new_tuple.src_ip = hwe->ipv4.orig_tuple.src_ip;
			hwe->ipv4.new_tuple.dest_ip = hwe->ipv4.orig_tuple.dest_ip;
		}

		arht_multicast_hwnat_state_handler(hwe,foe_index,port_mask,local,0);
		return 0;
	}
}
EXPORT_SYMBOL(arht_multicast_hwnat_list_update_lan);

int32_t FillSpeedtestEntryInfo(struct sk_buff * skb, struct airoha_foe_entry *foe_entry)
{
	int index=0;
	struct hwnat_shrink_field shrinkField = {0};

	struct ethhdr *eth = NULL;
	struct vlan_hdr *vh = NULL;
	struct pppoe_hdr *peh= NULL;

	uint16_t eth_type;
	uint16_t vlan=0,pppoe_sid=0,eth_type_origin=0;
	
	skb_reset_mac_header(skb);

	eth = (struct ethhdr *)skb->data;
	eth_type_origin =ntohs(eth->h_proto);
	eth_type=eth->h_proto;
	skb->data += ETH_HLEN;
	if(eth->h_proto== htons(0x8100))
	{
		vh = (struct vlan_hdr *)(skb->data);
		eth_type =vh->h_vlan_encapsulated_proto;
		skb->data += VLAN_HLEN;
		foe_entry->ib1 = (foe_entry->ib1 & ~(AIROHA_FOE_IB1_BIND_VPM | AIROHA_FOE_IB1_BIND_VLAN_LAYER)) | 
								FIELD_PREP(AIROHA_FOE_IB1_BIND_VLAN_LAYER, 1) | 
								FIELD_PREP(AIROHA_FOE_IB1_BIND_VPM, 1) ;
		vlan= ntohs(vh->h_vlan_TCI);
	}

	if(eth_type == htons(ETH_P_PPP_SES)){

		peh = (struct pppoe_hdr *)(skb->data);
		if (peh->ver != 1 || peh->type != 1)
		return 1;
		pppoe_sid=ntohs(peh->sid);
		skb->data += 8;
		foe_entry->ib1 = (foe_entry->ib1 & ~AIROHA_FOE_IB1_BIND_PPPOE) | 
									FIELD_PREP(AIROHA_FOE_IB1_BIND_PPPOE, 1);
	}


	skb_reset_network_header(skb);
	PpeClearEntryInfo(foe_entry);
	if ((eth_type == htons(ETH_P_IP)) || (eth_type == htons(ETH_P_PPP_SES)
		&& peh->tag[0].tag_type == htons(PPP_IP))) 
	/* Set VLAN Info - VLAN1/VLAN2 */
	/* Set Layer2 Info - DMAC, SMAC */
 {
 			
            FoeSetEntryMac(eth->h_dest,&(foe_entry->ipv4.l2.common.dest_mac_hi),&(foe_entry->ipv4.l2.common.dest_mac_lo));
            FoeSetEntryMac(eth->h_source,&(foe_entry->ipv4.l2.common.src_mac_hi),&(foe_entry->ipv4.l2.src_mac_lo));
			foe_entry->ipv4.l2.common.vlan1 = vlan;
			foe_entry->ipv4.l2.pppoe_id= pppoe_sid;
			if(eth->h_proto== htons(0x8100))
			foe_entry->ipv4.l2.common.etype = eth_type_origin;

			foe_entry->ipv4.new_tuple.src_ip = foe_entry->ipv4.orig_tuple.src_ip;
			foe_entry->ipv4.new_tuple.dest_ip = foe_entry->ipv4.orig_tuple.dest_ip;

			foe_entry->ipv4.new_tuple.src_port= foe_entry->ipv4.orig_tuple.src_port;
			foe_entry->ipv4.new_tuple.dest_port= foe_entry->ipv4.orig_tuple.dest_port;

			
		
	} 
	else {
			// if smac doesn't change,then smac_idx[4]=1; else, smac_idx[3:0] =0~15
			if(cmpMacInfo(eth->h_source, skb->data) == HWNAT_SUCCESS) {
				set_ppe_entry_smac_index(foe_entry, PPE_PKT_TYPE_IPV6_ROUTE_5T, 0x10);
			} else {
				memcpy(shrinkField.smac, eth->h_source, ETH_ALEN);

				index = find_and_update_shrink_table(PPE_UPDMEM_SEL_SMAC, &shrinkField);
				if(index != -1) {
					set_ppe_entry_smac_index(foe_entry, PPE_PKT_TYPE_IPV6_ROUTE_5T, index);
				} else {
					printk("smac: find and update shrink table failed!\n");
				}
			}
            FoeSetEntryMac(eth->h_dest,&(foe_entry->ipv6.l2.dest_mac_hi), &(foe_entry->ipv6.l2.dest_mac_lo));

			foe_entry->ipv6.l2.vlan1 = vlan;
			foe_entry->ipv6.l2.src_mac_hi = (foe_entry->ipv6.l2.src_mac_hi & ~AIROHA_FOE_MAC_PPPOE_ID) | 
										FIELD_PREP(AIROHA_FOE_MAC_PPPOE_ID, pppoe_sid);
			if(eth->h_proto== htons(0x8100))
			foe_entry->ipv6.l2.etype = eth_type_origin;
	}

	return 0;
}


int isValidPpeEntry(struct sk_buff *skb, struct airoha_foe_entry *foe_entry)
{
	unsigned char dmac[ETH_ALEN];
	memset(dmac, 0, sizeof(dmac));

	if (IS_IPV4_GRP(foe_entry)) {
		if ((foe_entry->ipv4.orig_tuple.src_ip== 0) && (foe_entry->ipv4.orig_tuple.dest_ip== 0))
			return 0;
	} else if (IS_IPV6_GRP(foe_entry)) {
		if ((foe_entry->ipv6.src_ip[0] == 0) && (foe_entry->ipv6.src_ip[1] == 0)
			&& (foe_entry->ipv6.src_ip[2] == 0) && (foe_entry->ipv6.src_ip[3] == 0)
			&& (foe_entry->ipv6.dest_ip[0] == 0) && (foe_entry->ipv6.dest_ip[1] == 0)
			&& (foe_entry->ipv6.dest_ip[2] == 0) && (foe_entry->ipv6.dest_ip[3] == 0))
			return 0;
	} else if (IS_L2_RRIDGE(foe_entry)) {
		//do nothing

	} else {
		return 1;
	}

	return 1;
}

#if defined(CONFIG_SUPPORT_QDMALAN_TR471)
void SetSpeedtestPortInfo(struct airoha_foe_entry * foe_entry, struct port_info *pinfo, u32 fport)
{

  
    u32 channel = 0, qdata=0, val=0, priority=0;
	foe_entry->ib1 = (foe_entry->ib1 & ~(AIROHA_FOE_IB1_BIND_STATE)) | 
					FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND);

	val = FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x1f) |
		  FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, fport) | 
		  FIELD_PREP(AIROHA_FOE_IB2_NBQ, pinfo->channel) | 
		  AIROHA_FOE_IB2_PSE_QOS;

	if (glb_eth){
		if(glb_eth->qdma_init.speedtest_fastpath){
			val |= AIROHA_FOE_IB2_FAST_PATH;
		}
	}

	channel = pinfo->channel;

	qdata = FIELD_PREP(AIROHA_FOE_CHANNEL, channel) |
	       FIELD_PREP(AIROHA_FOE_QID, priority) |
	       FIELD_PREP(AIROHA_FOE_SHAPER_ID, 0x7f);

	if (IS_IPV4_GRP(foe_entry)) 
	{
		foe_entry->ipv4.l2.common.etype = pinfo->stag;
		foe_entry->ipv4.data = qdata;
		foe_entry->ipv4.ib2 = val;
	}else  
	{
		foe_entry->ipv6.l2.etype = pinfo->stag;
		foe_entry->ipv6.data = qdata;
		foe_entry->ipv6.ib2 = val;
	}

	return ;

}

int speedtest_tx_offload(struct sk_buff * skb, struct airoha_foe_entry *foe_entry,struct airoha_ppe *ppe,struct port_info *pinfo)
{
	int ret = 0;
	u32 foe_entry_idx= 0;
	struct airoha_gdm_dev *gdm_dev;
  /* this check is for: onu as iperf server, ethernet lan pc as iperf client 
   * The condition is that when the interface name is "eth" and the skb is not associated with
   * WAN interface,the speedtest_tx_offload is skipped
   */
	if(skb->dev && memcmp(skb->dev->name,"eth",3) == 0)
	{
		gdm_dev = airoha_ppe_get_gdm_dev(glb_eth, skb->dev);
		if (arht_is_valid_gdm_dev(glb_eth, gdm_dev) && !(gdm_dev->flags & AIROHA_PRIV_F_WAN))
			return 0;
	}

	
	foe_entry_idx = skb->hash & AIROHA_PPE_ENTRY_MASK;
	
	/* get start fill entry for each layer */
	FillSpeedtestEntryInfo(skb, foe_entry);

	if(!isValidPpeEntry(skb, foe_entry)) {
		skb->hash = 0;
		ret = 1;
		skb->data = skb_mac_header(skb);
		return ret;
	}

	/* Set force port info */
	SetSpeedtestPortInfo(foe_entry,pinfo,FE_PSE_PORT_GDM2);

	airoha_ppe_foe_commit_entry_ptr(ppe,foe_entry,foe_entry_idx,1);		
	ret = 1;
	skb->data = skb_mac_header(skb);
	return ret;
}

int speedtest_lan_tx_offload(struct sk_buff *skb, struct airoha_foe_entry *foe_entry, struct airoha_ppe *ppe, struct port_info *pinfo, u32 fport)
{
	int ret = 0;
	u32 foe_entry_idx = 0;

	foe_entry_idx = skb->hash & AIROHA_PPE_ENTRY_MASK;

	/* get start fill entry for each layer */
	FillSpeedtestEntryInfo(skb, foe_entry);

	if(!isValidPpeEntry(skb, foe_entry)) {
		skb->hash = 0;
		ret = 1;
		skb->data = skb_mac_header(skb);
		return ret;
	}

	/* Set force port info for QDMALAN */
	SetSpeedtestPortInfo(foe_entry, pinfo, fport);

	airoha_ppe_foe_commit_entry_ptr(ppe,foe_entry,foe_entry_idx,1);		
	ret = 1;
	skb->data = skb_mac_header(skb);
	return ret;
}
#else
void SetSpeedtestPortInfo(struct airoha_foe_entry * foe_entry, struct airoha_ppe *ppe,struct port_info *pinfo)
{

  
    u32 channel = 0, qdata=0, val=0, priority=0;
	foe_entry->ib1 = (foe_entry->ib1 & ~(AIROHA_FOE_IB1_BIND_STATE)) | 
					FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND);

	val = FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x1f) |
		  FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_GDM2) | 
		  FIELD_PREP(AIROHA_FOE_IB2_NBQ, pinfo->channel) | 
		  AIROHA_FOE_IB2_PSE_QOS;

	if(glb_eth->qdma_init.speedtest_fastpath){
		val |= AIROHA_FOE_IB2_FAST_PATH;
	}

	channel = pinfo->channel;

	qdata = FIELD_PREP(AIROHA_FOE_CHANNEL, channel) |
	       FIELD_PREP(AIROHA_FOE_QID, priority) |
	       FIELD_PREP(AIROHA_FOE_SHAPER_ID, 0x7f);

	if (IS_IPV4_GRP(foe_entry)) 
	{
		foe_entry->ipv4.l2.common.etype = pinfo->stag;
		foe_entry->ipv4.data = qdata;
		foe_entry->ipv4.ib2 = val;
	}else  
	{
		foe_entry->ipv6.l2.etype = pinfo->stag;
		foe_entry->ipv6.data = qdata;
		foe_entry->ipv6.ib2 = val;
	}

	return ;

}
int speedtest_tx_offload(struct sk_buff * skb, struct airoha_foe_entry *foe_entry,struct airoha_ppe *ppe,struct port_info *pinfo)
{
	int ret = 0;
	u32 foe_entry_idx= 0;
	struct airoha_gdm_dev *gdm_dev;
  /* this check is for: onu as iperf server, ethernet lan pc as iperf client 
   * The condition is that when the interface name is "eth" and the skb is not associated with
   * WAN interface,the speedtest_tx_offload is skipped
   */
	if(skb->dev && memcmp(skb->dev->name,"eth",3) == 0)
	{
		gdm_dev = airoha_ppe_get_gdm_dev(glb_eth, skb->dev);
		if (arht_is_valid_gdm_dev(glb_eth, gdm_dev) && !(gdm_dev->flags & AIROHA_PRIV_F_WAN))
			return 0;
	}

	
	foe_entry_idx = skb->hash & AIROHA_PPE_ENTRY_MASK;
	
	/* get start fill entry for each layer */
	FillSpeedtestEntryInfo(skb, foe_entry);

	if(!isValidPpeEntry(skb, foe_entry)) {
		skb->hash = 0;
		ret = 1;
		skb->data = skb_mac_header(skb);
		return ret;
	}

	/* Set force port info */
	SetSpeedtestPortInfo(foe_entry,ppe,pinfo);

	airoha_ppe_foe_commit_entry_ptr(ppe,foe_entry,foe_entry_idx,1);		
	ret = 1;
	skb->data = skb_mac_header(skb);
	return ret;
}
#endif

void SetTR471PortInfo(struct airoha_foe_entry * foe_entry)
{
    u32  qdata=0, val=0;
	foe_entry->ib1 = (foe_entry->ib1 & ~(AIROHA_FOE_IB1_BIND_STATE)) | 
					FIELD_PREP(AIROHA_FOE_IB1_BIND_STATE, AIROHA_FOE_STATE_BIND);

	val = FIELD_PREP(AIROHA_FOE_IB2_PORT_AG, 0x1f) |
		  FIELD_PREP(AIROHA_FOE_IB2_PSE_PORT, FE_PSE_PORT_CDM4) | 
		  FIELD_PREP(AIROHA_FOE_IB2_FAST_PATH, 1) |
		  FIELD_PREP(AIROHA_FOE_IB2_PSE_QOS, 1) |
		  FIELD_PREP(AIROHA_FOE_IB2_NBQ, 2);


	qdata = FIELD_PREP(AIROHA_FOE_SHAPER_ID, 0x7f);

	if (IS_IPV4_GRP(foe_entry)) 
	{
		foe_entry->ipv4.data = qdata;
		foe_entry->ipv4.ib2 = val;
	}else  
	{
		foe_entry->ipv6.data = qdata;
		foe_entry->ipv6.ib2 = val;
	}

	return ;

}
int32_t FillTR471EntryInfo(struct sk_buff * skb, struct airoha_foe_entry *foe_entry)
{

	unsigned char srcmac[6] = {0x22,0x88,0x77,0x33,0x55,0xdd};

	struct ethhdr *eth = NULL;
	struct vlan_hdr *vh = NULL;
	struct pppoe_hdr *peh= NULL;
	int offset =0;
	uint16_t eth_type;
	uint16_t vlan=0,pppoe_sid=0,eth_type_origin=0;
	

	eth = (struct ethhdr *)(skb->data - 14);
	eth_type_origin =ntohs(eth->h_proto);
	eth_type=eth->h_proto;
	if(eth->h_proto== htons(0x8100))
	{
		vh = (struct vlan_hdr *)(skb->data);
		eth_type =vh->h_vlan_encapsulated_proto;
		vlan= ntohs(vh->h_vlan_TCI);
		offset = VLAN_HLEN;
	}

	if(eth_type == htons(ETH_P_PPP_SES)){

		peh = (struct pppoe_hdr *)(skb->data + offset);
		if (peh->ver != 1 || peh->type != 1)
		return 1;
		pppoe_sid=ntohs(peh->sid);
	}

	PpeClearEntryInfo(foe_entry);
	if ((eth_type == htons(ETH_P_IP)) || (eth_type == htons(ETH_P_PPP_SES)
		&& peh->tag[0].tag_type == htons(PPP_IP))) 
	/* Set VLAN Info - VLAN1/VLAN2 */
	/* Set Layer2 Info - DMAC, SMAC */
 {
 			
            FoeSetEntryMac(eth->h_dest,&(foe_entry->ipv4.l2.common.dest_mac_hi),&(foe_entry->ipv4.l2.common.dest_mac_lo));
            FoeSetEntryMac(srcmac,&(foe_entry->ipv4.l2.common.src_mac_hi),&(foe_entry->ipv4.l2.src_mac_lo));
//			if(eth->h_proto== htons(0x8100))
//			foe_entry->ipv4.l2.common.etype = eth_type_origin;

			foe_entry->ipv4.new_tuple.src_ip = foe_entry->ipv4.orig_tuple.src_ip;
			foe_entry->ipv4.new_tuple.dest_ip = foe_entry->ipv4.orig_tuple.dest_ip;

			foe_entry->ipv4.new_tuple.src_port= foe_entry->ipv4.orig_tuple.src_port;
			foe_entry->ipv4.new_tuple.dest_port= foe_entry->ipv4.orig_tuple.dest_port;			
		
	} 
	else {
			// if smac doesn't change,then smac_idx[4]=1; else, smac_idx[3:0] =0~15
//			if(cmpMacInfo(srcmac, skb->data) == HWNAT_SUCCESS) {
				set_ppe_entry_smac_index(foe_entry, PPE_PKT_TYPE_IPV6_ROUTE_5T, 0x10);
//			} else {
//				memcpy(shrinkField.smac, srcmac, ETH_ALEN);

//				index = find_and_update_shrink_table(PPE_UPDMEM_SEL_SMAC, &shrinkField);
//				if(index != -1) {
//					set_ppe_entry_smac_index(foe_entry, PPE_PKT_TYPE_IPV6_ROUTE_5T, index);
//				} else {
//					printk("smac: find and update shrink table failed!\n");
//				}
//			}
            FoeSetEntryMac(eth->h_dest,&(foe_entry->ipv6.l2.dest_mac_hi), &(foe_entry->ipv6.l2.dest_mac_lo));

			
//			foe_entry->ipv6.l2.src_mac_hi = (foe_entry->ipv6.l2.src_mac_hi & ~AIROHA_FOE_MAC_PPPOE_ID) | 
//										FIELD_PREP(AIROHA_FOE_MAC_PPPOE_ID, pppoe_sid);
//			if(eth->h_proto== htons(0x8100))
//			foe_entry->ipv6.l2.etype = eth_type_origin;
	}

	return 0;
}

int tr471_downstream_offload(struct sk_buff * skb,struct airoha_eth *eth)
{
	/* CID:930520 */
	if ((NULL == skb) || (NULL == eth))
	{
		return -1;
	}

	int ret = 0;
	u32 foe_entry_idx= 0;
	struct airoha_foe_entry *foe_entry;
//	foe_entry_idx = skb->hash;
	foe_entry_idx = FOE_ENTRY_NUM(skb);
	foe_entry = airoha_ppe_foe_get_entry(eth->ppe, foe_entry_idx);
	if (foe_entry == NULL)
	{
		return -1;
	}
	/* get start addr for each layer */
	if (FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, foe_entry->ib1) == AIROHA_FOE_STATE_BIND) {
		skb->hash = 0;
		ret = 0;
		goto finish;
	}
	/* get start fill entry for each layer */
	if (FillTR471EntryInfo(skb, foe_entry)) {

		goto finish;
	}
		/* Enter binding state */
	if(isValidPpeEntry(skb, foe_entry)) {
		/* Set force port info */
		SetTR471PortInfo(foe_entry);
	} else {
		skb->hash = 0;
		ret = 1;
		goto finish;
	}
	airoha_ppe_foe_commit_entry_ptr(eth->ppe,foe_entry,foe_entry_idx,1);		
	ret = 1;
finish:
	return ret;
}
void  qdma_get_tr471_rxmsg(int rx_ring,unsigned int * rx_byte_cnt_l,unsigned int * rx_byte_cnt_h,unsigned int * err_cnt,unsigned int * drop_cnt)
{

	struct airoha_qdma *qdma = &glb_eth->qdma[1];
	struct airoha_queue *q;
	q=&qdma->q_rx[rx_ring];


	struct airoha_qdma_desc rxdesc;
	TR471_RX_DSCP_T *pRxD;
//	memcpy(&rxdesc, &q->desc[(q->head+ q->ndesc-1)% q->ndesc], sizeof(struct airoha_qdma_desc));
	memcpy(&rxdesc, &q->desc[q->head], sizeof(struct airoha_qdma_desc));

	pRxD = (TR471_RX_DSCP_T *)&rxdesc;

	*rx_byte_cnt_l=pRxD->rx_byte_cnt_l;
    *rx_byte_cnt_h=pRxD->rx_byte_cnt_h;
	*err_cnt=pRxD->seq_err_cnt;
	*drop_cnt=pRxD->seq_drop_cnt;
	
	return;
}
int airoha_eth_fast_tx(struct sk_buff *skb, int channel){
	struct airoha_gdm_dev *dev = glb_eth->ports[0]->devs[0];
	struct net_device *netdev = dev->dev;
	struct airoha_qdma *qdma = dev->qdma;
	u32 nr_frags, msg0, msg1, len;
	struct netdev_queue *txq;
	struct airoha_queue *q;
	struct airoha_queue_entry *e;
	LIST_HEAD(tx_list);
	void *data;
	int i, qid;
	u16 index,tag;
	skb->dev = netdev;

	skb_set_queue_mapping(skb, 7);
	
	qid = skb_get_queue_mapping(skb) % ARRAY_SIZE(qdma->q_tx);
	if(skb->inner_protocol == PPE_MAGIC_LOCAL_OUT)
		tag = PPE_MAGIC_LOCAL_OUT;
	else if(skb->inner_protocol == PPE_MAGIC_DYNAMIC_IFC)
		tag = PPE_MAGIC_DYNAMIC_IFC;
	else
		tag = DP_SPEED_UP;//use in sptag for pingpong stream

	msg0 = FIELD_PREP(QDMA_ETH_TXMSG_TCO_MASK, 1) |
		   FIELD_PREP(QDMA_ETH_TXMSG_CHAN_MASK,
			  channel) |
		   FIELD_PREP(QDMA_ETH_TXMSG_QUEUE_MASK,
			  qid % AIROHA_NUM_QOS_QUEUES) |
			  FIELD_PREP(QDMA_ETH_TXMSG_SP_TAG_MASK, tag);
	
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		msg0 |= FIELD_PREP(QDMA_ETH_TXMSG_TCO_MASK, 1) |
			FIELD_PREP(QDMA_ETH_TXMSG_UCO_MASK, 1) |
			FIELD_PREP(QDMA_ETH_TXMSG_ICO_MASK, 1);

	/* TSO: fill MSS info in tcp checksum field */
	if (skb_is_gso(skb)) {
		if (skb_cow_head(skb, 0))
			goto error;

		if (skb_shinfo(skb)->gso_type & (SKB_GSO_TCPV4 |
						 SKB_GSO_TCPV6)) {
			__be16 csum = cpu_to_be16(skb_shinfo(skb)->gso_size);

			tcp_hdr(skb)->check = (__force __sum16)csum;
			msg0 |= FIELD_PREP(QDMA_ETH_TXMSG_TSO_MASK, 1) |
					FIELD_PREP(QDMA_ETH_TXMSG_UCO_MASK, 1) |
					FIELD_PREP(QDMA_ETH_TXMSG_ICO_MASK, 1);
		}
	} 
	if(skb->mark ==FOE_MAGIC_TR471_HW_TEST_UPSTREAM){
	msg0 &= ~( QDMA_ETH_TXMSG_TSO_MASK |
			   QDMA_ETH_TXMSG_UCO_MASK |
			   QDMA_ETH_TXMSG_TCO_MASK);	
	msg0 |=	FIELD_PREP(QDMA_ETH_TXMSG_ICO_MASK, 1);
		}
	
	msg1 =0x7f4007ff;
	q = &qdma->q_tx[qid];
	if (WARN_ON_ONCE(!q->ndesc))
		goto error;

	spin_lock_irq(&q->lock);

	txq = netdev_get_tx_queue(netdev, qid);
	nr_frags = 1 + skb_shinfo(skb)->nr_frags;

	if (q->queued + nr_frags >= q->ndesc) {
		/* not enough space in the queue */
		spin_unlock_irq(&q->lock);
		goto error;
	}

	len = skb_headlen(skb);
	data = skb->data;
	
	e = list_first_entry(&q->tx_list, struct airoha_queue_entry,
			     list);
	index = e - q->entry;

	for (i = 0; i < nr_frags; i++) {
		struct airoha_qdma_desc *desc = &q->desc[index];
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		dma_addr_t addr;
		u32 val;
		addr = dma_map_single(netdev->dev.parent, data, len,
					  DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(netdev->dev.parent, addr)))
			goto error_unmap;

		list_move_tail(&e->list, &tx_list);
		e->skb = i ? NULL : skb;
		e->dma_addr = addr;
		e->dma_len = len;

		e = list_first_entry(&q->tx_list, struct airoha_queue_entry,
				     list);
		index = e - q->entry;

		val = FIELD_PREP(QDMA_DESC_LEN_MASK, len);
		if (i < nr_frags - 1){
			val |= FIELD_PREP(QDMA_DESC_MORE_MASK, 1);
		}
		WRITE_ONCE(desc->ctrl, cpu_to_le32(val));
		WRITE_ONCE(desc->addr, cpu_to_le32(addr));

		val = FIELD_PREP(QDMA_DESC_NEXT_ID_MASK, index);
		WRITE_ONCE(desc->data, cpu_to_le32(val));
		WRITE_ONCE(desc->msg0, cpu_to_le32(msg0));
		WRITE_ONCE(desc->msg1, cpu_to_le32(msg1));

		data = skb_frag_address(frag);
		len = skb_frag_size(frag);
	}
	
	q->queued += i;

	netdev_tx_sent_queue(txq, skb->len);
	airoha_qdma_rmw(qdma, REG_TX_CPU_IDX(qid),
			TX_RING_CPU_IDX_MASK,
			FIELD_PREP(TX_RING_CPU_IDX_MASK, index));

	spin_unlock_irq(&q->lock);

	return NETDEV_TX_OK;

error_unmap:
	while (!list_empty(&tx_list)) {
		e = list_first_entry(&tx_list, struct airoha_queue_entry,
				     list);
		dma_unmap_single(netdev->dev.parent, e->dma_addr, e->dma_len,
				 DMA_TO_DEVICE);
		e->dma_addr = 0;
		list_move_tail(&e->list, &q->tx_list);
	}

	spin_unlock_irq(&q->lock);
error:
	dev_kfree_skb_any(skb);
	netdev->stats.tx_dropped++;

	return NETDEV_TX_OK;
}

int SendToPpe(struct sk_buff * skb){
	
	unsigned int ip_ver = 0;
	unsigned char tmp_dst_mac[] = {0x0e,0x69,0x10,0x13,0x4d,0x2d};
	unsigned char tmp_src_mac[] = {0x00,0x00,0x00,0xff,0xee,0xdd};
	unsigned int paddingLength = 0;
	unsigned int skbLenTmp = 0;
	struct sk_buff * skb2 = NULL;
	struct iphdr *iph = NULL;
	iph = (struct iphdr *)skb->data;
 	ip_ver = iph->version;

	/* 1. add mac */
	skb = skb_unshare(skb, GFP_ATOMIC);
	if (!skb) {
		return 0;
	}

	if(skb_headroom(skb) <ETH_HLEN)
	{
		struct sk_buff *skb_tmp = skb_realloc_headroom(skb,14);
		dev_kfree_skb(skb);
		if(skb_tmp == NULL){
			return 0;
		}
		skb = skb_tmp;
	}
	
	skb_push(skb, 14);

	/* 2. fill in layer2 information */
	memcpy(skb->data, tmp_dst_mac, 6);
	memcpy(skb->data + 6, tmp_src_mac, 6);    


	if (4 == ip_ver){
		*(u16 *)(skb->data+12) = htons(ETH_P_IP);
	}else if (6 == ip_ver){
		*(u16 *)(skb->data+12) = htons(ETH_P_IPV6);
	}

	if (skb->len < 64)
	{
		paddingLength = 64 - skb->len;
		skbLenTmp = skb->len;
	
		if(skb_tailroom(skb) < paddingLength){
			skb2 = skb_copy_expand(skb, skb_headroom(skb), paddingLength, GFP_ATOMIC);
			if (skb2) {
				kfree_skb(skb);
				skb = skb2;
				skb_put(skb, paddingLength);
			}
		}
		else {
			skb_put(skb, paddingLength);
		}
		memset(skb->data + skbLenTmp, 0, paddingLength);
	}
	/* 3.redirect to PPE, send packet to PPE directly */
	airoha_eth_fast_tx(skb, 7);

	return 1;
}

static void airoha_gdma_start_TxRx_channel(struct airoha_gdm_dev *dev)
{
	if(glb_eth->fe_regs){
		airoha_fe_wr(glb_eth, REG_GDM_TXCHN_EN(dev->port->id), 0xffffffff);
		airoha_fe_wr(glb_eth, REG_GDM_RXCHN_EN(dev->port->id), 0xffff);
	}	
}

static void airoha_gdma_stop_TxRx_channel(struct airoha_gdm_dev *dev)
{
	if(glb_eth->fe_regs){
		airoha_fe_wr(glb_eth, REG_GDM_TXCHN_EN(dev->port->id), 0x0);
		airoha_fe_wr(glb_eth, REG_GDM_RXCHN_EN(dev->port->id), 0x0);
	}
}

static void airoha_xsi_mac_start(struct airoha_gdm_dev *dev)
{
	/*Note: Start xsi mac mbi mpi by sequence*/
	if(dev->xfi_mac){
		regmap_clear_bits(dev->xfi_mac, AIROHA_PCS_XFI_MAC_XFI_GIB_CFG,
					AIROHA_PCS_XFI_RXMBI_STOP);
		msleep(1);			
		regmap_clear_bits(dev->xfi_mac, AIROHA_PCS_XFI_MAC_XFI_GIB_CFG,
					AIROHA_PCS_XFI_RXMPI_STOP);	
		regmap_clear_bits(dev->xfi_mac, AIROHA_PCS_XFI_MAC_XFI_GIB_CFG,
					AIROHA_PCS_XFI_TXMPI_STOP);			
		regmap_clear_bits(dev->xfi_mac, AIROHA_PCS_XFI_MAC_XFI_GIB_CFG,
					AIROHA_PCS_XFI_TXMBI_STOP);

	}	
}

static void airoha_xsi_mac_stop(struct airoha_gdm_dev *dev)
{
	
	/*Note: Stop xsi mac mbi mpi by sequence*/
	if(dev->xfi_mac){
		regmap_set_bits(dev->xfi_mac, AIROHA_PCS_XFI_MAC_XFI_GIB_CFG,
					AIROHA_PCS_XFI_RXMPI_STOP);
		regmap_set_bits(dev->xfi_mac, AIROHA_PCS_XFI_MAC_XFI_GIB_CFG,
					AIROHA_PCS_XFI_RXMBI_STOP);
		regmap_set_bits(dev->xfi_mac, AIROHA_PCS_XFI_MAC_XFI_GIB_CFG,
					AIROHA_PCS_XFI_TXMBI_STOP);
		msleep(1);
		regmap_set_bits(dev->xfi_mac, AIROHA_PCS_XFI_MAC_XFI_GIB_CFG,
					AIROHA_PCS_XFI_TXMPI_STOP);
	}
}

static void airoha_xsi_mac_reset(struct airoha_gdm_dev *dev)
{
	if(dev->xfi_mac){
		regmap_clear_bits(dev->xfi_mac, AIROHA_PCS_XFI_MAC_XFI_LOGIC_RST,
				  AIROHA_PCS_XFI_MAC_LOGIC_RST);
		regmap_set_bits(dev->xfi_mac, AIROHA_PCS_XFI_MAC_XFI_LOGIC_RST,
				AIROHA_PCS_XFI_MAC_LOGIC_RST);
	}		
}
static void airoha_qdma_start_channel(struct airoha_gdm_dev *dev,uint channel)
{
	
	int  i = 0;
	if(dev->qdma){
		for (i = 0; i < AIROHA_NUM_QOS_QUEUES; i++)
			airoha_qdma_clear(dev->qdma, REG_QUEUE_CLOSE_CFG(channel),
					  TXQ_DISABLE_CHAN_QUEUE_MASK(channel, i));	
	}
}

static void airoha_qdma_stop_channel(struct airoha_gdm_dev *dev,uint channel)
{
	int  i = 0;
	if(dev->qdma){
		for (i = 0; i < AIROHA_NUM_QOS_QUEUES; i++)
			airoha_qdma_set(dev->qdma, REG_QUEUE_CLOSE_CFG(channel),
					  TXQ_DISABLE_CHAN_QUEUE_MASK(channel, i));
	}
}

static u32 airoha_eth_get_link_rate(struct net_device *eth_dev)
{
	struct ethtool_link_ksettings ecmd;
	u32 speed;
	memset(&ecmd,0,sizeof(ecmd));
	eth_dev->ethtool_ops->get_link_ksettings(eth_dev,&ecmd);
	speed = ecmd.base.speed; 
	return speed;
}

static void airoha_eth_link_rate_update(int idx, u32 speed)
{
	QDMA_TxRateLimitSet_T txRateLimitSet = {0};

	if(glb_eth){
		/*Set tx qdma channel ratelimit based on link rate of lan port*/
		txRateLimitSet.chnlRateLimitEn = 1;
		txRateLimitSet.chnlIdx = idx+1;
		txRateLimitSet.rateLimitValue = (speed*1000);
                /* A 1G LAN port loses packets when contending with a 10G port
                * unless its QDMA channel shaper is given a small margin above
                * nominal line rate. Non-upstream code used 1001 Mbps; 70 kbps
                * is the measured requirement. Not specific to flow counting.
                */
                if (speed == SPEED_1000)
			txRateLimitSet.rateLimitValue += 70;
		qdma_set_qdmalan_tx_ratelimit(&txRateLimitSet);
	}else{
		printk("%s:glb_eth = NULL \n",__func__);
	}
	
}	
static void airoha_eth_mbi_hang_unlock_by_arbit_reset(void)
{
    int ret, val = 0;
	if(glb_eth->fe_regs){
		/*Tx terminate*/
		ret = read_poll_timeout(airoha_fe_rr, val,
					!(val & REG_GDM4_MBI_TX_BUSY),
					USEC_PER_MSEC, 100 * USEC_PER_MSEC,
					false, glb_eth, REG_GDM4_CHN_RLS);	
						
		if(ret){
			airoha_fe_rmw(glb_eth, FE_RESET_GLO, GDM4_MBI_ARB_TX_RST, 
						FIELD_PREP(GDM4_MBI_ARB_TX_RST, 1));
						
			ret = read_poll_timeout(airoha_fe_rr, val,
					!(val & REG_GDM4_MBI_TX_BUSY),
					USEC_PER_MSEC, 100 * USEC_PER_MSEC,
					false, glb_eth, REG_GDM4_CHN_RLS);		
				
			if(ret)
				printk(" Error: %s MBI TX Hang issue Terminate Fail! \n",__func__);
			
			airoha_fe_rmw(glb_eth, FE_RESET_GLO, GDM4_MBI_ARB_TX_RST, 
						FIELD_PREP(GDM4_MBI_ARB_TX_RST, 1));
			
			ret = read_poll_timeout(airoha_fe_rr, val,
					!(val & REG_GDM4_MBI_TX_BUSY),
					USEC_PER_MSEC, 100 * USEC_PER_MSEC,
					false, glb_eth, REG_GDM4_CHN_RLS);
			if(ret)
				printk(" Error2: %s MBI TX Hang issue Terminate Fail! \n",__func__);		
		
		}
		
		
		/*Rx terminate*/
		ret = read_poll_timeout(airoha_fe_rr, val,
					!(val & REG_GDM4_MBI_RX_BUSY),
					USEC_PER_MSEC, 100 * USEC_PER_MSEC,
					false, glb_eth, REG_GDM4_CHN_RLS);	
		
		if(ret){
			airoha_fe_rmw(glb_eth, FE_RESET_GLO, GDM4_MBI_ARB_RX_RST, 
						FIELD_PREP(GDM4_MBI_ARB_RX_RST, 1));
						
			ret = read_poll_timeout(airoha_fe_rr, val,
					!(val & REG_GDM4_MBI_RX_BUSY),
					USEC_PER_MSEC, 100 * USEC_PER_MSEC,
					false, glb_eth, REG_GDM4_CHN_RLS);	
				
			if(ret)
				printk(" Error: %s MBI RX Hang issue Terminate Fail! \n",__func__);
			
			airoha_fe_rmw(glb_eth, FE_RESET_GLO, GDM4_MBI_ARB_RX_RST, 
						FIELD_PREP(GDM4_MBI_ARB_RX_RST, 1));
						
			ret = read_poll_timeout(airoha_fe_rr, val,
					!(val & REG_GDM4_MBI_RX_BUSY),
					USEC_PER_MSEC, 100 * USEC_PER_MSEC,
					false, glb_eth, REG_GDM4_CHN_RLS);	
			if(ret)
				printk(" Error2: %s MBI RX Hang issue Terminate Fail! \n",__func__);		
					
		}
	}	
	
}
static void airoha_eth_monitor_link_up_protection(struct airoha_gdm_dev *dev, struct net_device *eth_dev, int channel)
{
		/*Start QDMA channel & MAC when Link Up*/
		airoha_gdma_start_TxRx_channel(dev);

		if (arht_switch_set_mfc_hook && switch_set_mfc_enable)
			arht_switch_set_mfc_hook();
		if (dev->port->id != 1){
			airoha_xsi_mac_start(dev);
		}
		
		airoha_qdma_start_channel(dev,channel);
		
		printk("\n [ARIOHA_ETH_MONITOR] Itf - %s Link Up Check Success! \n",eth_dev->name);
}

static void airoha_eth_monitor_link_down_protection(struct airoha_gdm_dev *dev, struct net_device *eth_dev, int channel)
{
	int ret = 0;
	if (glb_eth){
		airoha_flow_table_entries_lan(&glb_eth->flow_table,eth_dev);
		
		if (dev->port->id != 1){	
			airoha_qdma_stop_channel(dev,channel);
			/*Rleasing Process for Serdes Port*/
			airoha_xsi_mac_stop(dev);
			msleep(1);
			airoha_gdma_stop_TxRx_channel(dev);
			
			/* Clean downstream rules by fport and channel */
			if (ra_sw_nat_hook_clean_entry_by_fport_and_channel)
				ra_sw_nat_hook_clean_entry_by_fport_and_channel(airoha_get_fe_port(dev), channel);

			if(glb_eth->extra_ops.set_channel_retire){
				ret = glb_eth->extra_ops.set_channel_retire(glb_eth, dev);
			}
			else{
				ret = airoha_fe_gdm_rls(dev->port);
				airoha_eth_mbi_hang_unlock_by_arbit_reset();
				airoha_xsi_mac_reset(dev);
			}
			if(ret < 0 )
				printk("\n [ARIOHA_ETH_MONITOR] Itf - %s Link Down GDM%d Rls Fail! \n",eth_dev->name,dev->port->id);
			else
				printk("\n [ARIOHA_ETH_MONITOR] Itf - %s Link Down GDM%d Rls Success! \n",eth_dev->name,dev->port->id);
			
			//msleep(1);
			//airoha_gdma_start_TxRx_channel(port);
			
		}
		//for gsw
		else
		{
			/* Clean downstream rules by fport and channel */
			if (ra_sw_nat_hook_clean_entry_by_fport_and_channel)
				ra_sw_nat_hook_clean_entry_by_fport_and_channel(airoha_get_fe_port(dev), channel);
			printk("\n [ARIOHA_ETH_MONITOR] Itf - %s Link Down GDM%d! \n",eth_dev->name,dev->port->id);
		}
	}	
}

static void airoha_eth_monitor_gsw_process(struct airoha_gdm_dev *dev)
{
	struct net_device *eth_dev = NULL;
	int i = 0;
	int ret = 0;

	EphyMonitor();
	for(i=0; i<AIROHA_MAX_GSW_LAN_PORTS; i++)
	{
		char ifname[8] = {0};
		ret = snprintf(ifname,sizeof(ifname),"lan%d",i+1);
		if (ret < 0)
		{
			printk("ifname len is negative.\n");
		}
		eth_dev = dev_get_by_name(&init_net,ifname);
		
		if(eth_dev && netif_running(eth_dev) && netif_device_present(eth_dev))
		{					
			rtnl_lock();
			
			/*1. Detect Link Rate*/
			if(eth_dev->ethtool_ops &&eth_dev->ethtool_ops->get_link_ksettings)
			{
				u32 speed;				
				speed = airoha_eth_get_link_rate(eth_dev);
					if(speed != SPEED_UNKNOWN && speed != gsw_speed[i]){
					airoha_eth_link_rate_update(i,speed);
					printk("%s: %s LinkRate changed for %d to %u!\n",__func__,eth_dev->name,gsw_speed[i],speed);
					gsw_speed[i] = speed;
				}
			}
			
			/*2. Detect Link Status*/
			     /*Link down to up*/
			/* CID:923125 */
			if (eth_dev->ethtool_ops)
			{
			if(!eth_lastlinks[i]&& eth_dev->ethtool_ops->get_link(eth_dev)){
				
				airoha_eth_monitor_link_up_protection(dev, eth_dev, i+1);
				eth_lastlinks[i] = 1;
				
			     /* Link up to down*/	
			}else if (eth_lastlinks[i]&& !eth_dev->ethtool_ops->get_link(eth_dev)){
				
				airoha_eth_monitor_link_down_protection(dev, eth_dev, i+1);	
				eth_lastlinks[i] = 0;
				}
			}
			rtnl_unlock();	
			dev_put(eth_dev);
		}	
	}	
}

void get_serdes_info_from_dev(struct airoha_gdm_dev *dev, int *serdes_idx, int *channel)
{
	struct airoha_eth *eth = dev->eth;
	int i;

	if (!eth || !eth->soc)
		return;

	for (i = 0; i < SERDES_MAX_IDX; i++) {
		if (eth->soc->nbq[i] == dev->nbq) {
			int expected_port_id = -1;
			if (eth->soc->fport[i] == FE_PSE_PORT_GDM3) 
				expected_port_id = AIROHA_GDM3_IDX;
			else if (eth->soc->fport[i] == FE_PSE_PORT_GDM4) 
				expected_port_id = AIROHA_GDM4_IDX;

			if (dev->port->id == expected_port_id) {
				*channel = eth->soc->chnl[i];
				*serdes_idx = i;
				break;
			}
		}
	}
}

static void airoha_eth_monitor_serdes_link_status_handler(struct airoha_gdm_dev *dev)
{
	int serdes_idx =-1;
	int channel = 0;
	int serdes_port = -1;
	struct net_device *eth_dev;
	
	if (!dev) {
		return;
	}
	eth_dev = dev->dev;

	get_serdes_info_from_dev(dev, &serdes_idx, &channel);
	if (serdes_idx == SERDES_ETH_IDX)
		serdes_port = ARHT_ETH_PORT_2;
	else if (serdes_idx == SERDES_PCIE0_IDX || serdes_idx == SERDES_PCIE1_IDX)
		serdes_port = ARHT_ETH_PORT_3;
	else if (serdes_idx == SERDES_USB_IDX)
		serdes_port = ARHT_ETH_PORT_4;
	if (serdes_port < 0 || serdes_port >= ARHT_ETH_PORT_MAX) {
		return;
	}
		/*1. Detect Link Rate*/
	if (eth_dev->ethtool_ops &&eth_dev->ethtool_ops->get_link_ksettings)
	{
		u32 speed;				
		speed = airoha_eth_get_link_rate(eth_dev);
		if(speed != SPEED_UNKNOWN && speed != xsi_speed[serdes_idx]){ 
			airoha_eth_link_rate_update(dev->qdma->eth->soc->chnl[serdes_idx]-1,speed);
			printk("%s: %s LinkRate changed for %d to %u!\n",__func__,eth_dev->name,xsi_speed[serdes_idx],speed);
			xsi_speed[serdes_idx] = speed;
		}
	}

	if (!eth_lastlinks[serdes_port] && (netif_running(eth_dev)&& netif_carrier_ok(eth_dev))){
		if (glb_eth){
			if (dev->qdma){
				airoha_eth_monitor_link_up_protection(dev, eth_dev, channel);
			}
		}
		eth_lastlinks[serdes_port] = 1;

	/* Link up to down*/
	}else if (eth_lastlinks[serdes_port] && (!netif_running(eth_dev) || !netif_carrier_ok(eth_dev))){	
		if (glb_eth){
			if (dev->qdma){
				/*Stop QDMA channel & MAC when Link Down*/
				airoha_eth_monitor_link_down_protection(dev, eth_dev, channel);
			}
		}
		eth_lastlinks[serdes_port] = 0;
	}
}

static void airoha_eth_monitor_serdes_process(struct airoha_gdm_dev *dev)
{
	/* CID:923145 */
	if (NULL == dev)
	{
		printk("airoha_gdm_dev dev is null.\n");
		return;
	}
	struct net_device *eth_dev = dev->dev;
	/*Detect Link Status*/ 
	/*Link down to up*/
	if (!eth_dev){
		printk("Error ! %s: Invaild eth dev port->id:%d\n",__func__,dev->port->id);
		return;
	}

	rtnl_lock();
	airoha_eth_monitor_serdes_link_status_handler(dev);
	rtnl_unlock();
}

void airoha_eth_monitor(struct work_struct *work)
{
	int p, i;
	static u32 gdm4_overflow_drop_cnt_last = 0;
	u32 gdm4_overflow_drop_cnt_cur;
	
	if (glb_eth && glb_eth->fe_regs) {
		gdm4_overflow_drop_cnt_cur =
			airoha_fe_rr(glb_eth, REG_FE_GDM_RX_OVERFLOW_DROP_CNT(4)); 
		if (gdm4_overflow_drop_cnt_cur != gdm4_overflow_drop_cnt_last) {
			airoha_fe_do_core_reset(glb_eth);
			gdm4_overflow_drop_cnt_last =
				airoha_fe_rr(glb_eth, REG_FE_GDM_RX_OVERFLOW_DROP_CNT(4));
		}
	}
	//fe_oq_stat_monitor();
	for(p = 0; p < ARRAY_SIZE(glb_eth->ports); p++)
	{
		if(!glb_eth->extra_ops.support_eth_monitor(p))
			continue;

		struct airoha_gdm_dev *dev;
		struct net_device *eth_dev = NULL;

		for(i=0; i<ARRAY_SIZE(glb_eth->ports[p]->devs); i++){
			dev = glb_eth->ports[p]->devs[i];

			if(!dev)
				continue;
			
			eth_dev = dev->dev;

			if(netdev_uses_dsa(eth_dev)){
				/*Detect eth0 - lan1~4*/
				airoha_eth_monitor_gsw_process(dev);
			}else{
				/*Detect eth2*/
				airoha_eth_monitor_serdes_process(dev);
			}
		}
	}
	
	if(glb_eth->work_started)
		schedule_delayed_work(&airoha_eth_monitor_workqueue,msecs_to_jiffies(125));
}

void airoha_eth_monitor_workqueue_init(void)
{
	struct airoha_eth *eth = glb_eth;

	if (!eth)
		return;

	if(eth->extra_ops.support_eth_monitor){
		if(!eth->work_started)
		{
			eth->work_started = true;
			printk("[AIROHA_ETH] ETH State Monitor Active \n");
			INIT_DELAYED_WORK(&airoha_eth_monitor_workqueue, airoha_eth_monitor);
			schedule_delayed_work(&airoha_eth_monitor_workqueue,msecs_to_jiffies(50000));
		}
	}
}

void airoha_eth_monitor_workqueue_exit(void)
{
	struct airoha_eth *eth = glb_eth;

	if (!eth)
		return;

	if(eth->extra_ops.support_eth_monitor){
		if(eth->work_started)
		{
			eth->work_started = false;
			cancel_delayed_work_sync(&airoha_eth_monitor_workqueue);	
		}
	}
}


static int airoha_check_pon_rx_hook(void *pMsg,struct sk_buff *skb, uint pktLen)
{
	/*
	PON RX process hook 
	Ruturn: if pwan_cb_rx_hook return success iterate to next packet otherwise it go to eth rx
	*/
	if(g_pon_serdes_eth)
		return RX_PON_FAIL;
	
	if(pwan_cb_rx_hook){
		if(pwan_cb_rx_hook(pMsg,QDMA_RX_DSCP_MSG_LENS,skb,pktLen) == 1){
			return RX_PON_SUCCESS_GRO;
		}
	}else{
		return RX_PON_FAIL;
	}

	return RX_PON_SUCCESS;
}

static int airoha_force_to_cpu_handler(struct sk_buff *skb,
					unsigned short stag, int crsn)
{
	if(crsn == HIT_BIND_FORCE_TO_CPU){
		if(stag == PPE_UDF_LOCAL_IN && likely(arht_force_to_cpu_hook))
			return arht_force_to_cpu_hook(skb, stag);
		else if(stag == PPE_UDF_MULTICAST && likely(arht_multicast_bind_to_cpu))
			return arht_multicast_bind_to_cpu(skb);
	}
	else if(crsn == HIT_BIND_MUL_CPU)
	{
		if(arht_multicast_bind_to_cpu)
			return arht_multicast_bind_to_cpu(skb);
	}

	kfree_skb(skb);
	return 0;
}

int airoha_receive_hook(struct airoha_queue *q, struct airoha_qdma_desc *desc, 
	int port_id, int len)
{
	int sport, crsn, VirIfIdx = 0;
	unsigned short rx_udf = 0;
	int hopflags;
	bool ipv6 = 0;
	int ret = 0;
	struct pwan_msg pMsg;
	struct sk_buff *skb = q->skb;
	u32 sptag;
	
	pMsg.msg0 = le32_to_cpu(desc->msg0);
	pMsg.msg1 = le32_to_cpu(desc->msg1);

	sptag = FIELD_GET(QDMA_ETH_RXMSG_SPTAG,
					      le32_to_cpu(desc->msg0));
	
	airoha_get_entry_bind(pMsg.msg1, q, glb_eth, sptag);
	
	crsn = FIELD_GET(QDMA_ETH_RXMSG_CRSN_MASK, pMsg.msg1);
	sport = FIELD_GET(AIROHA_RXD4_SPORT, pMsg.msg1);
	VirIfIdx = FIELD_GET(QDMA_ETH_RXMSG_SPTAG_PINGPONG, pMsg.msg0);
	u32 hash = FIELD_GET(AIROHA_RXD4_FOE_ENTRY, pMsg.msg1);
	ipv6 = FIELD_GET(QDMA_ETH_RXMSG_IP6_MASK, pMsg.msg1);
	AIROHA_LOG(AIROHA_DEBUG_LEVEL_INFO, "sport: %d, VirIfIdx: %d",sport,VirIfIdx);
	
	if (crsn == HIT_BIND_FORCE_TO_CPU && VirIfIdx == PPE_UDF_LOCAL_IN_NS) {
        if (arht_force_to_cpu_prepare_gro_hook){
            ret = arht_force_to_cpu_prepare_gro_hook(skb, ipv6);
        } else {
            ret = 1;
        }
        return ret;
     }

	if(crsn == HIT_BIND_FORCE_TO_CPU || 
		crsn == HIT_BIND_MUL_CPU){
		airoha_force_to_cpu_handler(skb, VirIfIdx, crsn);
		return 0;
	}
	if(tr471_rx_hook){
		ret=tr471_rx_hook(skb,sport,hash);
		if(ret==TR471_UPSTREAM_SUCCESS){
			return 0;
		}else if(ret==TR471_DOWNSTREAM_SUCCESS && 
		(FIELD_GET(AIROHA_RXD4_PPE_CPU_REASON, pMsg.msg1)==PPE_CPU_REASON_HIT_UNBIND_RATE_REACHED)){
			tr471_downstream_offload(skb,glb_eth);
		}
	}
	if(sport == FE_PSE_PORT_CDM1){
		if(wan_speed_test_pinpong_handle_hook && (VirIfIdx == DP_SPEED_UP)){
			skb->mark = DP_SPEED_UP;
			skb_set_hash(skb, hash,PKT_HASH_TYPE_L4);
			if(set_entry_reason_hook){
				set_entry_reason_hook(skb, crsn);
			}
			wan_speed_test_pinpong_handle_hook(skb);
			return 0;
		}
		if(local_out_pingpong_hook && (VirIfIdx == PPE_MAGIC_LOCAL_OUT)){
			local_out_pingpong_hook(skb);
			return 0;
		}
		if(dynamic_ifc_pingpong_hook && (VirIfIdx == PPE_MAGIC_DYNAMIC_IFC)){
			if (skb_mac_header_was_set(skb) && skb_mac_header(skb) <= skb->data)
				skb_push(skb, skb->data - skb_mac_header(skb));
			else {
				dev_kfree_skb(skb);
				return 0;
			}
			dynamic_ifc_pingpong_hook(skb);
			return 0;
		}
	}

	pMsg.msg2 = le32_to_cpu(desc->msg2);
	pMsg.msg3 = le32_to_cpu(desc->msg3);
	rx_udf = FIELD_GET(QDMA_ETH_RXMSG_AGG_COUNT_MASK, pMsg.msg2);
	
	if(airoha_tunnel_pingpong_hook && airoha_tunnel_pingpong_hook(skb, VirIfIdx,rx_udf,ipv6)){
		return 0;		
	}
	if(sport == FE_PSE_PORT_GDM1 || sport == FE_PSE_PORT_GDM2){
		hopflags = FIELD_GET(QDMA_ETH_RXMSG_HOPFLAGS, pMsg.msg0);
		//when dir is encryption,the sport is 1,and when the dir is direction,the sport is 2
		if(arht_soe_ipsec_rcv_packek_from_soe && (hopflags >= 3 && hopflags <= 7)){
			if(arht_soe_wireguard_rcv_packet_from_soe)
			{
				if(arht_soe_wireguard_rcv_packet_from_soe(skb,len,rx_udf,hopflags) == -2)
				{
					arht_soe_ipsec_rcv_packek_from_soe(skb,len,rx_udf,hopflags);
					return 0;
				}
				else
					return 0;
			}
			else
				arht_soe_ipsec_rcv_packek_from_soe(skb,len,rx_udf,hopflags);
			return 0;
		}
	}

			
	if(port_id==2){
		ret = airoha_check_pon_rx_hook((void *)&pMsg,skb,len);
		if(ret != RX_PON_FAIL){
			return ret;
		}
	}
	
	if(wan_speed_test_hook 
		&& wan_speed_test_hook(skb)==SPEED_TEST_SUCCESS)
	{
		return 0;			
	}

	if(airoha_pon_sfu_point_to_point_transmit_hook)
	{
		if(airoha_pon_sfu_point_to_point_transmit_hook(skb, sptag))
			return 0;
	}
	
	return 1;
}

int airoha_get_free_lro_ring(u32 foe_entry_idx)
{
	int i = 0;

	/* check if the entry has been binded. */
	for(i = 0; i < 2 * LRO_RING_NUM; i++)
	{
		if(lro_ring_reserve[i][0] == LRO_RING_RESERVED)
		{
			if(ppe_entry_is_valid(lro_ring_reserve[i][1], (LRO_RING_START + i)))     /* current ppe entry has aged out. */
			{
				lro_ring_reserve[i][1] = foe_entry_idx;
				return (LRO_RING_START + i);
			}
		}

		if((lro_ring_reserve[i][0] == LRO_RING_RESERVED) && (lro_ring_reserve[i][1] == foe_entry_idx))
		{
			return (LRO_RING_START + i);
		}
	}

	/* scan for free Rx ring. */
	for(i = 0; i < 2 * LRO_RING_NUM; i++)
	{
		if(lro_ring_reserve[i][0] == LRO_RING_FREE)
		{
			lro_ring_reserve[i][1] = foe_entry_idx;
			lro_ring_reserve[i][0] = LRO_RING_RESERVED;
			return (LRO_RING_START + i);
		}
	}

	return 1;
}


struct dst_entry *arht_gen_dst_clone(struct dst_entry *dst)
{
	return dst_clone(dst);
}
EXPORT_SYMBOL(arht_gen_dst_clone);

void fast_path_speed_threshold_init(void)
{
	if(glb_eth && glb_eth->soc->version == 0x7581)
		fast_path_speed_threshold = LINK_SPEED_1000M;
	else //for an7583
		fast_path_speed_threshold = LINK_SPEED_2500M;

	return;
}

void arht_conntrack_get_cnt(u32 hash, struct airoha_foe_stats64 *stats){
	u64 bytes = 0, packets = 0;
	if (arht_conntrack_get_cnt_hook)
		if(!arht_conntrack_get_cnt_hook(hash, &bytes, &packets)){
			stats->packets = packets;
			stats->bytes = bytes;
			}

}
void arht_conntrack_free_cnt(u32 hash){
	if(arht_conntrack_free_cnt_hook)
		arht_conntrack_free_cnt_hook(hash);

}
