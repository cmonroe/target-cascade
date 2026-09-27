#ifndef __ARHT_PPE_H_
#define __ARHT_PPE_H_

#include <linux/if_vlan.h>

/* L2B ether type configuration */
#define L2B_ETYPE_MAX_INDEX	16
#define L2B_ETYPE_INVALID_INDEX	(-1)

#define REG_PPE_L2B_ETYPE_EN(_n)	(((_n) ? PPE2_BASE : PPE1_BASE) + 0x28c)
#define REG_PPE_L2B_ETYPE_N(_m, _n)	\
	(((_m) ? PPE2_BASE : PPE1_BASE) + 0x2d0 + (((_n) / 2) << 2))

#define HWNAT_DEFAULT_MTRGRP 0x7F
#define HWNAT_DEFAULT_ACNT0GRP 0x1F
#define HWNAT_DEFAULT_ACNT1GRP 0x1F
#define HWNAT_DEFAULT_GRP_ID 0x3F

enum {
	PPE_CPU_REASON_KEEPALIVE_WITH_UNI_OLD_PACKET = 0x13,
	PPE_CPU_REASON_KEEPALIVE_WITH_MUL_NEW_PACKET = 0x14,
	PPE_CPU_REASON_KEEPALIVE_WITH_DUP_OLD_PACKET = 0x15,
};

struct FoeEntryExt
{
	unsigned char vlan_count;
	u32 fe_resource_mark;
	int lan_ifindex;
	u32 conntrack_idx;
}; 

/*****************fe_resource_mark bitmap format******************************/
/*reserve			acnt1&meter2		acnt0&meter1	acnt2&meter0         */
/*00000000			0000000 			00000000		000000000            */
/*****************fe_resource_mark format*************************************/
#define ACCOUNT2_OFFSET    	(0)
#define ACCOUNT2_MASK       	(0x7F)
#define METER0_MASK       	(0x7F)
#define METER0_ENABLE_OFFSET	(7)
#define ACCOUNT2_ENABLE_OFFSET	(8)
	
#define ACCOUNT0_MASK_LEN  	(6)
#define ACCOUNT0_OFFSET    	(9)
#define ACCOUNT0_MASK      	(0x3F)
#define METER1_MASK       	(0x1F)
#define METER1_ENABLE_OFFSET	(15)
#define ACCOUNT0_ENABLE_OFFSET	(16)
	
#define ACCOUNT1_OFFSET    	(17)
#define ACCOUNT1_MASK      	(0x1F)
#define METER2_MASK       	(0xF)
#define METER2_ENABLE_OFFSET	(22)
#define ACCOUNT1_ENABLE_OFFSET	(23)


#define SMACT_SIZE	(0x800)
#define UPDMEM_NUM	(16)
#define UPDMEM_SMAC_CNT		(6)
#define UPDMEM_IPV4_LINE	(2)
#define UPDMEM_IPV6_LINE	(8)

/* PPE_UPDMEM_CTRL */
#define PPE_UPDMEM_ACK						(1<<31)
#define PPE_UPDMEM_ADDR_SHIFT				(8)
#define PPE_UPDMEM_OFST_SHIFT				(4)
#define PPE_UPDMEM_OFST_MASK				(0xF<<PPE_UPDMEM_OFST_SHIFT)
#define PPE_UPDMEM_SEL_SMAC			(0)
#define PPE_UPDMEM_SEL_IPv6			(1)
#define PPE_UPDMEM_SEL_IPv4			(2)
#define PPE_UPDMEM_SEL_SHIFT				(2)
#define PPE_UPDMEM_CTRL_READ		(0)
#define PPE_UPDMEM_CTRL_WRITE		(1)
#define PPE_UPDMEM_WR						(1<<1)
#define PPE_UPDMEM_REQ						(1<<0)

#define SMAC_PON_IDX 14

#define TO_MULTICAST_OFFLOAD 1
#define TO_CPU 0

#define MAX_VLAN_DEPTH      5

#define BITMAP_IDX_SIZE ((16384+31)/32) /*default use sram*/
#ifndef IFF_PON_DEV
#define IFF_PON_DEV (1UL << 31)
#endif
struct hwnat_shrink_field {
	//unsigned int smac[UPDMEM_SMAC_LINE];		// 0:smac[31~0]; 1:smac[48~32];
	unsigned char smac[UPDMEM_SMAC_CNT];		// 0:smac[31~0]; 1:smac[48~32];
	unsigned int eg_ipv4[UPDMEM_IPV4_LINE]; 	// 0:dipv4; 1:sipv4
	unsigned int eg_ipv6[UPDMEM_IPV6_LINE]; 	// 0:dipv6[31:0], ....., 7:sipv6[127:96]
	unsigned int foe_idx;
};

struct hwnat_shrink_table {
	//unsigned int smac[UPDMEM_SMAC_LINE];		// 0:smac[31~0]; 1:smac[48~32];
	unsigned char smac[UPDMEM_SMAC_CNT];		// 0:smac[47:40], .... ,5:smac[7:0];
	unsigned int eg_ipv4[UPDMEM_IPV4_LINE]; 	// 0:dipv4; 1:sipv4
	unsigned int eg_ipv6[UPDMEM_IPV6_LINE]; 	// 0:dipv6[31:0], ....., 7:sipv6[127:96]
	unsigned int valid[3];
	unsigned long timestamp[3];
	unsigned long bitmap[3][BITMAP_IDX_SIZE];
	unsigned int pinned[3];
};

inline static int airoha_ppe_is_pon_dev(struct net_device *dev)
{
	struct net_device *real_dev = dev;
	if (dev == NULL)
		return 0;
	if (is_vlan_dev(dev))
		real_dev = vlan_dev_real_dev(dev);
	return ((real_dev != NULL) && (real_dev->priv_flags & IFF_PON_DEV));
}

inline static int airoha_ppe_is_ppp_dev(struct net_device *dev)
{
	return ((dev != NULL) && (dev->name[0] == 'p') && \
		(dev->name[1] == 'p') && (dev->name[2] == 'p'));
}

inline static struct airoha_gdm_dev *airoha_ppe_get_gdm_dev(struct airoha_eth *eth, struct net_device *dev)
{
	if(airoha_ppe_is_pon_dev(dev)){
		return eth->ports[1]->devs[0];
	}

	return (struct airoha_gdm_dev *)netdev_priv(dev);
}

inline static void FoeSetEntryMac(uint8_t * Dst, u32 * Src_hi, u16 * Src_lo)
{
	*Src_hi = (Dst[0] << 24) | (Dst[1] << 16) | (Dst[2] << 8) | Dst[3];
    *Src_lo = (Dst[4] << 8) | Dst[5];
}

//export symbol function
int arht_multicast_handler_for_sfu(struct sk_buff* skb);
int find_and_update_shrink_table(int select, struct hwnat_shrink_field *shrinkFieldPtr);
int ppe_dump_shrink_table(void);
int arht_general_offload_bind(struct sk_buff * skb, unsigned short type);
int airoha_ppe_tx_handler(struct sk_buff *skb, struct port_info *pinfo, u8 fport);
void arht_ppe_general_init(struct airoha_ppe *ppe);
void arht_ppe_general_exit(void);
int arht_hwnat_delete_ppe_entry(unsigned int foe_index);

int airoha_set_entry_fe_resource_mark(u32 foe_entry_idx, u32 fe_resource_mark);
u32 airoha_get_entry_fe_resource_mark(u32 foe_entry_idx);

//unused function
void npu_get_entry_bind(struct sk_buff *skb, u32 hash, u32 reason);
void airoha_ppe_foe_flow_update_wifi_npu_offload(struct airoha_ppe *ppe, struct sk_buff *skb, struct port_info *pinfo);
int airoha_is_bridge_mode(struct sk_buff * skb);

//define on airoha_ppe.c

void ppe_set_vlan_info(struct airoha_foe_entry *hwe, struct sk_buff *skb);
int airoha_set_ppe_mac(struct airoha_foe_entry *foe_entry, struct net_device *dev, char* src_mac, char*dst_mac, u16 pppid);
void set_ppe_entry_smac_index (struct airoha_foe_entry *foe_entry, unsigned int type, unsigned char value);
void airoha_ppe_foe_flow_update_eth_offload(struct airoha_ppe *ppe, struct sk_buff *skb, struct port_info *pinfo, u8 fport);
void airoha_ppe_foe_flow_update_pon_offload(struct airoha_ppe *ppe, struct sk_buff *skb, struct port_info *pinfo, u8 fport);
void airoha_ppe_hook_init(void);
void airoha_ppe_hook_exit(void);
void UpdateShrinkTable(int index,const u8 *addr);
void PpeClearEntryInfo(struct airoha_foe_entry *foe_entry);
int ppe_entry_is_valid(u32 foe_entry_idx, int ring_idx);
struct airoha_flow_table_entry *airoha_flow_table_entry_get_by_hash(struct airoha_ppe *ppe, u32 hash);
int __airoha_ppe_foe_commit_entry(struct airoha_ppe *ppe, u32 hash);
void airoha_set_flow_destination(struct net_device *dev, struct airoha_flow_table_entry *e);
void airoha_ppe_clear_sram_table_flow(struct airoha_ppe *ppe, uint entry_idx);
void airoha_ppe_clear_sram_table_all(struct airoha_ppe *ppe);
void airoha_ppe_clean_sram_table(void);
void airoha_ppe_delete_entry(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, uint entry_idx);
int airoha_get_foe_from_skb(struct sk_buff * skb);
void airoha_pon_set_macaddr(const u8 *addr);
int arht_ppe_multicast_set_valid(struct sk_buff* skb);
int arht_ppe_multicast_handler(struct airoha_ppe *ppe, struct sk_buff* skb);
int airoha_get_ppe_entry_state(unsigned int foe_index);
int arht_ppe_multicast_check_valid(struct airoha_ppe *ppe, struct airoha_foe_entry *hwe, unsigned int foe_index);
int32_t PpeFillInL2Info(struct sk_buff * skb, struct airoha_foe_entry *foe_entry);
int32_t PpeFillInL3Info(struct sk_buff * skb, struct airoha_foe_entry *foe_entry);
u32 arht_ppe_foe_entry_set_qdata(struct airoha_gdm_dev *dev, struct net_device *netdev, u32 qdata, u32 priority,int dsa_port);
u32 arht_ppe_foe_entry_set_fastpath(struct airoha_eth *eth,struct airoha_gdm_dev *dev,u32 val,int dsa_port);
void arht_ppe_init(struct airoha_ppe *ppe);
void arht_ppe_deinit(void);

int airoha_ppe_clean_entry_by_gemport(unsigned int gemport_id);
int airoha_ppe_rxinfo_handler(struct sk_buff *skb, int magic, char *data, int data_length);
int is_Valid_Foe_Entry(struct sk_buff * skb);
int airoha_ppe_foe_get_vlan_info(struct sk_buff *skb, u16 *vn, u16 *vid1, u16 *vid2);
void airoha_ppe_foe_get_vlan_vpm(struct sk_buff *skb, u16 *vpm);

/* L2B ether type configuration functions */
int ppe_set_l2b_ether_type_auto(u16 etype, unsigned int is_pppoe, bool *existed);
int ppe_clear_l2b_ether_type_auto(u16 etype, unsigned int is_pppoe);
#endif /* __ARHT_PPE_H_ */