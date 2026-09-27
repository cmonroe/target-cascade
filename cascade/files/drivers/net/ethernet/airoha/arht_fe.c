// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 AIROHA Inc
 * Author:  2024 AIROHA Inc
 */

#include "airoha_eth.h"
#include "airoha_regs.h"
#include "airoha_function.h"
#include "arht_fe.h"



/************************************************************************
*                  P U B L I C   D A T A
*************************************************************************
*/
#define CHANNEL_RETIRE 1
#define CHANNEL_DROP 0

DEFINE_SPINLOCK(fe_pse_reset_lock);
atomic_t qdma_stop_flag = ATOMIC_INIT(0);
/* Counts how many times airoha_fe_do_core_reset() has been invoked.
 * Readable via debugfs dp_api/fe_hc for RD diagnostics.
 * Use atomic_t to avoid data races between the workqueue writer
 * and the debugfs reader running on different CPUs.
 */
atomic_t fe_core_reset_count = ATOMIC_INIT(0);
int channel_retire = CHANNEL_RETIRE;

/* FE */
#define isEN751221		0
#define PSE_BASE			0x0100
#define CSR_IFC_BASE		0x0200
#define CDM1_BASE			0x0400
#define GDM1_BASE			0x0500
#define PPE1_BASE			0x0c00

#define CDM2_BASE			0x1400
#define GDM2_BASE			0x1500

#define GDM3_BASE			0x1100
#define GDM4_BASE			0x2500

#define GDM_BASE(_n)			\
	((_n) == 4 ? GDM4_BASE :	\
	 (_n) == 3 ? GDM3_BASE :	\
	 (_n) == 2 ? GDM2_BASE : GDM1_BASE)

#define REG_FE_WAN_MAC_H		0x0030
#define REG_FE_MAC_LMIN(_n)		((_n) + 0x04)
#define REG_FE_MAC_LMAX(_n)		((_n) + 0x08)

#define GDMA1_TXCHN_EN      (GDM1_BASE + 0x24)
#define GDMA1_RXCHN_EN      (GDM1_BASE + 0x28)

#define GDMA2_TXCHN_EN       (GDM2_BASE + 0x24)
#define GDMA2_RXCHN_EN       (GDM2_BASE + 0x28)


#define CDMA1_HWF_CHN_EN     (CDM1_BASE + 0x0c)
#define CDMA2_HWF_CHN_EN     (CDM2_BASE + 0x0c)
#define GDMA_CHN_RLS_CHN_OFFSET     4
#define GDMA_CHN_RLS_EN_OFFSET      0 

#define GDMA1_CHN_RLS       (GDM1_BASE + 0x20)
#define GDMA2_CHN_RLS       (GDM2_BASE + 0x20)



#define L2BR_ETYPE_EN			(0x284)

#define L2BR_ETYPE_N(x)			(0x290 + 4*(x/2))

#define GDMA1_MIB_CLER			(GDM1_BASE + 0xf0)	
#define GDMA2_MIB_CLER			(GDM2_BASE + 0xf0)	
#define isEN7526c		0
#define isEN751627		0
#define GDMA2_FWD_CFG       (GDM2_BASE + 0x00)

#define GDMA2_TX_FAVOR_OAM_OFFSET		19


#define GDMA_MISC_CFG           (0x148)
#define GDMA2_RLS_MODE_BIT           (1<<1)

#define GDMA1_LEN_CFG       (GDM1_BASE + 0x14)
#define GDMA2_LEN_CFG    	(GDM2_BASE + 0x14)
#define GDMA3_LEN_CFG        (GDM3_BASE + 0x14)
#define GDMA4_LEN_CFG        (GDM4_BASE + 0x114)

#define GDMA1_COUNT_BASE 	    (0x600)
#define GDMA1_RX_OVER_DROP_CNT  (GDMA1_COUNT_BASE + 0x54)


#define GDMA2_COUNT_BASE 	(0x1600)
#define GDMA2_RX_OVDROPCNT    (GDMA2_COUNT_BASE + 0x54)

#define PSE_IQ_STA1     (0x110)
#define PSE_IQ_STA2     (0x114)

#define GDMA1_TX_CHN_VLD     (GDM1_BASE + 0x70)
#define GDMA2_TX_CHN_VLD     (GDM1_BASE + 0x70)

#define GDMA_CHN_RLS_STAT_OFFSET    1

#define GDMA_CHN_RLS_TIMEOUT        (10)

/* GDM2 RX eth MIB, support EN7523, EN7581, AN7552 */
#if defined(TCSUPPORT_CPU_EN7523) || defined(TCSUPPORT_CPU_EN7581)
#define GDM2_RX_ETH_MIB_SUPPORT	1
#else
#define GDM2_RX_ETH_MIB_SUPPORT	0
#endif

/* GDM2 TX eth MIB, support EN7523, EN7581, AN7552 */
#if defined(TCSUPPORT_CPU_EN7523) || defined(TCSUPPORT_CPU_EN7581)
#define GDM2_TX_ETH_MIB_SUPPORT	1
#else
#define GDM2_TX_ETH_MIB_SUPPORT	0
#endif

#define GDMA2_LPBP_CFG      (GDM2_BASE + 0x1c)
#define GDMA2_FWD_CFG       (GDM2_BASE + 0x00)

#define MBI_TX_BUSY_OFFSET          19
#define MBI_TX_TERMINATE_OFFSET     16
#define MBI_RX_BUSY_OFFSET          27
#define MBI_RX_TERMINATE_OFFSET     24

#define QDMA_GLB_CFG     0x5004

#define GDMA2_RX_OKCNT     	(GDMA2_COUNT_BASE + 0x48)
#define GDMA2_RX_FCDROPCNT     	(GDMA2_COUNT_BASE + 0x4c)
#define GDMA2_RX_RCDROPCNT     	(GDMA2_COUNT_BASE + 0x50)

#define GDMA2_RX_OVDROPCNT    (GDMA2_COUNT_BASE + 0x54)
#define GDMA2_RX_ERRDROPCNT    (GDMA2_COUNT_BASE + 0x58)
#define GDMA2_RX_OKBYTECNT    (GDMA2_COUNT_BASE + 0x5c)

#define GDMA2_RX_ETHERPCNT  (GDMA2_COUNT_BASE + 0x60)
#define GDMA2_RX_ETHERPLEN  (GDMA2_COUNT_BASE + 0x64)
#define GDMA2_RX_ETHDROPCNT (GDMA2_COUNT_BASE + 0x68)
#define GDMA2_RX_ETHBCCNT   (GDMA2_COUNT_BASE + 0x6c)
#define GDMA2_RX_ETHMCCNT   (GDMA2_COUNT_BASE + 0x70)
#define GDMA2_RX_ETHCRCCNT  (GDMA2_COUNT_BASE + 0x74)
#define GDMA2_RX_ETHFRACCNT (GDMA2_COUNT_BASE + 0x78)
#define GDMA2_RX_ETHJABCNT  (GDMA2_COUNT_BASE + 0x7c)
#define GDMA2_RX_ETHRUNTCNT (GDMA2_COUNT_BASE + 0x80)
#define GDMA2_RX_ETHLONGCNT (GDMA2_COUNT_BASE + 0x84)
#define GDMA2_RX_ETH_64_CNT (GDMA2_COUNT_BASE + 0x88)
#define GDMA2_RX_ETH_65_TO_127_CNT (GDMA2_COUNT_BASE + 0x8C)
#define GDMA2_RX_ETH_128_TO_255_CNT (GDMA2_COUNT_BASE + 0x90)
#define GDMA2_RX_ETH_256_TO_511_CNT (GDMA2_COUNT_BASE + 0x94)
#define GDMA2_RX_ETH_512_TO_1023_CNT (GDMA2_COUNT_BASE + 0x98)
#define GDMA2_RX_ETH_1024_TO_1518_CNT (GDMA2_COUNT_BASE + 0x9C)


#define GDMA2_RX_OKCNT_H	(GDMA2_COUNT_BASE + 0x190)
#define GDMA2_RX_OKBYTECNT_H	(GDMA2_COUNT_BASE + 0x194)
#define GDMA2_RX_ETHERPCNT_H	(GDMA2_COUNT_BASE + 0x198)
#define GDMA2_RX_ETHERPLEN_H	(GDMA2_COUNT_BASE + 0x19c)

#define GDMA2_RX_ETH_64_CNT_H			(GDMA2_COUNT_BASE + 0x1e8)
#define GDMA2_RX_ETH_65_TO_127_CNT_H	(GDMA2_COUNT_BASE + 0x1ec)
#define GDMA2_RX_ETH_128_TO_255_CNT_H	(GDMA2_COUNT_BASE + 0x1f0)
#define GDMA2_RX_ETH_256_TO_511_CNT_H	(GDMA2_COUNT_BASE + 0x1f4)
#define GDMA2_RX_ETH_512_TO_1023_CNT_H	(GDMA2_COUNT_BASE + 0x1f8)
#define GDMA2_RX_ETH_1024_TO_1518_CNT_H	(GDMA2_COUNT_BASE + 0x1fc)


#define GDMA2_TX_ETHCNT   	(GDMA2_COUNT_BASE + 0x10)
#define GDMA2_TX_ETHLENCNT   	(GDMA2_COUNT_BASE + 0x14)
#define GDMA2_TX_ETHDROPCNT   	(GDMA2_COUNT_BASE + 0x18)
#define GDMA2_TX_ETHBCDCNT   	(GDMA2_COUNT_BASE + 0x1C)
#define GDMA2_TX_ETHMULTICASTCNT   	(GDMA2_COUNT_BASE + 0x20)
#define GDMA2_TX_ETH_LESS64_CNT   	(GDMA2_COUNT_BASE + 0x24)
#define GDMA2_TX_ETH_MORE1518_CNT   	(GDMA2_COUNT_BASE + 0x28)
#define GDMA2_TX_ETH_64_CNT   			(GDMA2_COUNT_BASE + 0x2C)
#define GDMA2_TX_ETH_65_TO_127_CNT   	(GDMA2_COUNT_BASE + 0x30)
#define GDMA2_TX_ETH_128_TO_255_CNT   	(GDMA2_COUNT_BASE + 0x34)
#define GDMA2_TX_ETH_256_TO_511_CNT   	(GDMA2_COUNT_BASE + 0x38)
#define GDMA2_TX_ETH_512_TO_1023_CNT   	(GDMA2_COUNT_BASE + 0x3C)
#define GDMA2_TX_ETH_1024_TO_1518_CNT   	(GDMA2_COUNT_BASE + 0x40)
#define GDMA2_TX_ETHCNT_H	(GDMA2_COUNT_BASE + 0x188)
#define GDMA2_TX_ETHLENCNT_H	(GDMA2_COUNT_BASE + 0x18c)
#define GDMA2_TX_ETH_64_CNT_H		(GDMA2_COUNT_BASE + 0x1b8)
#define GDMA2_TX_ETH_65_TO_127_CNT_H	(GDMA2_COUNT_BASE + 0x1bc)
#define GDMA2_TX_ETH_128_TO_255_CNT_H	(GDMA2_COUNT_BASE + 0x1c0)
#define GDMA2_TX_ETH_256_TO_511_CNT_H	(GDMA2_COUNT_BASE + 0x1c4)
#define GDMA2_TX_ETH_512_TO_1023_CNT_H	(GDMA2_COUNT_BASE + 0x1c8)
#define GDMA2_TX_ETH_1024_TO_1518_CNT_H	(GDMA2_COUNT_BASE + 0x1cc)

#define GDMA3_CHN_RLS	(GDM3_BASE + 0x20)
#define GDMA3_TXCHN_EN	(GDM3_BASE + 0x24)
#define GDMA3_RXCHN_EN	(GDM3_BASE + 0x28)
#define GDMA3_TX_CHN_VLD (GDM3_BASE + 0x70)
#define GDMA3_RX_CHN_VLD (GDM3_BASE + 0x74)

unsigned long long gdm2_rx_len_high = 0;
unsigned long long gdm2_rx_drop_high = 0;

unsigned long long gdm2_tx_len_high = 0;
unsigned long long gdm2_tx_drop_high = 0;

#if defined(TCSUPPORT_CPU_AN7583)
#define HWF_QDMA_SEL_SUPPORT	1
#else
#define HWF_QDMA_SEL_SUPPORT	0
#endif

#define FE_HWF_QDMA_SEL_OFFSET (0x20f4)
#define ETH_OFT 5/*for 7583 GDM3*/
#define PCIE_OFT 6/*for 7583 GDM4 OQ0*/
#define USB_OFT 7/*for 7583 GDM4 OQ1*/

/*
#define FeGetHwfQdmaSelGdm3() IO_GMASK(FE_HWF_QDMA_SEL,1<<ETH_OFT,ETH_OFT)
#define FeGetHwfQdmaSelGdm4() (IO_GMASK(FE_HWF_QDMA_SEL,1<<PCIE_OFT,PCIE_OFT)||IO_GMASK(FE_HWF_QDMA_SEL,1<<USB_OFT,USB_OFT))
*/

#define FeGetHwfQdmaSelGdm3(eth) ((airoha_fe_rr(eth, FE_HWF_QDMA_SEL_OFFSET) & (1 << ETH_OFT)) >> ETH_OFT)

#define FeGetHwfQdmaSelGdm4(eth) (((airoha_fe_rr(eth, FE_HWF_QDMA_SEL_OFFSET) & (1 << PCIE_OFT)) >> PCIE_OFT) || \
                                  ((airoha_fe_rr(eth, FE_HWF_QDMA_SEL_OFFSET) & (1 << USB_OFT)) >> USB_OFT))

 
#define GDMA4_TXCHN_EN	(GDM3_BASE + 0x124)
#define GDMA4_RXCHN_EN	(GDM3_BASE + 0x128)
#define GDMA4_TX_CHN_VLD (GDM3_BASE + 0x170)
#define GDMA4_RX_CHN_VLD (GDM3_BASE + 0x174)
#define GDMA4_CHN_RLS      (GDM4_BASE + 0x120)

#define PSE_RSV_PAGE_DEFAULT    0x80/*hw default rsv page*/

#if defined(TCSUPPORT_CPU_EN7523)
#define PSE_SHARE_USED_MTHD_OFFSET 16
#define PSE_SHARE_USED_MTHD_MASK (0xffff<<PSE_SHARE_USED_MTHD_OFFSET)
#define PSE_SHARE_USED_THD	(0x94)
#define PSE_FQ_STA			(0x108)
#define PSE_FQFC_CFG_STA(i)	(0x118 + (i<<2))
#define PSE_FQFC_CFG_STA0	(0x118)
#define PSE_FQFC_CFG_STA1	(0x11C)
#define PSE_DROP_CNT(i)		(0x120 + (i<<2))
#define PSE_DROP_CNT_0      (0x120)
#define PSE_DROP_CNT_1      (0x124)
#define PSE_DROP_CNT_2      (0x128)
#define PSE_DROP_CNT_3      (0x12C)
#define PSE_DROP_CNT_4      (0x130)
#define PSE_DROP_CNT_5      (0x134)
#define PSE_DROP_CNT_6      (0x138)
#else
#define PSE_SHARE_USED_THD  (0xD0)
#define PSE_FQ_STA          (0x150)
#define PSE_FQFC_CFG_STA(i) (0x10C + (i<<2))
#define PSE_FQFC_CFG_STA0   (0x10C)
#define PSE_FQFC_CFG_STA1   (0x110)
#define PSE_DROP_CNT(i)     (0x178 + (i<<2))
#define PSE_DROP_CNT_0      (0x178)
#define PSE_DROP_CNT_1      (0x17C)
#define PSE_DROP_CNT_2      (0x180)
#define PSE_DROP_CNT_3      (0x184)
#define PSE_DROP_CNT_4      (0x188)
#define PSE_DROP_CNT_5      (0x18C)
#define PSE_DROP_CNT_6      (0x190)
#endif

#define PSE_QUEUE_CFG_WR		(0x80)
#define PSE_CFG_PORT_ID_SHIFT	(24)
#define PSE_CFG_QUEUE_ID_SHIFT	(16)
#define PSE_QUEUE_CFG_VAL		(0x84)

#if defined(TCSUPPORT_CPU_AN7552)
#define PSE_CFG_OQ_LTHD_SHIFT	(18)
#define PSE_CFG_OQ_EN_SHIFT	    (16)
#define PSE_CFG_OQ_EN_MASK		(0x1<<PSE_CFG_OQ_EN_SHIFT)
#define PSE_CFG_OQ_RSV_SHIFT	(0)
#else
#define PSE_CFG_OQ_LTHD_SHIFT	(30)
#define PSE_CFG_OQ_RSV_SHIFT	(0)
#endif

#define PSE_CFG_OQRSV_SEL_SHIFT	(0)
#define PSE_CFG_WR_EN_SHIFT		(8)
#define PSE_CFG_WR_EN			(0x1<<PSE_CFG_WR_EN_SHIFT)
#define PSE_CFG_OQRSV_SEL		(0x1<<PSE_CFG_OQRSV_SEL_SHIFT)

#define PSE_SHARE_USED_LTHD_OFFSET 16
#define PSE_BUFF_SET	(0x90)

/*
#define GET_PSE_ALL_RSV()    IO_GMASK(PSE_BUFF_SET,0x7fff,0)

#define SET_PSE_ALL_RSV(val)    IO_SMASK(PSE_BUFF_SET,0x7fff,0,val)

#define GET_PSE_FQ_LITMI() IO_GMASK(PSE_FQ_CFG,0x7fff,0)


#define SET_PSE_SHARED_USED_HTHD(val)   IO_SMASK(PSE_SHARE_USED_THD,0xffff,0,val)

#define SET_PSE_SHARED_USED_MTHD(val)   IO_SMASK(PSE_SHARE_USED_THD,PSE_SHARE_USED_MTHD_MASK,PSE_SHARE_USED_MTHD_OFFSET,val)

#define SET_PSE_SHARED_USED_LTHD(val)   IO_SMASK(PSE_BUFF_SET,PSE_SHARE_USED_LTHD_MASK,PSE_SHARE_USED_LTHD_OFFSET,val)
*/

#define GET_PSE_ALL_RSV(eth) \
    ((airoha_fe_rr(eth, PSE_BUFF_SET) & 0x7FFF) >> 0)

#define SET_PSE_ALL_RSV(eth, val) \
    airoha_fe_rmw(eth, PSE_BUFF_SET, 0x7FFF, (val << 0))

#define GET_PSE_FQ_LITMI(eth) \
    ((airoha_fe_rr(eth, PSE_FQ_CFG_OFFSET) & 0x7FFF) >> 0)

#define SET_PSE_SHARED_USED_HTHD(eth, val) \
    airoha_fe_rmw(eth, PSE_SHARE_USED_THD, 0xFFFF, (val << 0))

#define SET_PSE_SHARED_USED_MTHD(eth, val) \
    airoha_fe_rmw(eth, PSE_SHARE_USED_THD, PSE_SHARE_USED_MTHD_MASK, (val << PSE_SHARE_USED_MTHD_OFFSET))

#define SET_PSE_SHARED_USED_LTHD(eth, val) \
    airoha_fe_rmw(eth, PSE_BUFF_SET, PSE_SHARE_USED_LTHD_MASK, (val << PSE_SHARE_USED_LTHD_OFFSET))


#if 0
/* Warning: same sequence with enum 'FE_HookFunctionID_t' in ecnt_hook_fe.h */
fe_api_op_t
fe_operation[]=
{
	fe_api_set_pkt_length,
	fe_api_set_channel_enable,
	fe_api_set_mac_addr,
	fe_set_hwfwd_channel,
	fe_api_set_channel_retire,
	fe_api_set_crc_strip,
	fe_api_set_padding,
	fe_api_get_ext_tpid,
	fe_api_set_ext_tpid,
	fe_api_get_fw_cfg,
	fe_api_set_fw_cfg,
	fe_api_set_drop_udp_chksum_err_enable,
	fe_api_set_drop_tcp_chksum_err_enable,
	fe_api_set_drop_ip_chksum_err_enable,
	fe_api_set_drop_crc_err_enable,
	fe_api_set_drop_runt_enable,
	fe_api_set_drop_long_enable,
	fe_api_set_vlan_check,
	fe_api_get_ok_cnt,
	fe_api_get_rx_err_crc_cnt,
	fe_api_get_rx_drop_fifo_cnt,
	fe_api_get_rx_drop_err_cnt,
	fe_api_get_ok_byte_cnt,
	fe_api_get_tx_get_cnt,
	fe_api_get_tx_drop_cnt,
	fe_api_get_time_stamp,
	fe_api_set_time_stamp,
	fe_api_set_ins_vlan_tpid,
	fe_api_set_vlan_enable,
	fe_api_set_black_list,
	fe_api_set_ether_type,
	fe_api_set_L2U_key,
	fe_api_get_ac_group_pkt_cnt,
	fe_api_get_ac_group_byte_cnt,
	fe_api_clear_ac_group_pkt_cnt,
	fe_api_clear_ac_group_byte_cnt,
	fe_api_set_meter_group,
	fe_api_get_meter_group,
	fe_api_set_gdm_pcp_coding,
	fe_api_set_cdm_pcp_coding,
	fe_api_set_vip_enable,
	fe_api_get_eth_rx_cnt,
	fe_api_get_eth_tx_cnt,
	fe_api_get_eth_frame_cnt,
	fe_api_get_eth_err_cnt,
	fe_api_set_clear_mib,
	fe_api_set_cdm_rx_red_drop_mode,
	fe_api_get_cdm_rx_red_drop_mode,
	fe_api_set_channel_retire_all,
	fe_api_set_channel_retire_one,
	fe_api_set_tx_rate,
	fe_api_set_rxuc_rate,
	fe_api_set_rxbc_rate,
	fe_api_set_rxmc_rate,
	fe_api_set_rxoc_rate,
	fe_api_add_vip_ether,
	fe_api_add_vip_ppp,
	fe_api_add_vip_ip,
	fe_api_add_vip_tcp,
	fe_api_add_vip_udp,
	fe_api_del_vip_ether,
	fe_api_del_vip_ppp,
	fe_api_del_vip_ip,
	fe_api_del_vip_tcp,
	fe_api_del_vip_udp,	
	fe_api_add_l2lu_vlan_dscp,
	fe_api_add_l2lu_vlan_trfc,
	fe_api_del_l2lu_vlan_dscp,
	fe_api_del_l2lu_vlan_trfc,
	fe_api_add_traffic_class,
    fe_api_del_traffic_class,
	fe_api_set_tx_favor_oam_enable,
	fe_api_set_tls_cfg,
	fe_api_tls_forwad,
	fe_api_do_fe_reset,
	fe_api_set_mac_addr_7516,
	fe_api_set_wan_port_7516,
	fe_api_set_loopback_enable,
	fe_api_set_loopback_mode,
	fe_api_get_unknown_mul_pkt,
	fe_api_set_meter_ratelimit,
	fe_api_get_meter_ratelimit,
	fe_api_get_meter_idx,
	fe_api_get_acnt1_idx,
	fe_api_get_acnt0_idx,
	fe_api_init_resource_manage,
	fe_api_deinit_resource_manage,
	fe_api_set_rx_ratelimit_rule,
	fe_api_set_rx_ratelimit_mode,
	fe_api_set_meter_ctl_by_olt,
	fe_api_get_flow_cnt,
	fe_api_clear_flow_cnt,
	fe_api_get_acnt0_mode,
	fe_api_get_acnt1_mode,
	fe_api_set_acnt0_mode,
	fe_api_set_acnt1_mode,
	fe_api_get_meter_enable,
	fe_api_get_dev_mac_index,
	fe_api_set_pse_oq_threshold,
	fe_api_get_acnt2_idx,
	fe_api_set_acnt2_mode,
	fe_api_get_wan_itf_index,
	fe_api_set_glo_rate_byte,
	fe_api_get_pppoe_info,
	fe_api_set_pppoe_info_clean,
	fe_api_get_tx_traffic,  /* kbps */
	fe_api_get_rx_traffic,
	fe_api_get_tx_rate,     /* pps */
	fe_api_get_rx_rate,
	fe_api_get_tx_octets,  /* byte cnt in 15 minutes */
	fe_api_get_rx_octets,
	fe_api_get_rx_discard_counter, /*cnt in 15 minutes*/
	fe_api_get_tx_discard_counter,
	fe_api_get_rx_error_counter,
	fe_api_get_tx_error_counter,
	fe_api_add_dev_to_total_account,
	fe_api_add_stb_src_ip,
	fe_api_del_stb_src_ip,
	fe_api_set_ratelimit_for_pkt_formate,
	fe_api_set_mc_vlan_global,
	fe_api_get_mc_vlan_global,
	fe_api_set_mc_vlan_table_cfg,
	fe_api_get_mc_vlan_table_cfg,
	fe_api_set_mc_vlan_action_cfg,
	fe_api_get_mc_vlan_action_cfg,
	fe_api_set_mc_vlan_clear_all,
	fe_api_set_rx_mac_filter,
	fe_api_set_rx_mac_filter_rate,
	fe_api_xfi_link_change,
	fe_api_set_gdma_misc_config,
    fe_api_get_rx_ratelimit_mode,
	fe_api_get_hsgmii_rx_cnt,
	fe_api_get_hsgmii_tx_cnt,
	fe_api_set_aewan_fwdfq,
	fe_api_set_aewan_ifcdisable,
	fe_api_set_gdm2_sptag_for_loopback,
	fe_api_set_rx_rate,
	fe_api_set_tunnel_cfg,
	fe_api_set_gdm_sptag_for_extswitch,
	fe_api_pse_oq_rsv_en,
	fe_api_set_hsgmii_rx_port_ratelimit,
	fe_api_set_mbi_arb_rst,
	fe_api_set_rmbi_frag,
	fe_api_get_chn_rls,
	fe_api_set_tmbi_frag,
	fe_api_set_gdma_enable,
	fe_api_set_gdma_disable,
	fe_api_get_pse_drop_cnt,
    fe_api_set_chn_retire_action,
    fe_api_set_chn_retire_done,
    fe_api_set_qbi_fttr_chn_disable,
    fe_api_set_force_slow_enable,
    fe_api_set_force_slow_duty,
    fe_api_set_vip_rxq_selection,
    fe_api_set_vip_for_tcp_speedtest,
    fe_api_check_chn_rls,
	#ifndef TCSUPPORT_ACCOUNT_METER_V2
	fe_api_set_dev_stat_ratelimit_mode,
	#endif
	fe_api_set_clr_cnt
};
#endif

/************************************************************************
*                  FE APIs
*************************************************************************
*/

int fe_api_set_channel_enable(struct ecnt_fe_data *fe_data)
{
	unsigned long int offset, val;
	struct airoha_eth *eth = glb_eth;
	
	FE_Gdma_Sel_t gdm_sel = fe_data->gdm_sel;
	FE_TXRX_Sel_t txrx_sel = fe_data->txrx_sel;
	FE_Enable_t enable = fe_data->api_data.enable;
	uint channel = fe_data->channel;
    ulong flags = 0;

    if (isEN751221)
    {
	    spin_lock_irqsave(&fe_pse_reset_lock, flags);
    }

	if(gdm_sel == FE_GDM_SEL_GDMA1){
		if(txrx_sel == FE_GDM_SEL_TX)
			offset = GDMA1_TXCHN_EN;
		else
			offset = GDMA1_RXCHN_EN;
	}else{
		if(txrx_sel == FE_GDM_SEL_TX)
			offset = GDMA2_TXCHN_EN;
		else
			offset = GDMA2_RXCHN_EN;
	}

	//val = read_reg_word(base_addr);
	val = airoha_fe_rr(eth, offset);
	
	if(enable == FE_DISABLE){
		val &= ~(1<<channel);
	}else{
		val |= (1<<channel);
	}
	
	//write_reg_word(base_addr, val);
	airoha_fe_wr(eth, offset, val);
	

    if (isEN751221)
    {
	    spin_unlock_irqrestore(&fe_pse_reset_lock, flags);
    }
    
	return 0;
}



int fe_set_hwfwd_channel(struct ecnt_fe_data *fe_data)
{
	struct airoha_eth *eth = glb_eth;
	
	FE_Cdma_Sel_t	cdm_sel = fe_data->cdm_sel;
	uint			channel = fe_data->channel;
	FE_Enable_t		enable = fe_data->api_data.enable;
	unsigned int	offset, value ;

	if (cdm_sel == FE_CDM_SEL_CDMA1){
		offset = CDMA1_HWF_CHN_EN;
	}else if(cdm_sel == FE_CDM_SEL_CDMA2){
		offset = CDMA2_HWF_CHN_EN;
	}else{
		return -1;
	}
	printk("\n In fe_set_hwfwd_channel:: \n");
	printk("before: %08x \n",readl(((eth)->fe_regs)+offset));
	//value = read_reg_word(reg);
	value = airoha_fe_rr(eth, offset);

	value &= ~(1 << channel);

	value |= (enable << channel);
	
	//write_reg_word(reg, value);
	airoha_fe_wr(eth, offset, value);
	
	printk("after: %08x \n",readl(((eth)->fe_regs)+offset));

	return 0;
}



int fe_api_set_chn_retire_done(struct ecnt_fe_data *fe_data)
{
	struct airoha_eth *eth = glb_eth;
    unsigned int   offset = 0;
    unsigned int value = 0;
    uint      chn_done = 0;
    uint           chn = fe_data->channel;
    FE_Gdma_Sel_t gdm_sel = fe_data->gdm_sel;
	
	
	
    if (gdm_sel == FE_GDM_SEL_GDMA1)
    {
        offset = GDMA1_CHN_RLS;
    }
    else if(gdm_sel == FE_GDM_SEL_GDMA2)
    {
        offset = GDMA2_CHN_RLS;
    }
    else
    {
        return -1;
    }
    chn &= 0x1f;
    //value = read_reg_word(reg);
	value = airoha_fe_rr(eth, offset);
	
    chn_done = (value >> GDMA_CHN_RLS_CHN_OFFSET) & 0x1f;
    if(chn_done == chn)
    {
        //write_reg_word(reg, 0);
		airoha_fe_wr(eth, offset, 0);
    }
    else
    {
        return -1;
    }

    return 0;
}



int fe_api_set_chn_retire_action(struct ecnt_fe_data *fe_data)
{
	struct airoha_eth *eth = glb_eth;
    unsigned int      offset = 0;
    unsigned int    value = 0;
    unsigned int      chn = fe_data->channel;
    FE_Gdma_Sel_t gdm_sel = fe_data->gdm_sel;
    if (gdm_sel == FE_GDM_SEL_GDMA1)
    {
        offset = GDMA1_CHN_RLS;
    }
    else if(gdm_sel == FE_GDM_SEL_GDMA2)
    {
        offset = GDMA2_CHN_RLS;
    }
    else
    {
        return -1;
    }
    chn &= 0x1f;
    value = (chn << GDMA_CHN_RLS_CHN_OFFSET) | (1 << GDMA_CHN_RLS_EN_OFFSET);
    //write_reg_word(reg, value);
	airoha_fe_wr(eth, offset, value);

    return 0;
}



/* Check occurrence of FE HW bug, in case of which channel retire can not be performed */
static int fe_api_pse_iq_abnormal(void)
{
	struct airoha_eth *eth = glb_eth;
    uint32 pse_iq_cnt = 0, pse_iq_stat1 = 0, pse_iq_stat2 = 0;
   
    //pse_iq_stat1 = read_reg_word(0xbfb50110);
    //pse_iq_stat2 = read_reg_word(0xbfb50114);
	pse_iq_stat1 = airoha_fe_rr(eth, PSE_IQ_STA1);
	
    pse_iq_stat2 = airoha_fe_rr(eth, PSE_IQ_STA1);
	
    pse_iq_cnt = (pse_iq_stat1 & 0xff) + ((pse_iq_stat1 >> 8) & 0xff) + ((pse_iq_stat1 >> 16) & 0xff) + ((pse_iq_stat2 >> 8) & 0xff);

    if (pse_iq_cnt > 0xA0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}


int fe_get_hwfwd_channel(struct ecnt_fe_data *fe_data)
{
	struct airoha_eth *eth = glb_eth;
	unsigned int	offset, value ;
	FE_Cdma_Sel_t	cdm_sel = fe_data->cdm_sel;
	uint			channel = fe_data->channel;

	if (cdm_sel == FE_CDM_SEL_CDMA1){
		offset = CDMA1_HWF_CHN_EN;
	}else if(cdm_sel == FE_CDM_SEL_CDMA2){
		offset = CDMA2_HWF_CHN_EN;
	}else{
		return -1;
	}

	//value = read_reg_word(offset);
	value = airoha_fe_rr(eth, offset);

	value &= (1 << channel);

	fe_data->api_data.enable = (value >> channel);

	return 0;
}


int fe_api_set_channel_retire(struct ecnt_fe_data *fe_data)
{
	struct airoha_eth *eth = glb_eth;
	unsigned int reg,reg2,value,mask,ret = 0;
	unsigned int txreg,rxreg,txchn,rxchn;
	FE_Enable_t rxHwfwd;
	struct ecnt_fe_data cdm_fe_data;
	FE_Gdma_Sel_t gdm_sel = fe_data->gdm_sel;
	uint channel = fe_data->channel;
	uint mode = fe_data->reg_val;

    if (isEN751221 && fe_api_pse_iq_abnormal())
    {
        printk("Info: fe_api_set_channel_retire ingored due to PSE IQ resource abnormal\n");
        return 0;
    }

	if (gdm_sel == FE_GDM_SEL_GDMA1){
		reg = GDMA1_CHN_RLS;
		reg2 = GDMA1_TX_CHN_VLD;
		txreg = GDMA1_TXCHN_EN;
		rxreg = GDMA1_RXCHN_EN;
	}else if(gdm_sel == FE_GDM_SEL_GDMA2){
		reg = GDMA2_CHN_RLS;
		reg2= GDMA2_TX_CHN_VLD;
		txreg = GDMA2_TXCHN_EN;
		rxreg = GDMA2_RXCHN_EN;		
	}else{
		return -1;
	}	
	
	//mask = read_reg_word(reg2);
	mask = airoha_fe_rr(eth, reg2);
	
	/* this comment to be removed later 
	if ( ((1<< channel)& mask) == 0)
		return 0;
	*/
	if (gdm_sel == FE_GDM_SEL_GDMA1) {
		cdm_fe_data.cdm_sel = FE_CDM_SEL_CDMA1;
		cdm_fe_data.channel = channel;
		
		fe_get_hwfwd_channel(&cdm_fe_data);
		rxHwfwd = cdm_fe_data.api_data.enable;

		cdm_fe_data.api_data.enable = FE_DISABLE;
		fe_set_hwfwd_channel(&cdm_fe_data);
	}
	else {
		cdm_fe_data.cdm_sel = FE_CDM_SEL_CDMA2;
		cdm_fe_data.channel = channel;
		
		fe_get_hwfwd_channel(&cdm_fe_data);
		rxHwfwd = cdm_fe_data.api_data.enable;
		
		cdm_fe_data.api_data.enable = FE_DISABLE;
		fe_set_hwfwd_channel(&cdm_fe_data);
	}

	if (mode == FE_LINKDOWN){
		//txchn = read_reg_word(txreg);
		//rxchn = read_reg_word(rxreg);
		txchn = airoha_fe_rr(eth, txreg);
		rxchn = airoha_fe_rr(eth, rxreg);
		//write_reg_word(txreg,0);
		//write_reg_word(rxreg,0);
		airoha_fe_wr(eth, txreg, 0);
		airoha_fe_wr(eth, rxreg, 0);
	}

	value = (channel << GDMA_CHN_RLS_CHN_OFFSET) | (1 << GDMA_CHN_RLS_EN_OFFSET);
	
	//write_reg_word(reg,value);
	airoha_fe_wr(eth, reg, value);
	
	mdelay(1);
	
	value = 0;
		
	while( ( (airoha_fe_rr(eth, reg) & (1 << GDMA_CHN_RLS_STAT_OFFSET)) == 0 
				||  (airoha_fe_rr(eth, reg2) & (1 << channel)) != 0 )
				&& (value++ < GDMA_CHN_RLS_TIMEOUT)){
		mdelay(1);
	}
	
	if (value >= GDMA_CHN_RLS_TIMEOUT){
		printk("fe_api_set_channel_retire: timeout \n");
		ret = -1;
	}

	//write_reg_word(reg,0);
	airoha_fe_wr(eth, reg, 0);
	
	if (mode == FE_LINKDOWN){
		//write_reg_word(txreg,txchn);
		//write_reg_word(rxreg,rxchn);
		airoha_fe_wr(eth, txreg, txchn);
		airoha_fe_wr(eth, rxreg, rxchn);
	}
	
	if (gdm_sel == FE_GDM_SEL_GDMA1) {
		cdm_fe_data.cdm_sel = FE_CDM_SEL_CDMA1;
		cdm_fe_data.channel = channel;
		cdm_fe_data.api_data.enable = rxHwfwd;
		fe_set_hwfwd_channel(&cdm_fe_data);
	} else {
		cdm_fe_data.cdm_sel = FE_CDM_SEL_CDMA2;
		cdm_fe_data.channel = channel;
		cdm_fe_data.api_data.enable = rxHwfwd;
		fe_set_hwfwd_channel(&cdm_fe_data);
	}
	
	return ret;

}



int fe_api_set_ether_type(struct ecnt_fe_data *fe_data)
{
	struct airoha_eth *eth = glb_eth;
	unsigned long int val, type;
	uint index = fe_data->index;
	FE_Enable_t enable = fe_data->api_data.eth_cfg.enable;
	FE_PPPOE_t is_pppoe = fe_data->api_data.eth_cfg.is_pppoe;
	uint value = fe_data->api_data.eth_cfg.value;
	
	if(index > 15){
		printk("Error index %d, should be 0~15!\n", index);
		return 1;
	}
	//val = read_reg_word(L2BR_ETYPE_EN);
	val = airoha_fe_rr(eth, L2BR_ETYPE_EN);
	
	if(enable == FE_DISABLE){
		if(is_pppoe){	
			val &= ~(1<<(index+16));
		}
			val &= ~(1<<index);
	}else{
		if(is_pppoe){
			val |= (1<<(index+16));
		}
			val |= (1<<index);
	}

	//write_reg_word(L2BR_ETYPE_EN, val);
	airoha_fe_wr(eth, L2BR_ETYPE_EN, val);
	
	//type = read_reg_word(L2BR_ETYPE_N(index));
	type = airoha_fe_rr(eth, L2BR_ETYPE_N(index));
	
	type &= ~(0xffff << (16*(index%2)));
	type |= value << (16*(index%2));
	//write_reg_word(L2BR_ETYPE_N(index), type);
	airoha_fe_wr(eth, L2BR_ETYPE_N(index), type);
	
	return 0;
}


int fe_api_set_clear_mib(struct ecnt_fe_data *fe_data)
{
	struct airoha_eth *eth = glb_eth;
	unsigned long int base_addr, val, offset;
	FE_Gdma_Sel_t gdm_sel = fe_data->gdm_sel;
	FE_TXRX_Sel_t txrx_sel = fe_data->txrx_sel;
	
	if(gdm_sel == FE_GDM_SEL_GDMA1){
		base_addr = GDMA1_MIB_CLER;
	}else{
		base_addr = GDMA2_MIB_CLER;
	}
	offset = txrx_sel;
	
	//val = read_reg_word(base_addr);
	val = airoha_fe_rr(eth, base_addr);
	
	val |= (1<<offset);
	
	//write_reg_word(base_addr, val);
	airoha_fe_wr(eth, base_addr, val);
	
	return 0;
}



static int fe_set_tx_favor_oam_enable(unchar enable)
{
	struct airoha_eth *eth = glb_eth;
	unsigned int val;
	
	if((0 != enable)&&(1 != enable))
		return -1;
		
	if(!isEN7526c && !isEN751627)
		return -1;

	//val = read_reg_word(GDMA2_FWD_CFG);
	val = airoha_fe_rr(eth, GDMA2_FWD_CFG);

	val &= ~(1 << GDMA2_TX_FAVOR_OAM_OFFSET);
	val |= enable<<GDMA2_TX_FAVOR_OAM_OFFSET;

	//write_reg_word(GDMA2_FWD_CFG,val);
	airoha_fe_wr(eth, GDMA2_FWD_CFG, val);

	return 0;
}

int fe_api_set_tx_favor_oam_enable(struct ecnt_fe_data *fe_data)
{
	unchar enable = fe_data->api_data.enable;
	fe_data->retValue = fe_set_tx_favor_oam_enable(enable);	
	return 0;
}



int fe_api_set_gdma_misc_config(struct ecnt_fe_data *fe_data)
{
	struct airoha_eth *eth = glb_eth;
	FE_Gdma_Sel_t gdm_sel = fe_data->gdm_sel;
	uint mode = fe_data->api_data.fe_misc_cfg;

    //if(isEN7523){ need to revisit again and modify 
	if(1){
		if (FE_GDM_SEL_GDMA2 == gdm_sel){
			if(FE_MISC_CONFIG_GPON == mode){
				//IO_SBITS(GDMA_MISC_CFG,GDMA2_RLS_MODE_BIT);
				airoha_fe_set(eth, GDMA_MISC_CFG, GDMA2_RLS_MODE_BIT);	
			}else{
				//IO_CBITS(GDMA_MISC_CFG,GDMA2_RLS_MODE_BIT);
				airoha_fe_clear(eth, GDMA_MISC_CFG, GDMA2_RLS_MODE_BIT);	
			}
		}
	}
	else{
		return 0;
	}
	
	return 0;
}

int fe_api_set_pkt_length(struct ecnt_fe_data *fe_data)
{
	struct airoha_eth *eth = glb_eth;
	unsigned long int base_addr, val;
	FE_Gdma_Sel_t gdm_sel = fe_data->gdm_sel;
	uint length_long = fe_data->api_data.pkt_len.length_long;
	uint length_short = fe_data->api_data.pkt_len.length_short;

	if(gdm_sel == FE_GDM_SEL_GDMA1){
		base_addr = GDMA1_LEN_CFG;
	}else if(gdm_sel == FE_GDM_SEL_GDMA2){
	    base_addr = GDMA2_LEN_CFG;
    }else if(gdm_sel == FE_GDM_SEL_GDMA3){
		base_addr = GDMA3_LEN_CFG;
	}else if(gdm_sel == FE_GDM_SEL_GDMA4){
		base_addr = GDMA4_LEN_CFG;
	}else{
		printk("input gdm_sel error gdm_sel=%d\n",gdm_sel);
		return 0;
	}
	
	//val = read_reg_word(base_addr);
	val = airoha_fe_rr(eth, base_addr);
	
	if(length_long != 0)
		val &= ~(0xffff<<16);
	if(length_short != 0)
		val &= ~(0xffff);
	
	val |= ((length_long << 16) | length_short);
	//write_reg_word(base_addr, val);
	airoha_fe_wr(eth, base_addr, val);

	return 0;
}



int fe_api_get_rx_drop_fifo_cnt(struct ecnt_fe_data *fe_data)
{
	struct airoha_eth *eth = glb_eth;
	unsigned long int base_addr;
	FE_Gdma_Sel_t gdm_sel = fe_data->gdm_sel;
	
	if(gdm_sel == FE_GDM_SEL_GDMA1){
		base_addr = GDMA1_RX_OVER_DROP_CNT;
	}else{
		base_addr = GDMA2_RX_OVDROPCNT;
	}

	//fe_data->cnt = read_reg_word(base_addr);
	fe_data->cnt = airoha_fe_rr(eth, base_addr);
	
	return 0;
}

int fe_api_get_eth_rx_cnt(struct ecnt_fe_data *fe_data)
{
	struct airoha_eth *eth = glb_eth;
	if (GDM2_RX_ETH_MIB_SUPPORT)
	{
		unsigned long long gdm2_rx_high = 0;
		gdm2_rx_high = airoha_fe_rr(eth, GDMA2_RX_OKCNT_H);
		fe_data->api_data.FE_RxCnt.rxOKPktCnt = ((gdm2_rx_high << 32) + airoha_fe_rr(eth, GDMA2_RX_OKCNT));
		fe_data->api_data.FE_RxCnt.rxFCDropCnt = airoha_fe_rr(eth, GDMA2_RX_FCDROPCNT);
		fe_data->api_data.FE_RxCnt.rxRCDropCnt = airoha_fe_rr(eth, GDMA2_RX_RCDROPCNT);
		fe_data->api_data.FE_RxCnt.rxOVDropCnt = airoha_fe_rr(eth, GDMA2_RX_OVDROPCNT);
		fe_data->api_data.FE_RxCnt.rxERRDropCnt= airoha_fe_rr(eth, GDMA2_RX_ERRDROPCNT);

		gdm2_rx_high = airoha_fe_rr(eth, GDMA2_RX_OKBYTECNT_H);
		fe_data->api_data.FE_RxCnt.rxOKByteCnt = ((gdm2_rx_high << 32) + airoha_fe_rr(eth, GDMA2_RX_OKBYTECNT));
		fe_data->api_data.FE_RxCnt.rxOversizeCnt = airoha_fe_rr(eth, GDMA2_RX_ETHLONGCNT);
		fe_data->api_data.FE_RxCnt.rxUnderSizeCnt = airoha_fe_rr(eth, GDMA2_RX_ETHRUNTCNT);

		gdm2_rx_high = airoha_fe_rr(eth, GDMA2_RX_ETHERPCNT_H);
		fe_data->api_data.FE_RxCnt.rxFrameCnt = ((gdm2_rx_high << 32) + airoha_fe_rr(eth, GDMA2_RX_ETHERPCNT));

		gdm2_rx_high = airoha_fe_rr(eth, GDMA2_RX_ETHERPLEN_H);
		fe_data->api_data.FE_RxCnt.rxFrameLen = ((gdm2_rx_high << 32) + airoha_fe_rr(eth, GDMA2_RX_ETHERPLEN));
		fe_data->api_data.FE_RxCnt.rxDropCnt = (gdm2_rx_drop_high << 32) + airoha_fe_rr(eth, GDMA2_RX_ETHDROPCNT);
		fe_data->api_data.FE_RxCnt.rxBroadcastCnt = airoha_fe_rr(eth, GDMA2_RX_ETHBCCNT);
		fe_data->api_data.FE_RxCnt.rxMulticastCnt = airoha_fe_rr(eth, GDMA2_RX_ETHMCCNT);
		fe_data->api_data.FE_RxCnt.rxCrcCnt = airoha_fe_rr(eth, GDMA2_RX_ETHCRCCNT);
		fe_data->api_data.FE_RxCnt.rxFragFameCnt = airoha_fe_rr(eth, GDMA2_RX_ETHFRACCNT);
		fe_data->api_data.FE_RxCnt.rxJabberFameCnt = airoha_fe_rr(eth, GDMA2_RX_ETHJABCNT);
		fe_data->api_data.FE_RxCnt.rxLess64Cnt = airoha_fe_rr(eth, GDMA2_RX_ETHRUNTCNT);
		fe_data->api_data.FE_RxCnt.rxMore1518Cnt = airoha_fe_rr(eth, GDMA2_RX_ETHLONGCNT);

		gdm2_rx_high = airoha_fe_rr(eth, GDMA2_RX_ETH_64_CNT_H);
		fe_data->api_data.FE_RxCnt.rxEq64Cnt = ((gdm2_rx_high << 32) + airoha_fe_rr(eth, GDMA2_RX_ETH_64_CNT));

		gdm2_rx_high = airoha_fe_rr(eth, GDMA2_RX_ETH_65_TO_127_CNT_H);
		fe_data->api_data.FE_RxCnt.rxFrom65To127Cnt = ((gdm2_rx_high << 32) + airoha_fe_rr(eth, GDMA2_RX_ETH_65_TO_127_CNT));

		gdm2_rx_high = airoha_fe_rr(eth, GDMA2_RX_ETH_128_TO_255_CNT_H);
		fe_data->api_data.FE_RxCnt.rxFrom128To255Cnt = ((gdm2_rx_high << 32) + airoha_fe_rr(eth, GDMA2_RX_ETH_128_TO_255_CNT));

		gdm2_rx_high = airoha_fe_rr(eth, GDMA2_RX_ETH_256_TO_511_CNT_H);
		fe_data->api_data.FE_RxCnt.rxFrom256To511Cnt = ((gdm2_rx_high << 32) + airoha_fe_rr(eth, GDMA2_RX_ETH_256_TO_511_CNT));

		gdm2_rx_high = airoha_fe_rr(eth, GDMA2_RX_ETH_512_TO_1023_CNT_H);
		fe_data->api_data.FE_RxCnt.rxFrom512To1023Cnt = ((gdm2_rx_high << 32) + airoha_fe_rr(eth, GDMA2_RX_ETH_512_TO_1023_CNT));

		gdm2_rx_high = airoha_fe_rr(eth, GDMA2_RX_ETH_1024_TO_1518_CNT_H);
		fe_data->api_data.FE_RxCnt.rxFrom1024To1518Cnt = ((gdm2_rx_high << 32) + airoha_fe_rr(eth, GDMA2_RX_ETH_1024_TO_1518_CNT));
	}
	else
	{
		fe_data->api_data.FE_RxCnt.rxOKPktCnt = airoha_fe_rr(eth, GDMA2_RX_OKCNT);
		fe_data->api_data.FE_RxCnt.rxFCDropCnt = airoha_fe_rr(eth, GDMA2_RX_FCDROPCNT);
		fe_data->api_data.FE_RxCnt.rxRCDropCnt = airoha_fe_rr(eth, GDMA2_RX_RCDROPCNT);
		fe_data->api_data.FE_RxCnt.rxOVDropCnt = airoha_fe_rr(eth, GDMA2_RX_OVDROPCNT);
		fe_data->api_data.FE_RxCnt.rxERRDropCnt= airoha_fe_rr(eth, GDMA2_RX_ERRDROPCNT);
		fe_data->api_data.FE_RxCnt.rxOKByteCnt = airoha_fe_rr(eth, GDMA2_RX_OKBYTECNT);
		fe_data->api_data.FE_RxCnt.rxOversizeCnt = airoha_fe_rr(eth, GDMA2_RX_ETHLONGCNT);
		fe_data->api_data.FE_RxCnt.rxUnderSizeCnt = airoha_fe_rr(eth, GDMA2_RX_ETHRUNTCNT);
		fe_data->api_data.FE_RxCnt.rxFrameCnt = airoha_fe_rr(eth, GDMA2_RX_ETHERPCNT);
		fe_data->api_data.FE_RxCnt.rxFrameLen = (gdm2_rx_len_high<<32) + airoha_fe_rr(eth, GDMA2_RX_ETHERPLEN);
		fe_data->api_data.FE_RxCnt.rxDropCnt = airoha_fe_rr(eth, GDMA2_RX_ETHDROPCNT);
		fe_data->api_data.FE_RxCnt.rxBroadcastCnt = airoha_fe_rr(eth, GDMA2_RX_ETHBCCNT);
		fe_data->api_data.FE_RxCnt.rxMulticastCnt = airoha_fe_rr(eth, GDMA2_RX_ETHMCCNT);
		fe_data->api_data.FE_RxCnt.rxCrcCnt = airoha_fe_rr(eth, GDMA2_RX_ETHCRCCNT);
		fe_data->api_data.FE_RxCnt.rxFragFameCnt = airoha_fe_rr(eth, GDMA2_RX_ETHFRACCNT);
		fe_data->api_data.FE_RxCnt.rxJabberFameCnt = airoha_fe_rr(eth, GDMA2_RX_ETHJABCNT);
		fe_data->api_data.FE_RxCnt.rxLess64Cnt = airoha_fe_rr(eth, GDMA2_RX_ETHRUNTCNT);
		fe_data->api_data.FE_RxCnt.rxMore1518Cnt = airoha_fe_rr(eth, GDMA2_RX_ETHLONGCNT);
		fe_data->api_data.FE_RxCnt.rxEq64Cnt = airoha_fe_rr(eth, GDMA2_RX_ETH_64_CNT);
		fe_data->api_data.FE_RxCnt.rxFrom65To127Cnt = airoha_fe_rr(eth, GDMA2_RX_ETH_65_TO_127_CNT);
		fe_data->api_data.FE_RxCnt.rxFrom128To255Cnt = airoha_fe_rr(eth, GDMA2_RX_ETH_128_TO_255_CNT);
		fe_data->api_data.FE_RxCnt.rxFrom256To511Cnt = airoha_fe_rr(eth, GDMA2_RX_ETH_256_TO_511_CNT);
		fe_data->api_data.FE_RxCnt.rxFrom512To1023Cnt = airoha_fe_rr(eth, GDMA2_RX_ETH_512_TO_1023_CNT);
		fe_data->api_data.FE_RxCnt.rxFrom1024To1518Cnt = airoha_fe_rr(eth, GDMA2_RX_ETH_1024_TO_1518_CNT);
	}

	return 0;
}


int fe_api_get_eth_tx_cnt(struct ecnt_fe_data *fe_data)
{
	struct airoha_eth *eth = glb_eth;
	if (GDM2_TX_ETH_MIB_SUPPORT)
	{
		unsigned long long gdm2_tx_high = 0;
		gdm2_tx_high = airoha_fe_rr(eth, GDMA2_TX_ETHCNT_H);
		fe_data->api_data.FE_TxCnt.txFrameCnt = ((gdm2_tx_high << 32) + airoha_fe_rr(eth, GDMA2_TX_ETHCNT));

		gdm2_tx_high = airoha_fe_rr(eth, GDMA2_TX_ETHLENCNT_H);
		fe_data->api_data.FE_TxCnt.txFrameLen = ((gdm2_tx_high << 32) + airoha_fe_rr(eth, GDMA2_TX_ETHLENCNT));
		fe_data->api_data.FE_TxCnt.txDropCnt =  (gdm2_tx_drop_high << 32) + airoha_fe_rr(eth, GDMA2_TX_ETHDROPCNT);
		fe_data->api_data.FE_TxCnt.txBroadcastCnt = airoha_fe_rr(eth, GDMA2_TX_ETHBCDCNT);
		fe_data->api_data.FE_TxCnt.txMulticastCnt = airoha_fe_rr(eth, GDMA2_TX_ETHMULTICASTCNT);
		fe_data->api_data.FE_TxCnt.txLess64Cnt = airoha_fe_rr(eth, GDMA2_TX_ETH_LESS64_CNT);
		fe_data->api_data.FE_TxCnt.txMore1518Cnt = airoha_fe_rr(eth, GDMA2_TX_ETH_MORE1518_CNT);

		gdm2_tx_high = airoha_fe_rr(eth, GDMA2_TX_ETH_64_CNT_H);
		fe_data->api_data.FE_TxCnt.txEq64Cnt = ((gdm2_tx_high << 32) + airoha_fe_rr(eth, GDMA2_TX_ETH_64_CNT));

		gdm2_tx_high = airoha_fe_rr(eth, GDMA2_TX_ETH_65_TO_127_CNT_H);
		fe_data->api_data.FE_TxCnt.txFrom65To127Cnt = ((gdm2_tx_high << 32) + airoha_fe_rr(eth, GDMA2_TX_ETH_65_TO_127_CNT));

		gdm2_tx_high = airoha_fe_rr(eth, GDMA2_TX_ETH_128_TO_255_CNT_H);
		fe_data->api_data.FE_TxCnt.txFrom128To255Cnt = ((gdm2_tx_high << 32) + airoha_fe_rr(eth, GDMA2_TX_ETH_128_TO_255_CNT));

		gdm2_tx_high = airoha_fe_rr(eth, GDMA2_TX_ETH_256_TO_511_CNT_H);
		fe_data->api_data.FE_TxCnt.txFrom256To511Cnt = ((gdm2_tx_high << 32) + airoha_fe_rr(eth, GDMA2_TX_ETH_256_TO_511_CNT));

		gdm2_tx_high = airoha_fe_rr(eth, GDMA2_TX_ETH_512_TO_1023_CNT_H);
		fe_data->api_data.FE_TxCnt.txFrom512To1023Cnt = ((gdm2_tx_high << 32) + airoha_fe_rr(eth, GDMA2_TX_ETH_512_TO_1023_CNT));

		gdm2_tx_high = airoha_fe_rr(eth, GDMA2_TX_ETH_1024_TO_1518_CNT_H);
		fe_data->api_data.FE_TxCnt.txFrom1024To1518Cnt = ((gdm2_tx_high << 32) + airoha_fe_rr(eth, GDMA2_TX_ETH_1024_TO_1518_CNT));
	}
	else
	{
		fe_data->api_data.FE_TxCnt.txFrameCnt = airoha_fe_rr(eth, GDMA2_TX_ETHCNT);
		fe_data->api_data.FE_TxCnt.txFrameLen = (gdm2_tx_len_high<<32) + airoha_fe_rr(eth, GDMA2_TX_ETHLENCNT);
		fe_data->api_data.FE_TxCnt.txDropCnt = airoha_fe_rr(eth, GDMA2_TX_ETHDROPCNT);
		fe_data->api_data.FE_TxCnt.txBroadcastCnt = airoha_fe_rr(eth, GDMA2_TX_ETHBCDCNT);
		fe_data->api_data.FE_TxCnt.txMulticastCnt = airoha_fe_rr(eth, GDMA2_TX_ETHMULTICASTCNT);
		fe_data->api_data.FE_TxCnt.txLess64Cnt = airoha_fe_rr(eth, GDMA2_TX_ETH_LESS64_CNT);
		fe_data->api_data.FE_TxCnt.txMore1518Cnt = airoha_fe_rr(eth, GDMA2_TX_ETH_MORE1518_CNT);
		fe_data->api_data.FE_TxCnt.txEq64Cnt = airoha_fe_rr(eth, GDMA2_TX_ETH_64_CNT);
		fe_data->api_data.FE_TxCnt.txFrom65To127Cnt = airoha_fe_rr(eth, GDMA2_TX_ETH_65_TO_127_CNT);
		fe_data->api_data.FE_TxCnt.txFrom128To255Cnt = airoha_fe_rr(eth, GDMA2_TX_ETH_128_TO_255_CNT);
		fe_data->api_data.FE_TxCnt.txFrom256To511Cnt = airoha_fe_rr(eth, GDMA2_TX_ETH_256_TO_511_CNT);
		fe_data->api_data.FE_TxCnt.txFrom512To1023Cnt = airoha_fe_rr(eth, GDMA2_TX_ETH_512_TO_1023_CNT);
		fe_data->api_data.FE_TxCnt.txFrom1024To1518Cnt = airoha_fe_rr(eth, GDMA2_TX_ETH_1024_TO_1518_CNT);
	}

	return 0;
}



#ifdef TCSUPPORT_CPU_EN7580

int mbi_hang_unlock_by_terminate(FE_Gdma_Sel_t idx)
{
	struct airoha_eth *eth = glb_eth;
    unsigned int reg=0, value=0, cnt=0, mbi_ok_flag=0;
    
    if (idx == FE_GDM_SEL_GDMA1) {
        reg = GDMA1_CHN_RLS;
    } else if(idx == FE_GDM_SEL_GDMA2) {
        reg = GDMA2_CHN_RLS;
    } else {
        return -1;
    }

    cnt = mbi_ok_flag = 0;
    do {
        if((airoha_fe_rr(eth, reg) & (1 << MBI_TX_BUSY_OFFSET)) == 0) {
            mbi_ok_flag = 1;
            break;
        }
    } while((cnt++)<=10);
    if(mbi_ok_flag == 0) {
        value = airoha_fe_rr(eth, reg);
        airoha_fe_wr(eth, reg, value | (1<<MBI_TX_TERMINATE_OFFSET) );
        cnt = 0;
        do {
            if((airoha_fe_rr(eth, reg) & (1 << MBI_TX_BUSY_OFFSET)) == 0)
                break;
        } while((cnt++)<=10);
        if(cnt>10) {
            printk("Error: MBI TX Hang issue Terminate Fail!\n");
            return -1;
        }
        airoha_fe_wr(eth, reg, value & (~(1<<MBI_TX_TERMINATE_OFFSET)) );
    }
    
    cnt = mbi_ok_flag = 0;
    do {
        if((airoha_fe_rr(eth, reg) & (1 << MBI_RX_BUSY_OFFSET)) == 0) {
            mbi_ok_flag = 1;
            break;
        }
    } while((cnt++)<=10);
    if(mbi_ok_flag == 0) {
        value = airoha_fe_rr(eth, reg);
        airoha_fe_wr(eth, reg, value | (1<<MBI_RX_TERMINATE_OFFSET) );
        cnt = 0;
        do {
            if((airoha_fe_rr(eth, reg) & (1 << MBI_RX_BUSY_OFFSET)) == 0)
                break;
        } while((cnt++)<=10);
        if(cnt>10) {
            printk("Error: MBI RX Hang issue Terminate Fail!\n");
            return -1;
        }
        airoha_fe_wr(eth, reg, value & (~(1<<MBI_RX_TERMINATE_OFFSET)) );
    }
    
    return 0;
}
#endif

static int fe_channel_drop(void)
{
	struct airoha_eth *eth = glb_eth;
	unsigned int txreg,rxreg,txchn,rxchn;
	unsigned int hwreg,hw;
	unsigned int gdma_lpbk_cfg_reg, gdma_fwd_cfg_reg ,qdma_glb_cfg_reg,gdm2_tx_cha_vld_reg;
	unsigned int gdma_lpbk_cfg,gdma_fwd_cfg,qdma_glb_cfg;
	//QDMA_TxBufCtrl_T oldtxbuff,newTxbuff;
	unsigned int reg, reg2;
	//int ret;
	unsigned int value = 0;
	#ifdef TCSUPPORT_CPU_EN7580
	FE_Gdma_Sel_t gdm_sel = FE_GDM_SEL_GDMA2;
	#endif
		
	gdma_lpbk_cfg_reg	= GDMA2_LPBP_CFG;
	gdma_fwd_cfg_reg	= GDMA2_FWD_CFG;
	qdma_glb_cfg_reg	= QDMA_GLB_CFG;
	gdm2_tx_cha_vld_reg = GDMA2_TX_CHN_VLD;
	
	txreg = GDMA2_TXCHN_EN;
	rxreg = GDMA2_RXCHN_EN; 
	hwreg = CDMA2_HWF_CHN_EN;	
	reg = GDMA2_CHN_RLS;
	reg2= GDMA2_TX_CHN_VLD;
	
	txchn = airoha_fe_rr(eth, txreg);
	rxchn = airoha_fe_rr(eth, rxreg);
	hw = airoha_fe_rr(eth, hwreg);	

	#ifdef TCSUPPORT_CPU_EN7580
	mbi_hang_unlock_by_terminate(gdm_sel);
	#endif
	
	/*************diable Cdm2/Gdm2 rx and enable Gdm2 tx*********/	  
	airoha_fe_wr(eth, txreg,0xffff);
	airoha_fe_wr(eth, rxreg,0);
	airoha_fe_wr(eth, hwreg,0);

	/****************set gdm2 loop back*****************/
	gdma_lpbk_cfg = airoha_fe_rr(eth, gdma_lpbk_cfg_reg);
	gdma_fwd_cfg = airoha_fe_rr(eth, gdma_fwd_cfg_reg);
	qdma_glb_cfg = airoha_fe_rr(eth, qdma_glb_cfg_reg);
	
	airoha_fe_wr(eth, gdma_lpbk_cfg_reg,0x4007d003);
#if defined(TCSUPPORT_CPU_EN7581) || defined(TCSUPPORT_CPU_EN7523)
	airoha_fe_wr(eth, gdma_fwd_cfg_reg,0x03f1ffff);
#else
    airoha_fe_wr(eth, gdma_fwd_cfg_reg,0x03f17777);
#endif
	airoha_fe_wr(eth, qdma_glb_cfg_reg,qdma_glb_cfg | 1<<17);
		
	
	while((airoha_fe_rr(eth, gdm2_tx_cha_vld_reg) != 0) && (value++<300)){
		mdelay(1);
	}
			
	airoha_fe_wr(eth,gdma_lpbk_cfg_reg,gdma_lpbk_cfg);
	airoha_fe_wr(eth,gdma_fwd_cfg_reg,gdma_fwd_cfg);	
	airoha_fe_wr(eth,qdma_glb_cfg_reg,qdma_glb_cfg);

	airoha_fe_wr(eth, txreg,txchn);
	airoha_fe_wr(eth,rxreg,rxchn);
	airoha_fe_wr(eth,hwreg,hw);
	
	return 0;

}


static int fe_channel_retire_one(FE_Gdma_Sel_t idx,uint chn)
{
	struct airoha_eth *eth = glb_eth;
#ifdef TCSUPPORT_CPU_EN7580
	unsigned int txreg=0, rxreg=0, txchn=0, rxchn=0;
	unsigned int reg3=0;
#endif
	unsigned int reg=0, reg2=0, value=0;
	unsigned int rlsCnt=0;
	int ret = 0;

#ifdef TCSUPPORT_CPU_EN7580
	if (idx == FE_GDM_SEL_GDMA1){
		txreg = GDMA1_TXCHN_EN;
		rxreg = GDMA1_RXCHN_EN;
		reg = GDMA1_CHN_RLS;
		reg2 = GDMA1_TX_CHN_VLD;
		reg3 = QDMA1_CHN_VLD_BASE;
	}else if(idx == FE_GDM_SEL_GDMA2){
		txreg = GDMA2_TXCHN_EN;
		rxreg = GDMA2_RXCHN_EN;
		reg = GDMA2_CHN_RLS;
		reg2 = GDMA2_TX_CHN_VLD;
		reg3 = QDMA2_CHN_VLD_BASE;
	}else if(idx == FE_GDM_SEL_GDMA3){
        txreg = GDMA3_TXCHN_EN;
        rxreg = GDMA3_RXCHN_EN;
        reg = GDMA3_CHN_RLS;
        reg2= GDMA3_RX_CHN_VLD;
		if(HWF_QDMA_SEL_SUPPORT&&FeGetHwfQdmaSelGdm3(eth))
			reg3 = QDMA2_CHN_VLD_BASE;
		else
			reg3 = QDMA1_CHN_VLD_BASE;
	}else if(idx == FE_GDM_SEL_GDMA4){
        txreg = GDMA4_TXCHN_EN;
        rxreg = GDMA4_RXCHN_EN;
        reg = GDMA4_CHN_RLS;
        reg2= GDMA4_RX_CHN_VLD;
		if(HWF_QDMA_SEL_SUPPORT&&FeGetHwfQdmaSelGdm4(eth))
			reg3 = QDMA2_CHN_VLD_BASE;
		else
			reg3 = QDMA1_CHN_VLD_BASE;
    }else{
		return -1;
	}
	reg3 += (chn>>2)<<2;
	txchn = airoha_fe_rr(eth,txreg);
	rxchn = airoha_fe_rr(eth,rxreg);
	airoha_fe_wr(eth, rxreg, 1<<chn);
	airoha_fe_wr(eth, txreg, 1<<chn);
        
	chn &= 0x1f;
	value = (chn << GDMA_CHN_RLS_CHN_OFFSET) | (1 << GDMA_CHN_RLS_EN_OFFSET);
	airoha_fe_wr(eth, reg, value);
	
retry:
	
	mdelay(1);
    
	rlsCnt++;

	if (rlsCnt < GDMA_CHN_RLS_TIMEOUT)
	{
		for(value = 0; value < 2; value++)
		{
			if ( ((airoha_fe_rr(eth,reg) & (1 << GDMA_CHN_RLS_STAT_OFFSET)) == 0)
				|| ((airoha_fe_rr(eth,reg2) & (1 << chn)) != 0)
				|| ((airoha_fe_rr(eth,reg3) & (0xFF<<((chn&0x3)<<3))) != 0) ) {
				goto retry;
			}
		}
	} else {
		ret = -1;
	}
    
	airoha_fe_wr(eth, reg, 0);
	airoha_fe_wr(eth, txreg, txchn);
	airoha_fe_wr(eth, rxreg, rxchn); 
#else
	if (idx == FE_GDM_SEL_GDMA1){
		reg = GDMA1_CHN_RLS;
		reg2 = GDMA1_TX_CHN_VLD;
	}else if(idx == FE_GDM_SEL_GDMA2){
		reg = GDMA2_CHN_RLS;
		reg2= GDMA2_TX_CHN_VLD;
	}else{
		return -1;
	}	

	chn &= 0x1f;
	
	value = (chn << GDMA_CHN_RLS_CHN_OFFSET) | (1 << GDMA_CHN_RLS_EN_OFFSET);
	
	airoha_fe_wr(eth,reg,value);
	
retry:
	
	mdelay(1);
	
	rlsCnt++;

	if (rlsCnt < GDMA_CHN_RLS_TIMEOUT)
	{
		for(value = 0; value < 10; value++)
		{
			if ( (airoha_fe_rr(eth,reg) & (1 << GDMA_CHN_RLS_STAT_OFFSET)) == 0
				||(airoha_fe_rr(eth,reg2) & (1 << chn)) != 0 ) {
				goto retry;
			}
		}
	}else{
		ret = -1;			
	}

	airoha_fe_wr(eth,reg,0);
#endif

	return ret;
}

#define FE_PROBE_H          (PSE_BASE + 0x34)
#define GDMA1_RX_CHN_VLD     (GDM1_BASE + 0x74)
#define GDMA2_RX_CHN_VLD     (GDM2_BASE + 0x74)

static int fe_channel_retire(struct ecnt_fe_data *fe_data)
{
#if !defined(TCSUPPORT_CPU_EN7580)
	unsigned int txreg=0, rxreg=0, txchn=0, rxchn=0;
	unsigned int hw=0;
	// QDMA_TxBufCtrl_T oldtxbuff,newTxbuff;
#else
	unsigned int qdmaChnlEn[8];
#endif
	struct airoha_eth *eth = glb_eth;
	
	unsigned int hwreg=0, i=0, j=0;
	unsigned int reg=0, reg2=0;
	int ret=0;

	FE_Gdma_Sel_t gdm_sel = fe_data->gdm_sel;
	uint channel = fe_data->channel;

#ifdef TCSUPPORT_CPU_EN7580
    if (gdm_sel == FE_GDM_SEL_GDMA1){
        hwreg = QDMA1_CHN_EN_BASE;
        reg = GDMA1_CHN_RLS;
        reg2 = GDMA1_RX_CHN_VLD;
    }else if(gdm_sel == FE_GDM_SEL_GDMA2){
        hwreg = QDMA2_CHN_EN_BASE;
        reg = GDMA2_CHN_RLS;
        reg2= GDMA2_RX_CHN_VLD;
	}else if(gdm_sel == FE_GDM_SEL_GDMA3){
		if(HWF_QDMA_SEL_SUPPORT&&FeGetHwfQdmaSelGdm3(eth))
			hwreg = QDMA2_CHN_EN_BASE;
		else
			hwreg = QDMA1_CHN_EN_BASE;
        reg = GDMA3_CHN_RLS;
        reg2= GDMA3_RX_CHN_VLD;
	}else if(gdm_sel == FE_GDM_SEL_GDMA4){
		if(HWF_QDMA_SEL_SUPPORT&&FeGetHwfQdmaSelGdm4(eth))
			hwreg = QDMA2_CHN_EN_BASE;
		else
			hwreg = QDMA1_CHN_EN_BASE;
        reg = GDMA4_CHN_RLS;
        reg2= GDMA4_RX_CHN_VLD;
    }else{
        return -1;
    }
    
    for(i=0; i<8; i++) {
        qdmaChnlEn[i] = airoha_fe_rr(eth,hwreg+(i<<2));
        airoha_fe_wr(eth, hwreg+(i<<2), 0);
    }
    
     
	mbi_hang_unlock_by_terminate(gdm_sel);

    mdelay(1);

    for(i=0; i<channel; i++) {
        ret = fe_channel_retire_one(gdm_sel,i);
        if(ret == -1) {
            printk("fe_channel_retire_one(%d/%d): timeout (%08x) ,(%08x) \n", i, gdm_sel, airoha_fe_rr(eth,reg), airoha_fe_rr(eth,reg2));
        }
    }
    
    for(j=0; j<10; j++) {
        if (airoha_fe_rr(eth,reg2) == 0) {
            break;
        }
    }
    if(j==10) {
        printk("rx channel vld is error: rx_chnl_vld:%08x\n", airoha_fe_rr(eth,reg2));
    }
    
    for(i=0; i<8; i++) {
        airoha_fe_wr(eth, hwreg+(i<<2), qdmaChnlEn[i]);
    }
#else
	if (gdm_sel == FE_GDM_SEL_GDMA1){
		txreg = GDMA1_TXCHN_EN;
		rxreg = GDMA1_RXCHN_EN;
		hwreg = CDMA1_HWF_CHN_EN;
		reg = GDMA1_CHN_RLS;
		reg2 = GDMA1_TX_CHN_VLD;
	}else if(gdm_sel == FE_GDM_SEL_GDMA2){
		txreg = GDMA2_TXCHN_EN;
		rxreg = GDMA2_RXCHN_EN;	
		hwreg = CDMA2_HWF_CHN_EN;	
		reg = GDMA2_CHN_RLS;
		reg2= GDMA2_TX_CHN_VLD;
	}else{
		return -1;
	}	

	txchn = airoha_fe_rr(eth,txreg);
	
	rxchn = airoha_fe_rr(eth,rxreg);
	
	hw = airoha_fe_rr(eth,hwreg);
	
	// QDMA_API_GET_TXBUF_THRESHOLD(&oldtxbuff);

	airoha_fe_wr(eth,hwreg,0);

	// newTxbuff.mode = QDMA_ENABLE;
	// newTxbuff.chnThreshold = 1;
	// newTxbuff.totalThreshold = 0x40;
	// QDMA_API_SET_TXBUF_THRESHOLD(&newTxbuff);

	airoha_fe_wr(eth,rxreg,0);
	
	airoha_fe_wr(eth,txreg,0);
	
	mdelay(1);

	j = 0;
	while(j < 2)
	{
		for(i = 0; i < channel; i++)
		{
			ret = fe_channel_retire_one(gdm_sel,i);
			if(ret == -1 && j == 1) {
				printk("fe_channel_retire_one(%d/%d): timeout (%08x) ,(%08x) ,(%08x) \n",i,gdm_sel,airoha_fe_rr(eth,reg),airoha_fe_rr(eth,reg2),airoha_fe_rr(eth,FE_PROBE_H));
			}
		}
		j++;
	}
	
	airoha_fe_wr(eth,txreg,txchn);
	
	airoha_fe_wr(eth,rxreg,rxchn);
	
	// QDMA_API_SET_TXBUF_THRESHOLD(&oldtxbuff);

	airoha_fe_wr(eth,hwreg,hw);
#endif

	return 0;
}


/*
    used when wan link is down,and called by Wan MAC Driver. 
    if channel_retire is 1, this function will retire each channel twice by two loops. First loop retire the  channels queued in PSE buffer,
    these channels will be retired done at first loop. Second loop will given the chance to those channels not queued in PSE buffer but
    queued in QDMA TX queue. All Channels will be retired done at second loop;
    esle, this function will do channel drop. the packet queued in qdma will be sent to gdma2, and set the force port as drop.
    the default set channel_retire is 0, and this function will call channel drop
*/
int fe_api_set_channel_retire_all(struct ecnt_fe_data *fe_data)
{
    if (isEN751221 && fe_api_pse_iq_abnormal())
    {
        printk("Info: fe_api_set_channel_retire_all ingored due to PSE IQ resource abnormal\n");
        return 0;
    }

	atomic_set(&qdma_stop_flag, 1);
	if(channel_retire != CHANNEL_RETIRE)
		fe_channel_drop();
	else 
		fe_channel_retire(fe_data);
	atomic_set(&qdma_stop_flag, 0);

	return 0;
}



int fe_api_set_channel_retire_one(struct ecnt_fe_data *fe_data)
{
#if !defined(TCSUPPORT_CPU_EN7580)
	unsigned int hw=0;
	// QDMA_TxBufCtrl_T oldtxbuff,newTxbuff;
#endif
	struct airoha_eth *eth = glb_eth;
    unsigned int hwreg=0;
	FE_Gdma_Sel_t gdm_sel = fe_data->gdm_sel;
	uint channel = fe_data->channel;

    if (isEN751221 && fe_api_pse_iq_abnormal())
    {
        printk("Info: fe_api_set_channel_retire_one ingored due to PSE IQ resource abnormal\n");
        return 0;
    }

#ifdef TCSUPPORT_CPU_EN7580
    if (gdm_sel == FE_GDM_SEL_GDMA1){
        hwreg = QDMA1_CHN_EN_BASE;
    }else if(gdm_sel == FE_GDM_SEL_GDMA2){
        hwreg = QDMA2_CHN_EN_BASE;		
	}else if(gdm_sel == FE_GDM_SEL_GDMA3){
		if(HWF_QDMA_SEL_SUPPORT&&FeGetHwfQdmaSelGdm3(eth))
			hwreg = QDMA2_CHN_EN_BASE;
		else
			hwreg = QDMA1_CHN_EN_BASE;
	}else if(gdm_sel == FE_GDM_SEL_GDMA4){
		if(HWF_QDMA_SEL_SUPPORT&&FeGetHwfQdmaSelGdm4(eth))
			hwreg = QDMA2_CHN_EN_BASE;
		else
			hwreg = QDMA1_CHN_EN_BASE;
    }else{
        return -1;
    }

    mbi_hang_unlock_by_terminate(gdm_sel);
#if 0	
    // disable qdma queue enable for single channel
    hwreg += (channel>>2)<<2;
	hw = airoha_fe_rr(eth,hwreg);
	airoha_fe_wr(eth, hwreg, hw & (~(0xFF<<((channel&0x3)<<3))) );
    
    mdelay(1);
#endif    
    fe_channel_retire_one(gdm_sel, channel);
#if 0    
    airoha_fe_wr(eth, hwreg, hw);
#endif
#else
	if (gdm_sel == FE_GDM_SEL_GDMA1){
		hwreg = CDMA1_HWF_CHN_EN;
	}else if(gdm_sel == FE_GDM_SEL_GDMA2){
		hwreg = CDMA2_HWF_CHN_EN;		
	}else{
		return -1;
	}
	
	hw = airoha_fe_rr(eth,hwreg);
	
	// QDMA_API_GET_TXBUF_THRESHOLD(&oldtxbuff);	
	airoha_fe_wr(eth, hwreg,hw & (~(1<<channel)) );
	
	// newTxbuff.mode = QDMA_ENABLE;
	// newTxbuff.chnThreshold = 1;
	// newTxbuff.totalThreshold = 0x40;
	// QDMA_API_SET_TXBUF_THRESHOLD(&newTxbuff);

	mdelay(1);	

	fe_channel_retire_one(gdm_sel,channel);
	
	// QDMA_API_SET_TXBUF_THRESHOLD(&oldtxbuff);

	airoha_fe_wr(eth, hwreg,hw);
#endif

	return 0;
}


static inline unsigned int pse_get_oq_rsv(unsigned int port, unsigned int queue)
{
	struct airoha_eth *eth = glb_eth;
	unsigned int tmp_val; 

	//IO_SREG(PSE_QUEUE_CFG_WR, (port<<PSE_CFG_PORT_ID_SHIFT)|(queue<<PSE_CFG_QUEUE_ID_SHIFT));
	
	airoha_fe_wr(eth, PSE_QUEUE_CFG_WR, (port<<PSE_CFG_PORT_ID_SHIFT)|(queue<<PSE_CFG_QUEUE_ID_SHIFT));
	
	//tmp_val = IO_GMASK(PSE_QUEUE_CFG_VAL, PSE_CFG_OQ_RSV_MASK, PSE_CFG_OQ_RSV_SHIFT);
	
	tmp_val = ((airoha_fe_rr(eth, PSE_QUEUE_CFG_VAL) & PSE_CFG_OQ_RSV_MASK) >> PSE_CFG_OQ_RSV_SHIFT);
	

	return tmp_val;
}

	
static inline unsigned int pse_set_oq_rsv(unsigned int port, unsigned int queue, unsigned int val)
{
	struct airoha_eth *eth = glb_eth;
	//IO_SMASK(PSE_QUEUE_CFG_VAL, PSE_CFG_OQ_RSV_MASK, PSE_CFG_OQ_RSV_SHIFT, val);
	airoha_fe_rmw(eth, PSE_QUEUE_CFG_VAL, PSE_CFG_OQ_RSV_MASK, (val << PSE_CFG_OQ_RSV_SHIFT));
	
	//IO_SREG(PSE_QUEUE_CFG_WR, (port<<PSE_CFG_PORT_ID_SHIFT)|(queue<<PSE_CFG_QUEUE_ID_SHIFT)|PSE_CFG_WR_EN|PSE_CFG_OQRSV_SEL);
	airoha_fe_wr(eth, PSE_QUEUE_CFG_WR, (port<<PSE_CFG_PORT_ID_SHIFT)|(queue<<PSE_CFG_QUEUE_ID_SHIFT)|PSE_CFG_WR_EN|PSE_CFG_OQRSV_SEL);

	return 0;
}


static void fe_set_per_oq_rsv(uint port,uint oq,uint val)
{
#if defined(TCSUPPORT_CPU_EN7581)
	struct airoha_eth *eth = glb_eth;
    uint ori_rsv = pse_get_oq_rsv(port,oq);
    uint tmp = 0;
    uint pse_port_oq_num[PSE_PORT_NUM] = {PSE_PORT0_QUEUE_NUM,PSE_PORT1_QUEUE_NUM,\
        PSE_PORT2_QUEUE_NUM,PSE_PORT3_QUEUE_NUM,PSE_PORT4_QUEUE_NUM,PSE_PORT5_QUEUE_NUM,\
        PSE_PORT6_QUEUE_NUM,PSE_PORT7_QUEUE_NUM,PSE_PORT8_QUEUE_NUM,PSE_PORT9_QUEUE_NUM,\
        PSE_PORT10_QUEUE_NUM};

    if(port >= PSE_PORT_NUM)
        return;

    if(oq >= pse_port_oq_num[port])
        return;
    
    pse_set_oq_rsv(port,oq,val);

    /*modify all rsv*/
    tmp = GET_PSE_ALL_RSV(eth)-ori_rsv+val;
    SET_PSE_ALL_RSV(eth,tmp);

#if defined(TCSUPPORT_CPU_AN7583)
	/*modify hthd*/
    tmp = GET_PSE_FQ_LITMI(eth)-GET_PSE_ALL_RSV(eth)-0x100;
    SET_PSE_SHARED_USED_HTHD(eth,tmp);

    /*modify mthd&lthd,mthd = hthd - 0x100,lthd = mthd*0.75*/
    tmp = tmp-0x100;
    SET_PSE_SHARED_USED_MTHD(eth,tmp);
    tmp = tmp*3/4;
    SET_PSE_SHARED_USED_LTHD(eth,tmp);

#else
    /*modify hthd*/
    tmp = GET_PSE_FQ_LITMI(eth)-GET_PSE_ALL_RSV(eth)-0x20;
    SET_PSE_SHARED_USED_HTHD(eth,tmp);

    /*modify mthd&lthd,mthd = all_share - 0x20,lthd = mthd*0.75*/
    tmp = GET_PSE_FQ_LITMI(eth)-GET_PSE_ALL_RSV(eth)-0x100;
    SET_PSE_SHARED_USED_MTHD(eth,tmp);
    tmp = tmp*3/4;
    SET_PSE_SHARED_USED_LTHD(eth,tmp);
#endif
#endif
    
    return;
}

int fe_api_pse_oq_rsv_en(struct ecnt_fe_data *fe_data)
{
	unsigned int port = fe_data->api_data.fe_oq_rsv_en.port;
    unsigned int channel = fe_data->api_data.fe_oq_rsv_en.channel;
    unsigned int enable = fe_data->api_data.fe_oq_rsv_en.enable;

    /*keep P2 oq0~oq5 rsv*/
    if((FE_DP_GDM2 == port)&&(channel >= 0)&&(channel <= 5))
            return 0;
    
    if(enable)
        fe_set_per_oq_rsv(port,channel,PSE_RSV_PAGE_DEFAULT);
    else
        fe_set_per_oq_rsv(port,channel,0); 
    return 0;
}


// Function definitions
int fe_api_set_mac_addr(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_crc_strip(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_padding(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_ext_tpid(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_ext_tpid(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_fw_cfg(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_fw_cfg(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_drop_udp_chksum_err_enable(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_drop_tcp_chksum_err_enable(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_drop_ip_chksum_err_enable(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_drop_crc_err_enable(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_drop_runt_enable(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_drop_long_enable(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_vlan_check(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_ok_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_rx_err_crc_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_rx_drop_err_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_ok_byte_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_tx_get_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_tx_drop_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_time_stamp(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_time_stamp(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_ins_vlan_tpid(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_vlan_enable(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_black_list(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_L2U_key(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_ac_group_pkt_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_ac_group_byte_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_clear_ac_group_pkt_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_clear_ac_group_byte_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_meter_group(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_meter_group(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_gdm_pcp_coding(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_cdm_pcp_coding(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_vip_enable(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_eth_frame_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_eth_err_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_cdm_rx_red_drop_mode(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_cdm_rx_red_drop_mode(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_tx_rate(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_rxuc_rate(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_rxbc_rate(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_rxmc_rate(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_rxoc_rate(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_add_vip_ether(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_add_vip_ppp(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_add_vip_ip(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_add_vip_tcp(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_add_vip_udp(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_del_vip_ether(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_del_vip_ppp(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_del_vip_ip(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_del_vip_tcp(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_del_vip_udp(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_add_l2lu_vlan_dscp(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_add_l2lu_vlan_trfc(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_del_l2lu_vlan_dscp(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_del_l2lu_vlan_trfc(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_add_traffic_class(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_del_traffic_class(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_tls_cfg(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_tls_forwad(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_do_fe_reset(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_mac_addr_7516(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_wan_port_7516(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_loopback_enable(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_loopback_mode(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_unknown_mul_pkt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_meter_ratelimit(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_meter_ratelimit(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_meter_idx(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_acnt1_idx(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_acnt0_idx(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_init_resource_manage(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_deinit_resource_manage(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_rx_ratelimit_rule(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_rx_ratelimit_mode(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_meter_ctl_by_olt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_flow_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_clear_flow_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_acnt0_mode(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_acnt1_mode(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_acnt0_mode(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_acnt1_mode(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_meter_enable(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_dev_mac_index(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_pse_oq_threshold(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_acnt2_idx(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_acnt2_mode(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_wan_itf_index(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_glo_rate_byte(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_pppoe_info(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_pppoe_info_clean(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_tx_traffic(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_rx_traffic(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_tx_rate(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_rx_rate(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_tx_octets(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_rx_octets(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_rx_discard_counter(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_tx_discard_counter(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_rx_error_counter(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_tx_error_counter(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_add_dev_to_total_account(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_add_stb_src_ip(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_del_stb_src_ip(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_ratelimit_for_pkt_formate(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_mc_vlan_global(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_mc_vlan_global(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_mc_vlan_table_cfg(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_mc_vlan_table_cfg(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_mc_vlan_action_cfg(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_mc_vlan_action_cfg(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_mc_vlan_clear_all(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_rx_mac_filter(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_rx_mac_filter_rate(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_xfi_link_change(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_rx_ratelimit_mode(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_hsgmii_rx_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_hsgmii_tx_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_aewan_fwdfq(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_aewan_ifcdisable(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_gdm2_sptag_for_loopback(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_rx_rate(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_tunnel_cfg(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_gdm_sptag_for_extswitch(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_hsgmii_rx_port_ratelimit(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_mbi_arb_rst(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_rmbi_frag(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_chn_rls(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_tmbi_frag(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_gdma_enable(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_gdma_disable(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_get_pse_drop_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_qbi_fttr_chn_disable(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_force_slow_enable(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_force_slow_duty(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_vip_rxq_selection(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_vip_for_tcp_speedtest(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_check_chn_rls(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_dev_stat_ratelimit_mode(struct ecnt_fe_data *fe_data) {
    return 0;
}

int fe_api_set_clr_cnt(struct ecnt_fe_data *fe_data) {
    return 0;
}

#if 0
ecnt_ret_val ecnt_fe_api_hook(struct ecnt_data *in_data)
{
	struct ecnt_fe_data *fe_data = (struct ecnt_fe_data *)in_data ;
	/* ulong flags = 0 ; */
	
	if(fe_data->function_id >= FE_FUNCTION_MAX_NUM) {
		printk("fe_data->function_id is %d, exceed max number: %d", fe_data->function_id, FE_FUNCTION_MAX_NUM);
		return ECNT_HOOK_ERROR;
	}

	/* spin_lock_irqsave(&hookFuncLock[fe_data->function_id], flags) ; */
	fe_data->retValue = fe_operation[fe_data->function_id](fe_data) ;
	/* spin_unlock_irqrestore(&hookFuncLock[fe_data->function_id], flags) ; */
	
	return ECNT_CONTINUE;
}
#endif

void airoha_fe_core_reset(struct airoha_eth *eth)
{
	airoha_fe_rmw(eth, FE_RESET_GLO, REG_FE_CORE_RESET, 
				FIELD_PREP(REG_FE_CORE_RESET, 1));
	return;
}

#define PPE_TB_CFG_KA_AGE_MASK	\
	(PPE_TB_CFG_KEEPALIVE_MASK |	\
	 PPE_TB_CFG_AGE_TCP_FIN_MASK |	\
	 PPE_TB_CFG_AGE_UDP_MASK |	\
	 PPE_TB_CFG_AGE_TCP_MASK |	\
	 PPE_TB_CFG_AGE_UNBIND_MASK |	\
	 PPE_TB_CFG_AGE_NON_L4_MASK |	\
	 PPE_TB_CFG_AGE_PREBIND_MASK)
static const int fe_core_reset_gdm_ids[] = { 1, 2, 3, 4 };
void airoha_fe_do_core_reset(struct airoha_eth *eth)
{
	u32 gdm_txchn[ARRAY_SIZE(fe_core_reset_gdm_ids)];
	u32 gdm_rxchn[ARRAY_SIZE(fe_core_reset_gdm_ids)];
	u32 ppe_tb_cfg[AIROHA_MAX_NUM_PPE];
	u32 qdma_glo_cfg[AIROHA_MAX_NUM_QDMA];
	u32 tdma_glo_cfg;
	u32 pse_iq_s1 = 0, pse_iq_s2 = 0;
	unsigned long flags;
	int i, check_times;
	int num_ppe;
	if (!eth || !eth->fe_regs || !eth->soc)
		return;
	atomic_inc(&fe_core_reset_count);
	num_ppe = eth->soc->num_ppe;
	if (num_ppe > AIROHA_MAX_NUM_PPE)
		num_ppe = AIROHA_MAX_NUM_PPE;
	spin_lock_irqsave(&fe_pse_reset_lock, flags);
	atomic_set(&qdma_stop_flag, 1);
	for (i = 0; i < AIROHA_MAX_NUM_QDMA; i++) {
		qdma_glo_cfg[i] = airoha_qdma_rr(&eth->qdma[i], REG_QDMA_GLOBAL_CFG);
		airoha_qdma_clear(&eth->qdma[i], REG_QDMA_GLOBAL_CFG,
				  GLOBAL_CFG_TX_DMA_EN_MASK);
	}
	tdma_glo_cfg = airoha_fe_rr(eth, REG_TDMA_GLO_CFG);
	airoha_fe_clear(eth, REG_TDMA_GLO_CFG, TDMA_GLO_CFG_TX_DMA_EN_MASK);
	for (i = 0; i < ARRAY_SIZE(fe_core_reset_gdm_ids); i++) {
		int gdm = fe_core_reset_gdm_ids[i];
		gdm_txchn[i] = airoha_fe_rr(eth, REG_GDM_TXCHN_EN(gdm));
		gdm_rxchn[i] = airoha_fe_rr(eth, REG_GDM_RXCHN_EN(gdm));
		airoha_fe_wr(eth, REG_GDM_TXCHN_EN(gdm), 0);
		airoha_fe_wr(eth, REG_GDM_RXCHN_EN(gdm), 0);
	}
	for (i = 0; i < num_ppe; i++) {
		ppe_tb_cfg[i] = airoha_fe_rr(eth, REG_PPE_TB_CFG(i));
		airoha_fe_clear(eth, REG_PPE_TB_CFG(i), PPE_TB_CFG_KA_AGE_MASK);
	}
	spin_unlock_irqrestore(&fe_pse_reset_lock, flags);
	for (check_times = 0; check_times < 5; check_times++) {
		mdelay(1);
		pse_iq_s1 = airoha_fe_rr(eth, PSE_IQ_STA1);
		pse_iq_s2 = airoha_fe_rr(eth, PSE_IQ_STA2);
		if (pse_iq_s1 == 0 && pse_iq_s2 == 0)
			break;
	}
	if (check_times >= 5)
		pr_warn("[airoha_eth] FE core reset while PSE IQ not empty (s1=0x%08x s2=0x%08x)\n",
			pse_iq_s1, pse_iq_s2);
	spin_lock_irqsave(&fe_pse_reset_lock, flags);
	for (i = 0; i < AIROHA_MAX_NUM_QDMA; i++)
		airoha_qdma_clear(&eth->qdma[i], REG_QDMA_GLOBAL_CFG,
				  GLOBAL_CFG_RX_DMA_EN_MASK);
	airoha_fe_clear(eth, REG_TDMA_GLO_CFG, TDMA_GLO_CFG_RX_DMA_EN_MASK);
	spin_unlock_irqrestore(&fe_pse_reset_lock, flags);
	mdelay(1);
	airoha_fe_set(eth, REG_FE_RST_GLO_CFG, FE_RST_CORE_MASK);
	mdelay(1);
	spin_lock_irqsave(&fe_pse_reset_lock, flags);
	for (i = 0; i < AIROHA_MAX_NUM_QDMA; i++)
		airoha_qdma_rmw(&eth->qdma[i], REG_QDMA_GLOBAL_CFG,
				GLOBAL_CFG_TX_DMA_EN_MASK | GLOBAL_CFG_RX_DMA_EN_MASK,
				qdma_glo_cfg[i] & (GLOBAL_CFG_TX_DMA_EN_MASK |
						   GLOBAL_CFG_RX_DMA_EN_MASK));
	airoha_fe_rmw(eth, REG_TDMA_GLO_CFG,
		      TDMA_GLO_CFG_TX_DMA_EN_MASK | TDMA_GLO_CFG_RX_DMA_EN_MASK,
		      tdma_glo_cfg & (TDMA_GLO_CFG_TX_DMA_EN_MASK |
				      TDMA_GLO_CFG_RX_DMA_EN_MASK));
	for (i = 0; i < ARRAY_SIZE(fe_core_reset_gdm_ids); i++) {
		int gdm = fe_core_reset_gdm_ids[i];
		airoha_fe_wr(eth, REG_GDM_TXCHN_EN(gdm), gdm_txchn[i]);
		airoha_fe_wr(eth, REG_GDM_RXCHN_EN(gdm), gdm_rxchn[i]);
	}
	for (i = 0; i < num_ppe; i++)
		airoha_fe_rmw(eth, REG_PPE_TB_CFG(i), PPE_TB_CFG_KA_AGE_MASK,
			      ppe_tb_cfg[i] & PPE_TB_CFG_KA_AGE_MASK);
	atomic_set(&qdma_stop_flag, 0);
	spin_unlock_irqrestore(&fe_pse_reset_lock, flags);
	pr_info("[airoha_eth] FE core reset done\n");
}

void airoha_fe_pse_oq_set_fc_disable(struct airoha_eth *eth, u32 port, u32 queue)
{
#ifdef CONFIG_NET_AIROHA_FLOW_STATS
	airoha_fe_rmw(eth, REG_FE_PSE_QUEUE_CFG_VAL, 
			PSE_CFG_OQ_FC_ON,
			FIELD_PREP(PSE_CFG_OQ_FC_ON, 0));
	airoha_fe_rmw(eth, REG_FE_PSE_QUEUE_CFG_WR,
			PSE_CFG_PORT_ID_MASK | PSE_CFG_QUEUE_ID_MASK |
		    PSE_CFG_WR_EN_MASK | PSE_CFG_OQFCEN_SEL,
			FIELD_PREP(PSE_CFG_PORT_ID_MASK, port) |
			FIELD_PREP(PSE_CFG_QUEUE_ID_MASK, queue) |
			PSE_CFG_WR_EN_MASK | PSE_CFG_OQFCEN_SEL);
#endif

	return;
}

int airoha_fe_gdm_rls(struct airoha_gdm_port *port)
{
	int ret = 0;

	/*Only support gdm4 channel release for 7581 */
	if (port->id != 4)
		return -EINVAL;
	
	u32 val = 0;
	if(glb_eth->fe_regs){
		
		airoha_fe_rmw(glb_eth, REG_GDM4_CHN_RLS, REG_GDM4_TX_CHN_ID|REG_GDM4_TX_CHN_EN, 
					FIELD_PREP(REG_GDM4_TX_CHN_ID, 0)|FIELD_PREP(REG_GDM4_TX_CHN_EN, 1));
					
		ret = read_poll_timeout(airoha_fe_rr, val,
					val & REG_GDM4_TX_CHN_DN,
					USEC_PER_MSEC, 100 * USEC_PER_MSEC,
					false, glb_eth, REG_GDM4_CHN_RLS);	
					
		airoha_fe_rmw(glb_eth, REG_GDM4_CHN_RLS, REG_GDM4_TX_CHN_ID|REG_GDM4_TX_CHN_EN, 
					FIELD_PREP(REG_GDM4_TX_CHN_ID, 0)|FIELD_PREP(REG_GDM4_TX_CHN_EN, 0));			
	}
	return ret;
}


