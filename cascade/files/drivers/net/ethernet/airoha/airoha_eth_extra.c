// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025 AIROHA Inc
 */


#include "airoha_regs.h"
#include "airoha_eth.h"
#include "airoha_function.h"




unchar ethmac_addr[6] = {0x00, 0xAA, 0xBB, 0x01, 0x23, 0x40};
struct airoha_eth *glb_eth;
EXPORT_SYMBOL(glb_eth);
int g_pon_serdes_eth = 0;

static const struct ring_dscp_map ring_dscp_table[] = {
    {0, 1024},
    {1, 256},
    {2, 128},
    {3, 128},
    {4, 256},
    {6, 128},
    {7, 128},
    {8, 128},
    {9, 128},
    {11, 256},
    {15, 128},
};

/* LRO ring base index (ring 12-19 are LRO capable) */
#define AIROHA_LRO_RING_BASE	12
#define CPU_DSCP_MAX_NUM		4096

#if 0 
int pon_fill_forward_path(struct net_device_path_ctx *ctx,
				      struct net_device_path *path)
{
	path->dev = ctx->dev;
	path->type = DEV_PATH_ETHERNET;

	ctx->dev = glb_eth->ports[1]->devs[0]->dev;

	return 0;
}
EXPORT_SYMBOL(pon_fill_forward_path);
#endif

static bool arht_sel_phy_external(struct airoha_gdm_port *port)
{
	if (port->id == 1)
		return 0;
	
	if (port->id != 2 || !port->devs[0])
		return 1;

	return g_pon_serdes_eth;
}


static int arht_extra_hw_init(struct airoha_eth *eth)
{

	int i;
	struct airoha_ppe *ppe = eth->ppe;
	if (eth->extra_ops.set_fe_regs)
		eth->extra_ops.set_fe_regs(eth);
#ifdef CONFIG_NET_AIROHA_FLOW_STATS
        /* Disable OQ flow control on CDM3 q5/q7 (NPU flow-stats cores).
         * Each queue uses only its own OQ - no shared buffers, no backpressure.
         * A slow core drops its own packets instead of stalling the datapath.
         */
	airoha_fe_pse_oq_set_fc_disable(eth, FE_PSE_PORT_CDM3, 5);
	airoha_fe_pse_oq_set_fc_disable(eth, FE_PSE_PORT_CDM3, 7);
#endif
	for (i = 0; i < ARRAY_SIZE(eth->qdma); i++) {
		airoha_dp_api_qdma_meter_default_config(&eth->qdma[i]);
		if(eth->extra_ops.set_qdma_regs)
			eth->extra_ops.set_qdma_regs(&eth->qdma[i], eth);
	}

	airoha_qdma_multicast_init(eth);
	arht_ppe_init(ppe);
	airoha_eth_monitor_workqueue_init();
	airoha_dp_api_debugfs_init(eth);
	return 0;
}
static void arht_set_mac_addr(struct airoha_eth *eth, struct net_device *netdev)
{
	if (!is_valid_ether_addr(ethmac_addr)) {
		eth_hw_addr_random(netdev);
		dev_info(eth->dev, "generated random MAC address %pM\n", netdev->dev_addr);
	} else {
		eth_hw_addr_set(netdev, ethmac_addr);
	}
	dev_info(eth->dev, "MAC address %pM\n", netdev->dev_addr);
}
static inline u32 *arht_get_rx_dscp_array(struct airoha_eth *eth, int qdma_id)
{
	return qdma_id ? eth->dscp_cfg.rx_dscp_wan : eth->dscp_cfg.rx_dscp_lan;
}

static inline u8 arht_get_lro_mask(struct airoha_eth *eth, int qdma_id)
{
	return qdma_id ? eth->dscp_cfg.lro_mask_wan : eth->dscp_cfg.lro_mask_lan;
}

static int arht_rx_dscp_num(struct airoha_eth *eth, int qdma_id, int ring)
{
	int i;

	if (qdma_id < 0 || qdma_id >= AIROHA_MAX_NUM_QDMA)
		return DEFAULT_RING_NUM;

	if (eth->dscp_cfg.dscp_set_from_dts[qdma_id])
		return arht_get_rx_dscp_array(eth, qdma_id)[ring];

	for (i = 0; i < ARRAY_SIZE(ring_dscp_table); i++) {
		if (ring_dscp_table[i].ring == ring)
			return ring_dscp_table[i].dscp_num;
	}
	return DEFAULT_RING_NUM;
}

static void arht_ppe_exit(void)
{

	airoha_eth_monitor_workqueue_exit();
	airoha_hsgmii_exit();

}

/*
 * arht_is_lro_ring - Check if a ring is an LRO ring based on DTS configuration
 * Return: 1 if LRO ring, 0 if not LRO ring, -1 if DTS not configured
 */
static int arht_is_lro_ring(struct airoha_eth *eth, int qdma_id, int qid)
{
	if (qdma_id < 0 || qdma_id >= AIROHA_MAX_NUM_QDMA)
		return -1;

	if (!eth->dscp_cfg.dscp_set_from_dts[qdma_id])
		return -1;

	if (qid < AIROHA_LRO_RING_BASE ||
	    qid >= AIROHA_LRO_RING_BASE + AIROHA_MAX_NUM_LRO_QUEUES)
		return 0;

	return !!(arht_get_lro_mask(eth, qdma_id) & BIT(qid - AIROHA_LRO_RING_BASE));
}

/*
 * arht_get_lro_dscp - Get LRO DSCP value for a ring from DTS configuration
 * Return: DSCP value from DTS, or 0 if DTS not configured, or LRO_RX_DSCP_NUM as default
 */
static int arht_get_lro_dscp(struct airoha_eth *eth, int qdma_id, int qid)
{
	u32 dscp;

	if (qdma_id < 0 || qdma_id >= AIROHA_MAX_NUM_QDMA)
		return LRO_RX_DSCP_NUM;

	if (!eth->dscp_cfg.dscp_set_from_dts[qdma_id])
		return LRO_RX_DSCP_NUM;

	if (qid < 0 || qid >= AIROHA_NUM_RX_RING)
		return LRO_RX_DSCP_NUM;

	dscp = arht_get_rx_dscp_array(eth, qdma_id)[qid];
	return dscp > 0 ? dscp : LRO_RX_DSCP_NUM;
}

static const struct arht_extra_ops an7583_extra_ops = {
	/* common ops */
	.set_mac_addr = arht_set_mac_addr,
	.arht_hw_init = arht_extra_hw_init,
	.set_bucket_size = arht_set_bucket_size,
	.arht_rx_handler = airoha_receive_hook,
	.arht_tx_handler = airoha_qdma_lan_tx,
	.sel_phy_external = arht_sel_phy_external,
	.modify_ppe_entry = arht_modified_ppe_entry,
	.update_shrink_table = UpdateShrinkTable,
	.set_flow_dst = airoha_set_flow_destination,
	.tx_modified = arht_tx_modified,
	.get_gdm_dev = airoha_ppe_get_gdm_dev,
	.rx_dscp_num_init = arht_rx_dscp_num,
	.is_lro_ring = arht_is_lro_ring,
	.get_lro_dscp = arht_get_lro_dscp,
	.ppe_exit = arht_ppe_exit,
	/* chip ops */
	.support_eth_monitor = an7583_support_eth_monitor,
	.set_channel_retire = an7583_channel_retire,
	.set_qdma_regs = an7583_qdma_regs_setting,
	.set_fe_regs = an7583_fe_regs_setting,
	.get_qdma_channel = an7583_get_qdma_channel,
	.get_qdma_buf_size = an7583_get_qdma_buf_size,
	.conntrack_get_cnt = arht_conntrack_get_cnt,
	.conntrack_free_cnt = arht_conntrack_free_cnt,

};
static const  struct arht_extra_ops an7581_extra_ops = {
	/* common ops */
	.set_mac_addr = arht_set_mac_addr,
	.arht_hw_init = arht_extra_hw_init,
	.set_bucket_size = arht_set_bucket_size,
	.arht_rx_handler = airoha_receive_hook,
	.arht_tx_handler = airoha_qdma_lan_tx,
	.sel_phy_external = arht_sel_phy_external,
	.modify_ppe_entry = arht_modified_ppe_entry,
	.update_shrink_table = UpdateShrinkTable,
	.set_flow_dst = airoha_set_flow_destination,
	.tx_modified = arht_tx_modified,
	.get_gdm_dev = airoha_ppe_get_gdm_dev,
	.rx_dscp_num_init = arht_rx_dscp_num,
	.is_lro_ring = arht_is_lro_ring,
	.get_lro_dscp = arht_get_lro_dscp,
	.ppe_exit = arht_ppe_exit,
	/* chip ops */
	.support_eth_monitor = en7581_support_eth_monitor,
	.set_qdma_regs = an7581_qdma_regs_setting,
	.set_fe_regs = an7581_fe_regs_setting,
	.get_qdma_channel = en7581_get_qdma_channel,
	.get_qdma_buf_size = en7581_get_qdma_buf_size,
	.conntrack_get_cnt = arht_conntrack_get_cnt,
	.conntrack_free_cnt = arht_conntrack_free_cnt,

};


static void arht_config_extra_ops(struct airoha_eth *eth)
{
	if (airoha_is_7581(eth)) {
		eth->extra_ops = an7581_extra_ops;
		eth->qdma_init.speedtest_fastpath = 1;
	} else if (airoha_is_7583(eth)) {
		eth->extra_ops = an7583_extra_ops;
		eth->qdma_init.speedtest_fastpath = 1;
	}
}

static void arht_validate_rx_dscp_array(u32 *rx_dscp)
{
	int i;

	for (i = 0; i < AIROHA_NUM_RX_RING; i++) {
		if (rx_dscp[i] > CPU_DSCP_MAX_NUM)
			rx_dscp[i] = CPU_DSCP_MAX_NUM;
	}
}

static void arht_read_qdma_dscp_from_dts(struct airoha_eth *eth,
					 struct device_node *np,
					 int qdma_id,
					 const char *dscp_prop,
					 const char *lro_prop)
{
	u32 lro_mask_tmp;
	int ret_dscp, ret_lro;
	u32 *rx_dscp = arht_get_rx_dscp_array(eth, qdma_id);
	u8 *lro_mask = qdma_id ? &eth->dscp_cfg.lro_mask_wan : &eth->dscp_cfg.lro_mask_lan;

	ret_dscp = of_property_read_u32_array(np, dscp_prop, rx_dscp, AIROHA_NUM_RX_RING);
	if (!ret_dscp)
		arht_validate_rx_dscp_array(rx_dscp);

	ret_lro = of_property_read_u32(np, lro_prop, &lro_mask_tmp);
	*lro_mask = ret_lro ? 0 : (u8)(lro_mask_tmp & 0xFF);

	eth->dscp_cfg.dscp_set_from_dts[qdma_id] = (!ret_dscp) && (!ret_lro);
}

static void arht_read_dscp_num_from_dts(struct airoha_eth *eth)
{
	struct device_node *np = eth->dev->of_node;

	eth->dscp_cfg.dscp_set_from_dts[0] = false;
	eth->dscp_cfg.dscp_set_from_dts[1] = false;

	arht_read_qdma_dscp_from_dts(eth, np, 0, "rx-dscp-lan", "lro-mask-lan");
	arht_read_qdma_dscp_from_dts(eth, np, 1, "rx-dscp-wan", "lro-mask-wan");
}

int arht_extra_probe(struct airoha_eth *eth)
{
	int err = 0;

	err = is_ethmac_nvmem_cell_available(eth);
	if (err) {
		debugfs_remove_recursive(eth->debugfs_dir);
		return err;
	} else {
		get_ethmac_from_dts(eth);
	}
	arht_config_extra_ops(eth);
	eth->meter_enable = of_property_read_bool(eth->dev->of_node, "meter-enable");
	eth->reduce_memory = of_property_read_bool(eth->dev->of_node, "reduce-memory");
	arht_read_dscp_num_from_dts(eth);
	airoha_eth_qdma_fastpath_default_cfg(eth);
	glb_eth = eth;
	airoha_hsgmii_init();
	return 0;
}


