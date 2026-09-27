#ifndef _ARHT_FE_H_
#define _ARHT_FE_H_

#include <linux/bits.h>
#define AIROHA_MAX_NUM_PPE		2
#define REG_TDMA_GLO_CFG			0x0a04
#define TDMA_GLO_CFG_RX_DMA_EN_MASK		BIT(2)
#define TDMA_GLO_CFG_TX_DMA_EN_MASK		BIT(0)
int fe_api_set_pkt_length(struct ecnt_fe_data *fe_data);

int fe_api_set_channel_enable(struct ecnt_fe_data *fe_data);
int fe_api_set_mac_addr(struct ecnt_fe_data *fe_data);
int fe_api_set_mac_addr_7516(struct ecnt_fe_data *fe_data);
int fe_api_set_wan_port_7516(struct ecnt_fe_data *fe_data);
int fe_get_hwfwd_channel(struct ecnt_fe_data *fe_data);
int fe_set_hwfwd_channel(struct ecnt_fe_data *fe_data);
int fe_api_set_channel_retire(struct ecnt_fe_data *fe_data);
int fe_api_set_crc_strip(struct ecnt_fe_data *fe_data);
int fe_api_set_padding(struct ecnt_fe_data *fe_data);
int fe_api_get_ext_tpid(struct ecnt_fe_data *fe_data);
int fe_api_set_ext_tpid(struct ecnt_fe_data *fe_data);
int fe_api_get_fw_cfg(struct ecnt_fe_data *fe_data);

int fe_api_set_fw_cfg(struct ecnt_fe_data *fe_data);
int fe_api_set_drop_udp_chksum_err_enable(struct ecnt_fe_data *fe_data);
int fe_api_set_drop_tcp_chksum_err_enable(struct ecnt_fe_data *fe_data);
int fe_api_set_drop_ip_chksum_err_enable(struct ecnt_fe_data *fe_data);
int fe_api_set_drop_runt_enable(struct ecnt_fe_data *fe_data);
int fe_api_set_drop_long_enable(struct ecnt_fe_data *fe_data);
int fe_api_set_drop_crc_err_enable(struct ecnt_fe_data *fe_data);
int fe_api_set_vlan_check(struct ecnt_fe_data *fe_data);
int fe_api_get_ok_cnt(struct ecnt_fe_data *fe_data);
int fe_api_get_rx_err_crc_cnt(struct ecnt_fe_data *fe_data);
int fe_api_get_rx_drop_fifo_cnt(struct ecnt_fe_data *fe_data);
int fe_api_get_rx_drop_err_cnt(struct ecnt_fe_data *fe_data);
int fe_api_get_ok_byte_cnt(struct ecnt_fe_data *fe_data);
int fe_api_get_tx_get_cnt(struct ecnt_fe_data *fe_data);
int fe_api_get_tx_drop_cnt(struct ecnt_fe_data *fe_data);
int fe_api_get_time_stamp(struct ecnt_fe_data *fe_data);
int fe_api_set_time_stamp(struct ecnt_fe_data *fe_data);
int fe_api_set_ins_vlan_tpid(struct ecnt_fe_data *fe_data);
int fe_api_set_vlan_enable(struct ecnt_fe_data *fe_data);
int fe_api_set_black_list(struct ecnt_fe_data *fe_data);
int fe_api_set_ether_type(struct ecnt_fe_data *fe_data);
int fe_api_set_L2U_key(struct ecnt_fe_data *fe_data);
int fe_api_get_ac_group_pkt_cnt(struct ecnt_fe_data *fe_data);
int fe_api_get_ac_group_byte_cnt(struct ecnt_fe_data *fe_data);
int fe_api_clear_ac_group_pkt_cnt(struct ecnt_fe_data *fe_data);
int fe_api_clear_ac_group_byte_cnt(struct ecnt_fe_data *fe_data);
int fe_api_set_meter_group(struct ecnt_fe_data *fe_data);
int fe_api_get_meter_group(struct ecnt_fe_data *fe_data);
int fe_api_set_gdm_pcp_coding(struct ecnt_fe_data *fe_data);
int fe_api_set_cdm_pcp_coding(struct ecnt_fe_data *fe_data);
int fe_api_set_vip_enable(struct ecnt_fe_data *fe_data);
int fe_api_get_eth_rx_cnt(struct ecnt_fe_data *fe_data);
int fe_api_get_eth_tx_cnt(struct ecnt_fe_data *fe_data);
int fe_api_get_eth_frame_cnt(struct ecnt_fe_data *fe_data);
int fe_api_get_eth_err_cnt(struct ecnt_fe_data *fe_data);
int fe_api_set_clear_mib(struct ecnt_fe_data *fe_data);
int fe_api_set_cdm_rx_red_drop_mode(struct ecnt_fe_data *fe_data);
int fe_api_get_cdm_rx_red_drop_mode(struct ecnt_fe_data *fe_data);
int fe_api_set_channel_retire_all(struct ecnt_fe_data *fe_data);
int fe_api_set_tx_rate(struct ecnt_fe_data *fe_data);
int fe_api_set_rx_rate(struct ecnt_fe_data *fe_data);
int fe_api_set_rxuc_rate(struct ecnt_fe_data *fe_data);
int fe_api_set_rxbc_rate(struct ecnt_fe_data *fe_data);
int fe_api_set_rxmc_rate(struct ecnt_fe_data *fe_data);
int fe_api_set_rxoc_rate(struct ecnt_fe_data *fe_data);
int fe_api_set_rx_mac_filter_rate(struct ecnt_fe_data *fe_data);
int fe_api_add_vip_ether(struct ecnt_fe_data *fe_data);
int fe_api_add_vip_ppp(struct ecnt_fe_data *fe_data);
int fe_api_add_vip_ip(struct ecnt_fe_data *fe_data);
int fe_api_add_vip_tcp(struct ecnt_fe_data *fe_data);
int fe_api_add_vip_udp(struct ecnt_fe_data *fe_data);
int fe_api_del_vip_ether(struct ecnt_fe_data *fe_data);
int fe_api_del_vip_ppp(struct ecnt_fe_data *fe_data);
int fe_api_del_vip_ip(struct ecnt_fe_data *fe_data);
int fe_api_del_vip_tcp(struct ecnt_fe_data *fe_data);
int fe_api_del_vip_udp(struct ecnt_fe_data *fe_data);
int fe_api_add_l2lu_vlan_dscp(struct ecnt_fe_data *fe_data);
int fe_api_add_l2lu_vlan_trfc(struct ecnt_fe_data *fe_data);
int fe_api_del_l2lu_vlan_dscp(struct ecnt_fe_data *fe_data);
int fe_api_del_l2lu_vlan_trfc(struct ecnt_fe_data *fe_data);
int fe_api_add_traffic_class(struct ecnt_fe_data * fe_data);
int fe_api_del_traffic_class(struct ecnt_fe_data * fe_data);
int fe_api_set_tx_favor_oam_enable(struct ecnt_fe_data *fe_data);
int fe_api_set_tls_cfg(struct ecnt_fe_data *fe_data);
int fe_api_do_fe_reset(struct ecnt_fe_data *fe_data);
int fe_api_set_loopback_enable(struct ecnt_fe_data *fe_data);
int fe_api_set_loopback_mode(struct ecnt_fe_data *fe_data);
int fe_api_get_unknown_mul_pkt(struct ecnt_fe_data *fe_data);
int fe_api_set_glo_rate_byte(struct ecnt_fe_data *fe_data);
int fe_api_get_pppoe_info(struct ecnt_fe_data *fe_data);
int fe_api_set_pppoe_info_clean(struct ecnt_fe_data *fe_data);
int fe_api_get_tx_traffic(struct ecnt_fe_data *fe_data);
int fe_api_get_rx_traffic(struct ecnt_fe_data *fe_data);
int fe_api_get_tx_rate(struct ecnt_fe_data *fe_data);
int fe_api_get_rx_rate(struct ecnt_fe_data *fe_data);
int fe_api_get_tx_octets(struct ecnt_fe_data *fe_data);
int fe_api_get_rx_octets(struct ecnt_fe_data *fe_data);
int fe_api_get_rx_discard_counter(struct ecnt_fe_data *fe_data);
int fe_api_get_tx_discard_counter(struct ecnt_fe_data *fe_data);
int fe_api_get_rx_error_counter(struct ecnt_fe_data *fe_data);
int fe_api_get_tx_error_counter(struct ecnt_fe_data *fe_data);
int fe_api_add_dev_to_total_account(struct ecnt_fe_data *fe_data);
int fe_api_add_stb_src_ip(struct ecnt_fe_data *fe_data);
int fe_api_del_stb_src_ip(struct ecnt_fe_data *fe_data);

int fe_api_set_rx_mac_filter(struct ecnt_fe_data *fe_data);

int fe_api_set_mc_vlan_global(struct ecnt_fe_data *fe_data);
int fe_api_get_mc_vlan_global(struct ecnt_fe_data *fe_data);
int fe_api_set_mc_vlan_table_cfg(struct ecnt_fe_data *fe_data);
int fe_api_get_mc_vlan_table_cfg(struct ecnt_fe_data *fe_data);
int fe_api_set_mc_vlan_action_cfg(struct ecnt_fe_data *fe_data);
int fe_api_get_mc_vlan_action_cfg(struct ecnt_fe_data *fe_data);
int fe_api_set_mc_vlan_clear_all(struct ecnt_fe_data *fe_data);
int fe_api_xfi_link_change(struct ecnt_fe_data *fe_data);
int fe_api_set_gdma_misc_config(struct ecnt_fe_data *fe_data);
int fe_api_get_hsgmii_rx_cnt(struct ecnt_fe_data *fe_data);
int fe_api_get_hsgmii_tx_cnt(struct ecnt_fe_data *fe_data);
int fe_api_set_clr_cnt(struct ecnt_fe_data *fe_data);
int fe_api_set_aewan_fwdfq(struct ecnt_fe_data *fe_data);
int fe_api_set_aewan_ifcdisable(struct ecnt_fe_data *fe_data);
int fe_api_set_gdm2_sptag_for_loopback(struct ecnt_fe_data *fe_data);
int fe_api_set_tunnel_cfg(struct ecnt_fe_data *fe_data);
int fe_api_set_gdm_sptag_for_extswitch(struct ecnt_fe_data *fe_data);
int fe_api_pse_oq_rsv_en(struct ecnt_fe_data *fe_data);
int fe_api_set_hsgmii_rx_port_ratelimit(struct ecnt_fe_data *fe_data);
int fe_api_set_mbi_arb_rst(struct ecnt_fe_data *fe_data);
int fe_api_set_rmbi_frag(struct ecnt_fe_data *fe_data);
int fe_api_get_chn_rls(struct ecnt_fe_data *fe_data);
int fe_api_set_tmbi_frag(struct ecnt_fe_data *fe_data);
int fe_api_set_gdma_enable(struct ecnt_fe_data *fe_data);
int fe_api_set_gdma_disable(struct ecnt_fe_data *fe_data);
int fe_api_set_chn_retire_action(struct ecnt_fe_data *fe_data);
int fe_api_set_chn_retire_done(struct ecnt_fe_data *fe_data);
int fe_api_set_qbi_fttr_chn_disable(struct ecnt_fe_data *fe_data);
int fe_api_set_force_slow_enable(struct ecnt_fe_data *fe_data);
int fe_api_set_force_slow_duty(struct ecnt_fe_data *fe_data);

int fe_ioctl_set_tls_cfg(unsigned char cmd,unsigned char tls_port,unsigned short tls_vlan);
int fe_api_tls_forwad(struct ecnt_fe_data *fe_data);
int fe_ioctl_set_trunk_mode_tls_cfg(unsigned char cmd,FE_Tls_info_t tls_info);

int fe_api_init_resource_manage(struct ecnt_fe_data *fe_data);
int fe_api_deinit_resource_manage(struct ecnt_fe_data *fe_data);
int fe_api_set_meter_ratelimit(struct ecnt_fe_data *fe_data);
int fe_api_get_meter_ratelimit(struct ecnt_fe_data *fe_data);
int fe_api_get_meter_idx(struct ecnt_fe_data *fe_data);
int fe_api_get_acnt2_idx(struct ecnt_fe_data *fe_data);
int fe_api_get_acnt1_idx(struct ecnt_fe_data *fe_data);
int fe_api_get_acnt0_idx(struct ecnt_fe_data *fe_data);
int fe_api_get_rx_ratelimit_mode(struct ecnt_fe_data *fe_data);
int fe_api_set_rx_ratelimit_rule(struct ecnt_fe_data *fe_data);
int fe_api_set_rx_ratelimit_mode(struct ecnt_fe_data *fe_data);
int fe_api_set_meter_ctl_by_olt(struct ecnt_fe_data *fe_data);
int fe_api_get_flow_cnt(struct ecnt_fe_data *fe_data);
int fe_api_get_acnt0_mode(struct ecnt_fe_data *fe_data);
int fe_api_get_acnt1_mode(struct ecnt_fe_data *fe_data);
int fe_api_set_acnt0_mode(struct ecnt_fe_data *fe_data);
int fe_api_set_acnt1_mode(struct ecnt_fe_data *fe_data);
int fe_api_set_acnt2_mode(struct ecnt_fe_data *fe_data);
int fe_api_get_meter_enable(struct ecnt_fe_data *fe_data);
int fe_api_clear_flow_cnt(struct ecnt_fe_data *fe_data);
int fe_api_get_dev_mac_index(struct ecnt_fe_data *fe_data);
int fe_api_set_pse_oq_threshold(struct ecnt_fe_data *fe_data);
int fe_api_get_wan_itf_index(struct ecnt_fe_data *fe_data);
int fe_api_set_ratelimit_for_pkt_formate(struct ecnt_fe_data *fe_data);

int fe_api_get_pse_drop_cnt(struct ecnt_fe_data *fe_data);
int fe_api_set_vip_rxq_selection(struct ecnt_fe_data *fe_data);
int fe_api_set_vip_for_tcp_speedtest(struct ecnt_fe_data *fe_data);
int fe_api_check_chn_rls(struct ecnt_fe_data *fe_data);
int fe_api_set_dev_stat_ratelimit_mode(struct ecnt_fe_data *fe_data);


void airoha_fe_core_reset(struct airoha_eth *eth);
void airoha_fe_do_core_reset(struct airoha_eth *eth);
extern atomic_t fe_core_reset_count;
void airoha_fe_pse_oq_set_fc_disable(struct airoha_eth *eth, u32 port, u32 queue);
int airoha_fe_gdm_rls(struct airoha_gdm_port *port);

#endif  /* _ARHT_FE_H_ */
