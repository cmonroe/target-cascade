#include <linux/bitfield.h>

#include "../airoha_regs.h"
#include "../airoha_eth.h"
#include "../arht_dp_api.h"
#include "soc_en7581.h"

unsigned int en7581_get_fe_fport(struct sk_buff *skb, struct net_device *dev, u32 portid)
{
	u8 fport;
	fport = (portid == AIROHA_GDM4_IDX) ? FE_PSE_PORT_GDM4 : portid;
	return fport;
}



int en7581_support_eth_monitor(int p)
{
	/*gdm2 and gdm3 not detect, skip*/
	if(p == AIROHA_PORTS_GDM2_ID || p == AIROHA_PORTS_GDM3_ID)
		return 0;
	return 1;
}

void an7581_qdma_regs_setting(struct airoha_qdma *qdma, struct airoha_eth *eth)
{
	int mask = 0;
	int val = 0;

	int id = qdma - &eth->qdma[0];

	airoha_qdma_wr(qdma, REG_TXQ_TOTALTHR, 0x39992e00);
	airoha_qdma_wr(qdma, REG_TXQ_CHNLTHR_CFG, 0x39990400);
	airoha_qdma_wr(qdma, REG_TXQ_QUEUETHR_CFG, 0x20000020);
	airoha_qdma_set(qdma, QDMA_CSR_QOS_AGING_CFG, QDMA_QOS_AGING_EN);
	airoha_qdma_set(qdma, QDMA_CSR_QOS_AGING_CFG, QDMA_QOS_AGING_FAST_REPLACE);

	//set qdma multi issue
	mask = GLOBAL_CFG_RD_BYPASS_WR_MASK | GLOBAL_CFG_MAX_ISSUE_NUM_MASK;
	val = GLOBAL_CFG_RD_BYPASS_WR_MASK | FIELD_PREP(GLOBAL_CFG_MAX_ISSUE_NUM_MASK, 3);
	airoha_qdma_rmw(qdma, REG_QDMA_GLOBAL_CFG, mask, val);

	if (id == 0)
	{
		//set qdma egress ratemeter cfg
		mask = (EGRESS_RATE_METER_EQ_RATE_EN_MASK | EGRESS_RATE_METER_WINDOW_SZ_MASK | EGRESS_RATE_METER_TIMESLICE_MASK);
		val = (FIELD_PREP(EGRESS_RATE_METER_WINDOW_SZ_MASK, 1) | FIELD_PREP(EGRESS_RATE_METER_TIMESLICE_MASK, 0x740));
		airoha_qdma_rmw(qdma, REG_EGRESS_RATE_METER_CFG, mask, val);
	}

	/* Congestion thresholds for the SRAM (fast) hw-forward TX queue. Left at
	 * the reset default these trip early and drop at CDM hw-forward ingress
	 * (CDMA{1,2}_RXHWF_FAST_DROP_CNT) once a fast-path flow approaches 10G.
	 */
	mask = (TXQ_CNGST_TXQ_TOTAL_MAX_THR_MASK | TXQ_CNGST_TXQ_TOTAL_MIN_THR_MASK);
	val = (FIELD_PREP(TXQ_CNGST_TXQ_TOTAL_MAX_THR_MASK, BUFF_FAST_TOTAL_MAX_THRH)
		| FIELD_PREP(TXQ_CNGST_TXQ_TOTAL_MIN_THR_MASK, BUFF_FAST_TOTAL_MIN_THRH));
	airoha_qdma_rmw(qdma, REG_QDMA_TXQ_TOTAL_FAST_THR, mask, val);

	return;
}

void an7581_fe_regs_setting(struct airoha_eth *eth)
{
	/* Free Address Queue prefetch for both CDMs. AN7581 runs 10G on GDM2
	 * (CDM2/qdma1, uplink) and 10G on GDM4 (CDM1/qdma0, downlink), so unlike
	 * AN7583 both CDMs need it.
	 */
	//set cdm1 faq
	airoha_fe_wr(eth, REG_FAQ_CFG(1), 0x07e6);
	airoha_fe_wr(eth, REG_FAQTHR_CFG(1), 0xc40003f0);
	airoha_fe_set(eth, REG_FAQ_CFG(1), FAQ_EN_MASK);
	//set cdm2 faq
	airoha_fe_wr(eth, REG_FAQ_CFG(2), 0x07e6);
	airoha_fe_wr(eth, REG_FAQTHR_CFG(2), 0xc40003f0);
	airoha_fe_set(eth, REG_FAQ_CFG(2), FAQ_EN_MASK);
	//set qbi fttr chn disable
	airoha_fe_wr(eth, REG_QBI_FTTR_CHANNEL_CFG, 0);

	return;
}

unsigned int en7581_get_qdma_channel(struct airoha_gdm_dev *dev, u32 sptag)
{
	const struct airoha_eth_soc_data *soc;
	int serdes_idx;
	u32 portid;
	int nbq;

	if (!dev || !dev->port || !dev->eth)
		return 0;

	soc = dev->eth->soc;
	portid = dev->port->id;
	nbq = dev->nbq;

	switch (portid) {
	case AIROHA_GDM3_IDX:
		serdes_idx = (nbq == 5) ? SERDES_PCIE1_IDX : SERDES_PCIE0_IDX;
		break;
	case AIROHA_GDM4_IDX:
		serdes_idx = (nbq == 1) ? SERDES_USB_IDX : SERDES_ETH_IDX;
		break;
	default:
		/* GDM1: DSA switch ports, use sptag-based mapping */
		return LAN_IDX_FROM_TX_SPTAG((u16)(sptag & 0xFF)) %  AIROHA_MAX_NUM_CHANNELS;
	}

	return (u32)soc->chnl[serdes_idx] % AIROHA_MAX_NUM_CHANNELS;
}

unsigned int en7581_get_qdma_buf_size(int id)
{
	u32 buf_size;

	buf_size = id ? AIROHA_MAX_PACKET_SIZE / 2 : AIROHA_MAX_PACKET_SIZE;

	return buf_size;
}
