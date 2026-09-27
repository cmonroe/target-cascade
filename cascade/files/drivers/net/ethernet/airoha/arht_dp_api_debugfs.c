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
#include "airoha_eth.h"
#include "airoha_regs.h"

#include "airoha_function.h"


/************************************************************************
*                  P U B L I C   D A T A
*************************************************************************
*/
extern struct airoha_eth *glb_eth;
extern int gemport_ratelimit_enable[AIROHA_MAX_IDX_FOR_GEMPORT_RATELIMIT + 1];
extern int lan_ratelimit_enable[AIROHA_MAX_NUM_QDMA][GENERAL_INGRESS_INDEX_MAX_GRP1 + 1];
extern int gemport_ratelimit_flag;
extern unsigned int fast_path_speed_threshold;
extern int packet_is_transparent_mode;
extern bool switch_set_mfc_enable;

extern int timeOutVal;
extern int InitShrinkTable(void);
extern int ppe_dump_shrink_table(void);
extern int g_pon_serdes_eth;

ssize_t CHECK_BUF(char *debugfs_buffer, int index, int buf_size);

ssize_t CHECK_BUF(char *debugfs_buffer, int index, int buf_size)
{
	if(index >= buf_size -1)
	{
		buf_size*=2;
		debugfs_buffer=kmalloc(buf_size,GFP_KERNEL);
		
		if(!debugfs_buffer)
			return -ENOMEM;
		
	}
	return buf_size;
}
static ssize_t airoha_rxring_limit_value_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char input_str[64];
	char fuc_str[16];
	int ret = 0;
	unsigned int qdma_idx, ring_idx, value = 0;;
	struct airoha_eth *eth = glb_eth;

	if (count >= sizeof(input_str))
		return -EINVAL;
	if (copy_from_user(input_str, buf, count))
		return -EFAULT;
	input_str[count] = '\0';
	if(sscanf(input_str, "%15s %10u %10u %10u ",fuc_str, &qdma_idx, &ring_idx, &value) < 2){
		printk("\n Help: [set/get] [qdma_idx:0/1][ring_idx] [value] \n");
		return -EINVAL;
	}
	if(qdma_idx > 1 || ring_idx >= AIROHA_NUM_RX_RING)
		return -EINVAL;
	
	if(!strcmp(fuc_str,"set"))
		ret = airoha_dp_api_qdma_set_meter_value(&eth->qdma[qdma_idx],ring_idx,value);
	else if(!strcmp(fuc_str,"get")){
		ret = airoha_dp_api_qdma_get_meter_value(&eth->qdma[qdma_idx],ring_idx);
		printk("\n qdma idx:%u ring_idx:%u rxring_value:%u \n",qdma_idx,ring_idx,ret);
	}
	else{
		printk("\n Help: [set/get] [qdma_idx:0/1][ring_idx] [value] \n");
		return -EINVAL;
	}
	
	if(ret < 0)
		return -EINVAL;
		
	return count;
	
   
}

static ssize_t airoha_gemport_ratelimit_value_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	/* CID:1088148 */
	char input_str[64] = {0};
	int ret = 0;
	char fuc_str[16] = {0};
	unsigned int dir = 0, gemport_idx = 0, meter_idx = 0, value = 0;
	struct airoha_eth *eth = glb_eth;
	unsigned char group_id = 0;

	if (count >= sizeof(input_str))
		return -EINVAL;
	if (copy_from_user(input_str, buf, count))
		return -EFAULT;
	input_str[count] = '\0';
	if(sscanf(input_str, "%15s %10u %10u %10u ",fuc_str, &dir, &gemport_idx, &value) < 3){
		printk("\n Help: [set/get] [dir:0(DS)/1(US)][gemport_idx] [value] \n");
		return -EINVAL;
	}
	
	if (dir <= 1 && gemport_idx <= AIROHA_MAX_IDX_FOR_GEMPORT_RATELIMIT)
		meter_idx += AIROHA_NUM_RX_RING;
	else{
		printk("\n Error: dir should be betweeen 0 - 1 Index should be betweeen 0 - 31 \n");
		return -EINVAL;
	}

	if(!strcmp(fuc_str,"set"))
	{
	    ret = airoha_dp_api_qdma_set_meter_cfg(&eth->qdma[dir], group_id, meter_idx, value);
		ret |= airoha_dp_api_qdma_set_meter_value(&eth->qdma[dir], (group_id << 8) | meter_idx, value);
		if(value > 0 && ret == 0){
		    gemport_ratelimit_enable[meter_idx - AIROHA_NUM_RX_RING] = 1;
			gemport_ratelimit_flag = 0;
		}
		if(value == 0){
		    gemport_ratelimit_enable[meter_idx - AIROHA_NUM_RX_RING] = 0;
			gemport_ratelimit_flag = 1;
		}
	}
	else if(!strcmp(fuc_str, "get"))
	{
		ret = airoha_dp_api_qdma_get_meter_value(&eth->qdma[dir], (group_id << 8) | meter_idx);
		printk("\n gemport_idx: %u, dir: %s, ratelimit value: %ukbps\n", gemport_idx, dir ? "up" : "down", ret);
		}
	else{
		printk("\n Help: [set/get] [dir:0/1][gemport_idx] [value] \n");
		return -EINVAL;
	}
	
	if(ret < 0)
		return -EINVAL;
		
	return count;
}

static ssize_t airoha_lan_ratelimit_value_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	/* CID:1116759 */
	char input_str[64] = {0};
	int i = 0, ret = 0;
	char fuc_str[16] = {0};
	char itf_name[16] = {0};
	unsigned int dir = 0, meter_idx = 0, value = 0;
	struct airoha_eth *eth = glb_eth;
	unsigned char group_id = 0x1;

	if (count >= sizeof(input_str))
		return -EINVAL;
	if (copy_from_user(input_str, buf, count))
		return -EFAULT;
	input_str[count] = '\0';
	if(sscanf(input_str, "%15s %10u %15s %10u ",fuc_str, &dir, itf_name, &value) < 3)
	{
		printk("\n Help: [set/get] [dir:0(DS)/1(US)][itf_name] [value] \n");
		return -EINVAL;
	}	
  
	if (itf_name[0] != '\0'){
		for (i = 0; dev_meter_map[i].dev_name != NULL; i++) 
        {
            if (strcmp(itf_name, dev_meter_map[i].dev_name) == 0) 
            {
                meter_idx = dev_meter_map[i].meter_idx;
                break;
            }
        }
	}else{
		printk("\n Error: The lan dev name is error!\n");
		return -EINVAL;
	}

	if (dir >= AIROHA_MAX_NUM_QDMA)
	{
		printk("\n The dir is no correct: [dir:0(DS)/1(US)] \n");
		return -EINVAL;
	}

	if(!strcmp(fuc_str, "set"))
	{
	    ret = airoha_dp_api_qdma_set_meter_cfg(&eth->qdma[dir], group_id, meter_idx, value);
		ret |= airoha_dp_api_qdma_set_meter_value(&eth->qdma[dir], (group_id << 8) | meter_idx, value);
		if(value > 0 && ret == 0){
		    lan_ratelimit_enable[dir][meter_idx] = 1;
		}
		if(value == 0){
		    lan_ratelimit_enable[dir][meter_idx] = 0;
		}
	}
	else if(!strcmp(fuc_str, "get"))
	{
		ret = airoha_dp_api_qdma_get_meter_value(&eth->qdma[dir], (group_id << 8) | meter_idx);
		printk("\n itf_name: %s, dir: %s, ratelimit_value: %ukbps\n", itf_name, dir ? "up" : "down", ret);
	}
	else{
		printk("\n Help: [set/get] [dir:0/1][itf_name] [value] \n");
		return -EINVAL;
	}

	if(ret < 0)
		return -EINVAL;
		
	return count;
}

static ssize_t airoha_fe_debug_reg_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	int index = 0;
    int i = 0;
	ssize_t buf_size=4086;
	ssize_t ret = 0;
	struct airoha_eth *eth = glb_eth;
	char *debugfs_buffer;
	debugfs_buffer=kmalloc(buf_size,GFP_KERNEL);
   
	if(!debugfs_buffer)
		return -ENOMEM;
	/* CID:902641 */
    index = snprintf(debugfs_buffer, buf_size, "PSE_DROP_CNT:\n");

    for(i = 0; i < PSE_PORT_NUM; i++)
    {
        if (index < buf_size)
            index += snprintf(debugfs_buffer+index, buf_size - index, "P%i:0x%08x  ", i, airoha_fe_rr(eth,REG_FE_PSE_DROP_CNT(i)));

        if( (i%4) == 3 ){
            if (index < buf_size)
                index += snprintf(debugfs_buffer+index, buf_size - index, "\n");
        }
    }

    if (index < buf_size)
        index += snprintf(debugfs_buffer+index, buf_size - index, "\nPSE_IQ_CNT:    P0:0x%02x  P1:0x%02x  P2:0x%02x  P3:0x%02x  P4:0x%02x  P5:0x%02x\n"
            , ((airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA0)>>16) & 0x7fff), ((airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA1)>>16) & 0x7fff)
            , ((airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA2)>>16) & 0x7fff), ((airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA3)>>16) & 0x7fff)
            , ((airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA4)>>16) & 0x7fff), ((airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA5)>>16) & 0x7fff));

    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "               P6:0x%02x  P7:0x%02x  P8:0x%02x  P9:0x%02x\n"
            , ((airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA6)>>16) & 0x7fff), ((airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA7)>>16) & 0x7fff)
            , ((airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA8)>>16) & 0x7fff), ((airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA9)>>16) & 0x7fff));

    if (index < buf_size)
        index += snprintf(debugfs_buffer+index, buf_size - index, "PSE_OQ_CNT:    P0:0x%02x  P1:0x%02x  P2:0x%02x  P3:0x%02x  P4:0x%02x  P5:0x%02x\n"
            , (airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA0) & 0x7fff), (airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA1) & 0x7fff)
            , (airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA2) & 0x7fff), (airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA3) & 0x7fff)
            , (airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA4) & 0x7fff), (airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA5) & 0x7fff));

    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "               P6:0x%02x  P7:0x%02x  P8:0x%02x  P9:0x%02x\n"
            , (airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA6) & 0x7fff), (airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA7) & 0x7fff)
            , (airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA8) & 0x7fff), (airoha_fe_rr(eth,REG_FE_PSE_PORT_Q_USE_STA9) & 0x7fff));

    if (index < buf_size)
        index += snprintf(debugfs_buffer+index, buf_size - index, "PSE_SHARE_BUF:  SHARED_USED_CNT:0x%04x  SHARED_FREE_CNT:0x%04x\n"
            , ((airoha_fe_rr(eth,REG_FE_PSE_SHARE_BUF_STA)>>16) & 0x7fff), (airoha_fe_rr(eth,REG_FE_PSE_SHARE_BUF_STA) & 0x7fff));

    //FE CNT //BROWN
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "\nCDMA1_TX_OK_CNT           (0x%08x) = 0x%08x\n", CDMA1_TX_OK_CNT, airoha_fe_rr(eth,CDMA1_TX_OK_CNT));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "CDMA1_RXCPU_OK_CNT        (0x%08x) = 0x%08x\n", CDMA1_RXCPU_OK_CNT, airoha_fe_rr(eth,CDMA1_RXCPU_OK_CNT));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "CDMA1_RXHWF_OK_CNT        (0x%08x) = 0x%08x\n", CDMA1_RXHWF_OK_CNT, airoha_fe_rr(eth,CDMA1_RXHWF_OK_CNT));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "CDMA1_RXHWF_FAST_OK_CNT   (0x%08x) = 0x%08x\n", CDMA1_RXHWF_FAST_ALL_CNT, airoha_fe_rr(eth,CDMA1_RXHWF_FAST_ALL_CNT));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "CDMA1_RXCPU_DROP_CNT      (0x%08x) = 0x%08x\n", CDMA1_RXCPU_DROP_CNT, airoha_fe_rr(eth,CDMA1_RXCPU_DROP_CNT));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "CDMA1_RXHWF_DROP_CNT      (0x%08x) = 0x%08x\n", CDMA1_RXHWF_DROP_CNT, airoha_fe_rr(eth,CDMA1_RXHWF_DROP_CNT));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "CDMA1_RXHWF_FAST_DROP_CNT (0x%08x) = 0x%08x\n", CDMA1_RXHWF_FAST_DROP_CNT, airoha_fe_rr(eth,CDMA1_RXHWF_FAST_DROP_CNT));

    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "\nGDMA1_TX_GET_CNT          (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_GET_PKT_CNT(1) , airoha_fe_rr(eth,REG_FE_GDM_TX_GET_PKT_CNT(1)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA1_TX_OK_CNT_L         (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_OK_PKT_CNT_L(1) , airoha_fe_rr(eth,REG_FE_GDM_TX_OK_PKT_CNT_L(1)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA1_TX_OK_CNT_H         (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_OK_PKT_CNT_H(1), airoha_fe_rr(eth,REG_FE_GDM_TX_OK_PKT_CNT_H(1)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA1_TX_DROP_CNT         (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_ETH_DROP_CNT(1), airoha_fe_rr(eth,REG_FE_GDM_TX_ETH_DROP_CNT(1)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA1_RX_OK_CNT           (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_OK_PKT_CNT_L(1) , airoha_fe_rr(eth,REG_FE_GDM_RX_OK_PKT_CNT_L(1)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA1_RX_FC_DROP_CNT      (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_FC_DROP_CNT(1), airoha_fe_rr(eth,REG_FE_GDM_RX_FC_DROP_CNT(1)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA1_RX_RC_DROP_CNT      (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_RC_DROP_CNT(1), airoha_fe_rr(eth,REG_FE_GDM_RX_RC_DROP_CNT(1)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA1_RX_OVER_DROP_CNT    (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_OVERFLOW_DROP_CNT(1), airoha_fe_rr(eth,REG_FE_GDM_RX_OVERFLOW_DROP_CNT(1)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA1_RX_ERROR_DROP_CNT   (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_ERROR_DROP_CNT(1), airoha_fe_rr(eth,REG_FE_GDM_RX_ERROR_DROP_CNT(1)));

    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "\nCDMA2_TX_OK_CNT           (0x%08x) = 0x%08x\n", CDMA2_TX_OK_CNT, airoha_fe_rr(eth,CDMA2_TX_OK_CNT));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "CDMA2_RXCPU_OK_CNT        (0x%08x) = 0x%08x\n", CDMA2_RXCPU_OK_CNT, airoha_fe_rr(eth,CDMA2_RXCPU_OK_CNT));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "CDMA2_RXHWF_OK_CNT        (0x%08x) = 0x%08x\n", CDMA2_RXHWF_OK_CNT, airoha_fe_rr(eth,CDMA2_RXHWF_OK_CNT));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "CDMA2_RXHWF_FAST_OK_CNT   (0x%08x) = 0x%08x\n", CDMA2_RXHWF_FAST_ALL_CNT, airoha_fe_rr(eth,CDMA2_RXHWF_FAST_ALL_CNT));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "CDMA2_RXCPU_DROP_CNT      (0x%08x) = 0x%08x\n", CDMA2_RXCPU_DROP_CNT, airoha_fe_rr(eth,CDMA2_RXCPU_DROP_CNT));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "CDMA2_RXHWF_DROP_CNT      (0x%08x) = 0x%08x\n", CDMA2_RXHWF_DROP_CNT, airoha_fe_rr(eth,CDMA2_RXHWF_DROP_CNT));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "CDMA2_RXHWF_FAST_DROP_CNT (0x%08x) = 0x%08x\n", CDMA2_RXHWF_FAST_DROP_CNT, airoha_fe_rr(eth,CDMA2_RXHWF_FAST_DROP_CNT));

    //GDM2
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "\nGDMA2_TX_GET_CNT          (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_GET_PKT_CNT(2) , airoha_fe_rr(eth,REG_FE_GDM_TX_GET_PKT_CNT(2)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA2_TX_OK_CNT_L         (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_OK_PKT_CNT_L(2) , airoha_fe_rr(eth,REG_FE_GDM_TX_OK_PKT_CNT_L(2)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA2_TX_OK_CNT_H         (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_OK_PKT_CNT_H(2), airoha_fe_rr(eth,REG_FE_GDM_TX_OK_PKT_CNT_H(2)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA2_TX_DROP_CNT         (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_ETH_DROP_CNT(2), airoha_fe_rr(eth,REG_FE_GDM_TX_ETH_DROP_CNT(2)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA2_RX_OK_CNT           (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_OK_PKT_CNT_L(2) , airoha_fe_rr(eth,REG_FE_GDM_RX_OK_PKT_CNT_L(2)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA2_RX_FC_DROP_CNT      (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_FC_DROP_CNT(2), airoha_fe_rr(eth,REG_FE_GDM_RX_FC_DROP_CNT(2)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA2_RX_RC_DROP_CNT      (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_RC_DROP_CNT(2), airoha_fe_rr(eth,REG_FE_GDM_RX_RC_DROP_CNT(2)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA2_RX_OVER_DROP_CNT    (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_OVERFLOW_DROP_CNT(2), airoha_fe_rr(eth,REG_FE_GDM_RX_OVERFLOW_DROP_CNT(2)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA2_RX_ERROR_DROP_CNT   (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_ERROR_DROP_CNT(2), airoha_fe_rr(eth,REG_FE_GDM_RX_ERROR_DROP_CNT(2)));

    //GDM3
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "\nGDMA3_TX_GET_CNT          (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_GET_PKT_CNT(3) , airoha_fe_rr(eth,REG_FE_GDM_TX_GET_PKT_CNT(3)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA3_TX_OK_CNT_L         (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_OK_PKT_CNT_L(3) , airoha_fe_rr(eth,REG_FE_GDM_TX_OK_PKT_CNT_L(3)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA3_TX_OK_CNT_H         (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_OK_PKT_CNT_H(3), airoha_fe_rr(eth,REG_FE_GDM_TX_OK_PKT_CNT_H(3)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA3_TX_DROP_CNT         (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_ETH_DROP_CNT(3), airoha_fe_rr(eth,REG_FE_GDM_TX_ETH_DROP_CNT(3)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA3_RX_OK_CNT           (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_OK_PKT_CNT_L(3) , airoha_fe_rr(eth,REG_FE_GDM_RX_OK_PKT_CNT_L(3)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA3_RX_FC_DROP_CNT      (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_FC_DROP_CNT(3), airoha_fe_rr(eth,REG_FE_GDM_RX_FC_DROP_CNT(3)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA3_RX_RC_DROP_CNT      (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_RC_DROP_CNT(3), airoha_fe_rr(eth,REG_FE_GDM_RX_RC_DROP_CNT(3)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA2_RX_OVER_DROP_CNT    (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_OVERFLOW_DROP_CNT(3), airoha_fe_rr(eth,REG_FE_GDM_RX_OVERFLOW_DROP_CNT(3)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA3_RX_ERROR_DROP_CNT   (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_ERROR_DROP_CNT(3), airoha_fe_rr(eth,REG_FE_GDM_RX_ERROR_DROP_CNT(3)));

    //GDM4
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "\nGDMA4_TX_GET_CNT          (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_GET_PKT_CNT(4) , airoha_fe_rr(eth,REG_FE_GDM_TX_GET_PKT_CNT(4)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA4_TX_OK_CNT_L         (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_OK_PKT_CNT_L(4) , airoha_fe_rr(eth,REG_FE_GDM_TX_OK_PKT_CNT_L(4)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA4_TX_OK_CNT_H         (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_OK_PKT_CNT_H(4), airoha_fe_rr(eth,REG_FE_GDM_TX_OK_PKT_CNT_H(4)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA4_TX_DROP_CNT         (0x%08x) = 0x%08x\n", REG_FE_GDM_TX_ETH_DROP_CNT(4), airoha_fe_rr(eth,REG_FE_GDM_TX_ETH_DROP_CNT(4)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA4_RX_OK_CNT           (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_OK_PKT_CNT_L(4) , airoha_fe_rr(eth,REG_FE_GDM_RX_OK_PKT_CNT_L(4)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA4_RX_FC_DROP_CNT      (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_FC_DROP_CNT(4), airoha_fe_rr(eth,REG_FE_GDM_RX_FC_DROP_CNT(4)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA4_RX_RC_DROP_CNT      (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_RC_DROP_CNT(4), airoha_fe_rr(eth,REG_FE_GDM_RX_RC_DROP_CNT(4)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA4_RX_OVER_DROP_CNT    (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_OVERFLOW_DROP_CNT(4), airoha_fe_rr(eth,REG_FE_GDM_RX_OVERFLOW_DROP_CNT(4)));
    if (index < buf_size)
	    index += snprintf(debugfs_buffer+index, buf_size - index, "GDMA4_RX_ERROR_DROP_CNT   (0x%08x) = 0x%08x\n", REG_FE_GDM_RX_ERROR_DROP_CNT(4), airoha_fe_rr(eth,REG_FE_GDM_RX_ERROR_DROP_CNT(4)));

    if (index > buf_size)
	{
		index = buf_size;
	}

	ret = simple_read_from_buffer(buf, count, ppos, debugfs_buffer, index);
	kfree(debugfs_buffer);

    return ret;
}

static void airoha_debugfs_print_tuple(struct seq_file *m,
					   void *src_addr, void *dest_addr,
					   u16 *src_port, u16 *dest_port,
					   bool ipv6)
{
	__be32 n_addr[IPV6_ADDR_WORDS];

	if (ipv6) {
		ipv6_addr_cpu_to_be32(n_addr, src_addr);
		seq_printf(m, "%pI6", n_addr);
	} else {
		seq_printf(m, "%pI4h", src_addr);
	}
	if (src_port)
		seq_printf(m, ":%d", *src_port);

	seq_puts(m, "->");

	if (ipv6) {
		ipv6_addr_cpu_to_be32(n_addr, dest_addr);
		seq_printf(m, "%pI6", n_addr);
	} else {
		seq_printf(m, "%pI4h", dest_addr);
	}
	if (dest_port)
		seq_printf(m, ":%d", *dest_port);
}

static int airoha_ppe_debugfs_foe_flow_show(struct seq_file *m, void *private)
{
	struct airoha_flow_table_entry *e;
	struct hlist_node *n;
	struct airoha_ppe *ppe = glb_eth->ppe;
	int i;

	static const char *const ppe_type_str[] = {
		[PPE_PKT_TYPE_IPV4_HNAPT] = "IPv4 5T",
		[PPE_PKT_TYPE_IPV4_ROUTE] = "IPv4 3T",
		[PPE_PKT_TYPE_BRIDGE] = "L2B",
		[PPE_PKT_TYPE_IPV4_DSLITE] = "DS-LITE",
		[PPE_PKT_TYPE_IPV6_ROUTE_3T] = "IPv6 3T",
		[PPE_PKT_TYPE_IPV6_ROUTE_5T] = "IPv6 5T",
		[PPE_PKT_TYPE_IPV6_6RD] = "6RD",
	};

	static const char *const ppe_magic[] = {
		[PON] = "PON",
		[ETH2] = "ETH2",
		[LAN1] = "LAN1",
		[LAN2] = "LAN2",
		[LAN3] = "LAN3",
		[LAN4] = "LAN4",
	};

	static const char *const ppe_type[] = {
		[FLOW_TYPE_L4] = "FLOW_TYPE_L4",
		[FLOW_TYPE_L2] = "FLOW_TYPE_L2",
		[FLOW_TYPE_L2_SUBFLOW] = "FLOW_TYPE_L2_SUBFLOW",
	};

	for (i = 0; i < PPE_NUM_ENTRIES; i++) {
		hlist_for_each_entry_safe(e, n, &ppe->foe_flow[i], list) {
			const char *type_str = "UNKNOWN";
			void *src_addr = NULL, *dest_addr = NULL;
			u16 *src_port = NULL, *dest_port = NULL;
			bool ipv6 = false;
			
			int type = FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, e->data.ib1);
			if (type < ARRAY_SIZE(ppe_type_str) && ppe_type_str[type])
				type_str = ppe_type_str[type];
			seq_printf(m, "hash 0x%04x: %7s", e->hash, type_str);
			
			switch (type) {
			case PPE_PKT_TYPE_IPV4_HNAPT:
			case PPE_PKT_TYPE_IPV4_DSLITE:
				src_port = &e->data.ipv4.orig_tuple.src_port;
				dest_port = &e->data.ipv4.orig_tuple.dest_port;
				fallthrough;
			case PPE_PKT_TYPE_IPV4_ROUTE:
				src_addr = &e->data.ipv4.orig_tuple.src_ip;
				dest_addr = &e->data.ipv4.orig_tuple.dest_ip;
				break;
			case PPE_PKT_TYPE_IPV6_ROUTE_5T:
				src_port = &e->data.ipv6.src_port;
				dest_port = &e->data.ipv6.dest_port;
				fallthrough;
			case PPE_PKT_TYPE_IPV6_ROUTE_3T:
			case PPE_PKT_TYPE_IPV6_6RD:
				src_addr = &e->data.ipv6.src_ip;
				dest_addr = &e->data.ipv6.dest_ip;
				ipv6 = true;
				break;
			default:
				break;
			}

			if (src_addr && dest_addr) {
				seq_puts(m, " orig=");
				airoha_debugfs_print_tuple(m, src_addr, dest_addr,
							       src_port, dest_port, ipv6);
			}

			switch (type) {
			case PPE_PKT_TYPE_IPV4_HNAPT:
			case PPE_PKT_TYPE_IPV4_DSLITE:
				src_port = &e->data.ipv4.new_tuple.src_port;
				dest_port = &e->data.ipv4.new_tuple.dest_port;
				fallthrough;
			case PPE_PKT_TYPE_IPV4_ROUTE:
				src_addr = &e->data.ipv4.new_tuple.src_ip;
				dest_addr = &e->data.ipv4.new_tuple.dest_ip;
				seq_puts(m, " new=");
				airoha_debugfs_print_tuple(m, src_addr, dest_addr,
							       src_port, dest_port,
							       ipv6);
				break;
			default:
				break;
			}
			seq_printf(m, "  %s e_magic:%4s tx_modified:%d ingress_dev_idx:%u\n", 
				ppe_type[e->type], ppe_magic[e->e_magic], e->tx_modified, e->ingress_dev_idx);
		}
	}

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(airoha_ppe_debugfs_foe_flow);

static ssize_t airoha_fast_threshold_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char val_string[32];
    unsigned int value = 0;
    char unit = 0;
    int ret = 0, len = 0;

    if (count > sizeof(val_string) - 1)
        return -EINVAL;

    if (copy_from_user(val_string, buf, count))
        return -EFAULT;

    val_string[count] = '\0';

    // Remove leading/trailing whitespace
    len = strlen(val_string);
    while (len > 0 && isspace(val_string[len - 1])) {
        val_string[len - 1] = '\0';
        len--;
    }

    // Try to parse value and optional unit
    ret = sscanf(val_string, "%10u%c", &value, &unit);
    if (ret == 1) {
        // Only number, default unit is Mbps
        fast_path_speed_threshold = value;
    } else if (ret == 2) {
        if (unit == 'M' || unit == 'm') {
            fast_path_speed_threshold = value;
        } else if (unit == 'G' || unit == 'g') {
            fast_path_speed_threshold = value * 1000;
        } else {
            printk("Invalid unit! The Value is int and the uint is M or G.\n");
            return -EINVAL;
        }
    } else {
        printk("Invalid input format! Example: 100M or 2G\n");
        return -EINVAL;
    }

    printk("fast_path_speed_threshold has been set to %u Mbps\n", fast_path_speed_threshold);

    return count;
}

static ssize_t airoha_fast_threshold_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	int index = 0;
    ssize_t buf_size = 64; // buffer size, can be adjusted as needed
    ssize_t ret = 0;
    char *debugfs_buffer;

    debugfs_buffer = kmalloc(buf_size, GFP_KERNEL);
    if (!debugfs_buffer)
        return -ENOMEM;

    index = snprintf(debugfs_buffer, buf_size, "fast_path_speed_threshold = %u Mbps\n", fast_path_speed_threshold);
	if (index < 0)
	{
		printk("debugfs_buffer len is invalid.\n");
	}

    ret = simple_read_from_buffer(buf, count, ppos, debugfs_buffer, index);

    kfree(debugfs_buffer);

    return ret;
}

static ssize_t airoha_packet_transparent_mode_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char input_str[64];
	char fuc_str[16];
	int ret = 0;

	if (count >= sizeof(input_str))
		return -EINVAL;
	if (copy_from_user(input_str, buf, count))
		return -EFAULT;
	input_str[count] = '\0';
	if(sscanf(input_str, "%15s",fuc_str) < 1){
		printk("\n Help: echo [enable/disable] \n");
		return -EINVAL;
	}
	
	if(!strcmp(fuc_str,"enable")){
		packet_is_transparent_mode = 1;
		ret = 0;
		printk("\n packet_is_transparent_mode:%d \n",packet_is_transparent_mode);
	}
	else if(!strcmp(fuc_str,"disable")){
		packet_is_transparent_mode = 0;
		ret = 0;
		printk("\n packet_is_transparent_mode:%d \n",packet_is_transparent_mode);
	}
	else{
		printk("\n Help: [enable/disable] \n");
		return -EINVAL;
	}
		
	return count;   
}

static ssize_t airoha_packet_transparent_mode_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	int index = 0;
    ssize_t buf_size = 64; // buffer size, can be adjusted as needed
    ssize_t ret = 0;
    char *debugfs_buffer;

    debugfs_buffer = kmalloc(buf_size, GFP_KERNEL);
    if (!debugfs_buffer)
        return -ENOMEM;

    index += scnprintf(debugfs_buffer + index, buf_size - index,
                      "packet_is_transparent_mode enable: %d\n", packet_is_transparent_mode);

    ret = simple_read_from_buffer(buf, count, ppos, debugfs_buffer, index);

    kfree(debugfs_buffer);

    return ret;
}

static ssize_t airoha_switch_set_mfc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char input_str[64];
	char fuc_str[16];
	int ret = 0;

	if (count >= sizeof(input_str))
		return -EINVAL;
	if (copy_from_user(input_str, buf, count))
		return -EFAULT;
	input_str[count] = '\0';
	if (sscanf(input_str, "%15s", fuc_str) < 1) {
		printk("\n Help: echo [enable/disable] \n");
		return -EINVAL;
	}

	if (!strcmp(fuc_str, "enable")) {
		switch_set_mfc_enable = 1;
		ret = 0;
		printk("\n switch_set_mfc_enable:%d \n", switch_set_mfc_enable);
	} else if (!strcmp(fuc_str, "disable")) {
		switch_set_mfc_enable = 0;
		ret = 0;
		printk("\n switch_set_mfc_enable:%d \n", switch_set_mfc_enable);
	} else {
		printk("\n Help: [enable/disable] \n");
		return -EINVAL;
	}

	return count;
}

static ssize_t airoha_switch_set_mfc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	int index = 0;
	ssize_t buf_size = 64; // buffer size, can be adjusted as needed
	ssize_t ret = 0;
	char *debugfs_buffer;

	debugfs_buffer = kmalloc(buf_size, GFP_KERNEL);
	if (!debugfs_buffer)
		return -ENOMEM;

	index += scnprintf(debugfs_buffer + index, buf_size - index, "switch_set_mfc_enable: %d\n", switch_set_mfc_enable);

	ret = simple_read_from_buffer(buf, count, ppos, debugfs_buffer, index);

	kfree(debugfs_buffer);

	return ret;
}

static ssize_t shrink_table_dump_write_proc(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct hwnat_shrink_field shrinkField;
	struct sockaddr_in6 ip6;
	uint8_t val_string[128], cmd[16];
	uint8_t param1[16], param2[48], param3[48] ;
	//int ret = 0;
	int num_parsed;

	memset(&shrinkField, 0, sizeof(shrinkField));
	shrinkField.foe_idx = 16383;
	
	if (count > sizeof(val_string) - 1)
		return -EINVAL ;

	memset(&shrinkField, 0, sizeof(shrinkField));
	memset(&ip6, 0, sizeof(ip6));

	if (copy_from_user(val_string, buf, count))
		return -EFAULT ;

	val_string[count] = '\0';

	num_parsed = sscanf(val_string, "%15s %15s %47s %47s", cmd, param1, param2, param3);
	
	if (num_parsed < 1) {
		return -EINVAL;
	}
	printk("cmd:%s, param1:%s, param2:%s, param3:%s\n", cmd, param1, param2, param3);

	if(!strcmp(cmd, "dump")) {
		ppe_dump_shrink_table();
	}
#if 0
	else if(!strcmp(cmd, "timeout")) {
		if (num_parsed < 2) {
			printk("timeout: missing parameter.\n");
			return -EINVAL;
		}
		timeOutVal = atoi(param1) * 100;
	} else if(!strcmp(cmd, "clear")) {
		InitShrinkTable();
	}
	else if(!strcmp(cmd, "set")) {
		/* 
		   echo set smac [0~15]  00:aa:bb:01:23:01 > /sys/kernel/debug/airoha_eth/dp_api/shrink_table_debug
		   echo set ipv4 [0~15]  192.85.20.1 192.168.30.1 > /sys/kernel/debug/airoha_eth/dp_api/shrink_table_debug
		   echo set ipv6 [0~15]  2000::1  2000::2 > /sys/kernel/debug/airoha_eth/dp_api/shrink_table_debug
		*/
		if (num_parsed < 2) {
			printk("set: missing parameter.\n");
			return -EINVAL;
		}
		if(!strcmp(param1, "smac")) {
			if (num_parsed < 3) {
				printk("set smac: missing mac address.\n");
				return -EINVAL;
			}
			str_to_mac(shrinkField.smac, (char *)param2);		 
			ret = find_and_update_shrink_table(PPE_UPDMEM_SEL_SMAC, &shrinkField);
		} else if(!strcmp(param1, "ipv4")) {
			if (num_parsed < 4) {
				printk("set ipv4: missing ip addresses.\n");
				return -EINVAL;
			}
			str_to_ip((unsigned long *)&shrinkField.eg_ipv4[1], (char *)param2);
			printk("shrinkField.eg_ipv4:%X\n", shrinkField.eg_ipv4[1]);
			str_to_ip((unsigned long *)&shrinkField.eg_ipv4[0], (char *)param3);
			printk("shrinkField.eg_ipv4:%X\n", shrinkField.eg_ipv4[0]);
			find_and_update_shrink_table(PPE_UPDMEM_SEL_IPv4, &shrinkField);
		} else if(!strcmp(param1, "ipv6")) {
			if (num_parsed < 4) {
				printk("set ipv6: missing ip addresses.\n");
				return -EINVAL;
			}
			ret = inet_pton6((char *)param2, (unsigned char *)&ip6.sin6_addr.s6_addr[0]);
			shrinkField.eg_ipv6[4] = ntohl(*((unsigned int *)ip6.sin6_addr.s6_addr));
			shrinkField.eg_ipv6[5] = ntohl(*((unsigned int *)(ip6.sin6_addr.s6_addr + 4)));
			shrinkField.eg_ipv6[6] = ntohl(*((unsigned int *)(ip6.sin6_addr.s6_addr + 8)));
			shrinkField.eg_ipv6[7] = ntohl(*((unsigned int *)(ip6.sin6_addr.s6_addr + 12)));
			printk("eg_sipv6:%X:%X:%X:%X\n", shrinkField.eg_ipv6[4], shrinkField.eg_ipv6[5], shrinkField.eg_ipv6[6], shrinkField.eg_ipv6[7]);
			ret = inet_pton6((char *)param3, (unsigned char *)&ip6.sin6_addr.s6_addr[0]);
			shrinkField.eg_ipv6[0] = ntohl(*((unsigned int *)ip6.sin6_addr.s6_addr));
			shrinkField.eg_ipv6[1] = ntohl(*((unsigned int *)(ip6.sin6_addr.s6_addr + 4)));
			shrinkField.eg_ipv6[2] = ntohl(*((unsigned int *)(ip6.sin6_addr.s6_addr + 8)));
			shrinkField.eg_ipv6[3] = ntohl(*((unsigned int *)(ip6.sin6_addr.s6_addr + 12)));
			printk("eg_dipv6:%X:%X:%X:%X\n", shrinkField.eg_ipv6[0], shrinkField.eg_ipv6[1], shrinkField.eg_ipv6[2], shrinkField.eg_ipv6[3]);
			find_and_update_shrink_table(PPE_UPDMEM_SEL_IPv6, &shrinkField);
		}
	}
#endif
	return count ;
}

static ssize_t airoha_pon_serdes_mode_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	char input_str[32];
	int ret, val = 0;

	if (count >= sizeof(input_str))
		return -EINVAL;
	if (copy_from_user(input_str, buf, count))
		return -EFAULT;
	
	input_str[count] = '\0';
	ret = kstrtoint(input_str, 10, &val);
	if(ret){
		return ret;
	}
	if (val < 0 || val > 1){
		return -EINVAL;
	}
	
	g_pon_serdes_eth = val;
	
	return count;   
}

static ssize_t airoha_pon_serdes_mode_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	int index = 0;
    ssize_t buf_size = 64; // buffer size, can be adjusted as needed
    ssize_t ret = 0;
    char *debugfs_buffer;

    debugfs_buffer = kmalloc(buf_size, GFP_KERNEL);
    if (!debugfs_buffer)
        return -ENOMEM;

    index += scnprintf(debugfs_buffer + index, buf_size - index,
                      "g_pon_serdes_eth: %s\n", g_pon_serdes_eth?"ether":"pon");

    ret = simple_read_from_buffer(buf, count, ppos, debugfs_buffer, index);

    kfree(debugfs_buffer);

    return ret;
}

static const struct file_operations airoha_dp_api_debugfs_rxring_limit_value_fops = {
    .write = airoha_rxring_limit_value_write,
};

static const struct file_operations airoha_dp_api_debugfs_gemport_ratelimit_value_fops = {
    .write = airoha_gemport_ratelimit_value_write,
};

static const struct file_operations airoha_dp_api_debugfs_lan_ratelimit_value_fops = {
    .write = airoha_lan_ratelimit_value_write,
};

static const struct file_operations airoha_dp_api_debugfs_fe_debug_reg_fops = {
    .read = airoha_fe_debug_reg_read,
};

static const struct file_operations airoha_dp_api_debugfs_fast_threshold_fops = {
    .read = airoha_fast_threshold_read,
	.write = airoha_fast_threshold_write,
};

static const struct file_operations airoha_dp_api_debugfs_packet_transparent_mode_fops = {
    .write = airoha_packet_transparent_mode_write,
	.read = airoha_packet_transparent_mode_read,
};

static const struct file_operations airoha_dp_api_debugfs_switch_set_mfc_fops = {
    .write = airoha_switch_set_mfc_write,
	.read = airoha_switch_set_mfc_read,
};

static const struct file_operations airoha_dp_api_debugfs_shrink_table_debug_fops = {
	.write = shrink_table_dump_write_proc,
};
static const struct file_operations airoha_dp_api_debugfs_pon_serdes_mode_fops = {
    .write = airoha_pon_serdes_mode_write,
	.read = airoha_pon_serdes_mode_read,
};

extern atomic_t fe_core_reset_count;

static ssize_t airoha_fe_cr_cnt_read(struct file *file, char __user *buf,
				      size_t count, loff_t *ppos)
{
	ssize_t buf_size = 32;
	ssize_t ret = 0;
	char *debugfs_buffer;
	int index = 0;

	debugfs_buffer = kmalloc(buf_size, GFP_KERNEL);
	if (!debugfs_buffer)
		return -ENOMEM;

	index += scnprintf(debugfs_buffer + index, buf_size - index,
			   "%u\n", atomic_read(&fe_core_reset_count));

	ret = simple_read_from_buffer(buf, count, ppos, debugfs_buffer, index);

	kfree(debugfs_buffer);

	return ret;
}

static const struct file_operations airoha_dp_api_debugfs_fe_cr_cnt_fops = {
	.read    = airoha_fe_cr_cnt_read,
	.llseek  = default_llseek,
};

int airoha_dp_api_debugfs_init(struct airoha_eth *eth)
{
	struct dentry *root;

	root = debugfs_create_dir("dp_api", eth->debugfs_dir);
	debugfs_create_file("rxring_limit_value", 0644, root, eth,
			    &airoha_dp_api_debugfs_rxring_limit_value_fops);
	debugfs_create_file("gemport_ratelimit", 0644, root, eth,
			    &airoha_dp_api_debugfs_gemport_ratelimit_value_fops);					
	debugfs_create_file("lan_ratelimit", 0644, root, eth,
			    &airoha_dp_api_debugfs_lan_ratelimit_value_fops);	
	debugfs_create_file("fe_debug_reg", 0644, root, eth,
			    &airoha_dp_api_debugfs_fe_debug_reg_fops);			
	debugfs_create_file("foe_flow", 0444, root, eth,
			    &airoha_ppe_debugfs_foe_flow_fops);							
	debugfs_create_file("fast_threshold", 0644, root, eth,
			    &airoha_dp_api_debugfs_fast_threshold_fops);	
	debugfs_create_file("packet_transparent_mode", 0644, root, NULL,
                &airoha_dp_api_debugfs_packet_transparent_mode_fops);
	debugfs_create_file("switch_set_mfc_enable", 0644, root, NULL,
				&airoha_dp_api_debugfs_switch_set_mfc_fops);
	debugfs_create_file("shrink_table_debug", 0644, root, NULL,
				&airoha_dp_api_debugfs_shrink_table_debug_fops);
	debugfs_create_file("pon_serdes_mode", 0644, root, NULL,
				&airoha_dp_api_debugfs_pon_serdes_mode_fops);
	debugfs_create_file("fe_cr_cnt", 0444, root, NULL,
				&airoha_dp_api_debugfs_fe_cr_cnt_fops);

	return 0;
}

