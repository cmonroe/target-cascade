// SPDX-License-Identifier: GPL-2.0
/*
 * ASoC platform driver for the Airoha EN7581 telephony PCM engine
 * (descriptor-ring TDM DMA at 0x1fbd0000, "PCM1").
 *
 * The engine is the PCM highway master for an external SLIC codec
 * (Si32184/Si32282). It exposes two unidirectional DAIs so the sound
 * card enumerates a playback-only PCM device 0, a capture-only PCM
 * device 1, exposing plughw:0,0 and plughw:0,1.
 *
 * The DMA delivers each channel into its own sub-buffer at a global
 * per-channel stride (CHBFOSR), so the PCM devices are noninterleaved:
 * channel n occupies the n-th 1/channels slice of the ALSA buffer and
 * each descriptor advances one period within every slice.
 *
 * DT binding:
 *	voip_pcm: pcm@1fbd0000 {
 *		compatible = "airoha,en7581-pcm";
 *		reg = <0x0 0x1fbd0000 0x0 0x1000>;
 *		interrupts = <GIC_SPI 27 IRQ_TYPE_LEVEL_HIGH>;
 *		resets = <&scuclk EN7581_PCM1_RST>;
 *		airoha,chip-scu = <&chip_scu>;
 *		airoha,np-scu = <&scuclk>;
 *	};
 */

#include <linux/bitfield.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/reset.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>

#define REG_PICR			0x00
#define  PICR_PROBE_SEL			GENMASK(30, 28)
#define  PICR_CFG_VALID			BIT(26)
#define  PICR_LPBK_EN			BIT(25)
#define  PICR_SWRST_N			BIT(24)
#define  PICR_FC_INT_CFG		GENMASK(22, 18)
#define  PICR_BYTE_ORDER_BE		BIT(17)
#define  PICR_BIT_ORDER_MSB		BIT(16)
#define  PICR_ONEBIT_DELAY		BIT(12)
#define  PICR_DATA_EDGE_FALL		BIT(11)
#define  PICR_FS_EDGE_FALL		BIT(10)
#define  PICR_FS_LEN			GENMASK(9, 8)
#define  PICR_FS_LEN_16			3
#define  PICR_SFC_CS_DECODE		BIT(5)
#define  PICR_SAMPLE_16K		BIT(4)
#define  PICR_BIT_CLK			GENMASK(3, 1)
#define  PICR_BIT_CLK_2048K		3
#define  PICR_MSTDIS			BIT(0)

#define REG_PTTSCR(n)			((n) < 4 ? 0x04 + (n) * 4 : 0x48 + ((n) - 4) * 4)
#define REG_PRTSCR(n)			((n) < 4 ? 0x14 + (n) * 4 : 0x78 + ((n) - 4) * 4)
#define  TSCR_SLOT1_BW16		BIT(28)
#define  TSCR_SLOT1_START		GENMASK(25, 16)
#define  TSCR_SLOT0_BW16		BIT(12)
#define  TSCR_SLOT0_START		GENMASK(9, 0)

#define REG_ISR				0x24
#define REG_IMR				0x28
#define  INT_SLIC			BIT(14)
#define  INT_AHB_BUS_ERR		BIT(8)
#define  INT_RBUF_OVERRUN		BIT(7)
#define  INT_TBUF_UNDERRUN		BIT(6)
#define  INT_RDESC_END			BIT(5)
#define  INT_TDESC_END			BIT(4)
#define  INT_RDESC_UPDATE		BIT(3)
#define  INT_TDESC_UPDATE		BIT(2)
/*
 * TX buffer underrun is a non-event: an idle line legitimately runs the
 * ring dry and the engine just transmits idle until the next arm+kick
 * (aos masks every TX interrupt for the same reason).
 */
#define  INT_ERRORS			(INT_AHB_BUS_ERR | INT_RBUF_OVERRUN)

#define REG_TPDR			0x2c
#define REG_RPDR			0x30
#define REG_TDRBAR			0x34
#define REG_RDRBAR			0x38
#define REG_TRDRSR			0x3c
#define REG_TRDCR			0x40
#define  TRDCR_RXDMA_EN			BIT(1)
#define  TRDCR_TXDMA_EN			BIT(0)
#define REG_CHBFOSR			0xa8
#define REG_DCHENR			0xac

#define AN7581_PCM_NUM_DESC		15
#define AN7581_PCM_DESC_STRIDE_DW	3
#define AN7581_PCM_MAX_FRAMES		1020
#define AN7581_PCM_MAX_CHANNELS		2
#define AN7581_PCM_SLOTS		16
#define AN7581_PCM_BOUNCE_BYTES		(AN7581_PCM_MAX_FRAMES * 2 * \
					 AN7581_PCM_MAX_CHANNELS)

/*
 * Slot n carries channel n as a 16-bit sample starting at bit n*16. The
 * ProSLIC timeslot in the HAL is programmed to the same offset.
 */
#define AN7581_PCM_SLOT_OFF		0

/* chip-scu PCM clock output/source; 0xc01 is the vendor-proven value */
#define CHIP_SCU_PCM_CLK		0x1d0
#define  CHIP_SCU_PCM_CLK_CFG		0xc01

/* np-scu SSR3: interface mode selects */
#define NP_SCU_SSR3			0x94
#define  SSR3_PCM_SPI_SEL_SFC2		BIT(5)
#define  SSR3_PCM1_ISI_EN		BIT(0)

struct an7581_pcm_hwdesc {
	u32 status;
#define DESC_OWN			BIT(31)
#define DESC_SAMPLE_SIZE		GENMASK(9, 0)
	u32 chan_valid;
	u32 buf_addr;
} __packed;

/*
 * The 15-entry hardware descriptor ring is decoupled from the ALSA buffer
 * through dedicated per-descriptor bounce buffers (desc i <-> bounce i),
 * mirroring the vendor arht-voip pcmdriver model. The engine's internal
 * ring pointer survives DMA disable/enable, so hw_idx (the reclaim cursor)
 * must persist across stream stop/start and is only reset by block reset.
 */
struct an7581_pcm_stream {
	struct snd_pcm_substream *substream;
	struct an7581_pcm_hwdesc *desc;
	u8 *bounce_cpu;
	dma_addr_t bounce_dma;
	unsigned int channels;
	unsigned int periods;
	unsigned int period_frames;
	unsigned int chan_bytes;
	unsigned int hw_idx;
	unsigned int pending;
	u64 hw_ptr_frames;
	u64 reported_frames;
	u64 tx_fill_frames;
	bool running;
};

struct an7581_pcm_stats {
	u64 irq_total;
	u64 isr_bits[16];
	u64 completions[2];
	u64 kicks[2];
};

struct an7581_pcm {
	struct device *dev;
	void __iomem *base;
	struct reset_control *rst;
	int irq;
	spinlock_t lock;
	struct an7581_pcm_hwdesc *desc_cpu;
	dma_addr_t desc_dma;
	struct an7581_pcm_stream stream[2];
	struct an7581_pcm_stats stats;
	struct dentry *debugfs;
};

static u32 an7581_pcm_dma_addr(dma_addr_t addr)
{
	/* descriptor and buffer addresses carry physical | BIT(31) */
	return lower_32_bits(addr) | BIT(31);
}

static struct an7581_pcm_stream *an7581_pcm_substream_get(
	struct an7581_pcm *pcm, struct snd_pcm_substream *substream)
{
	return &pcm->stream[substream->stream];
}

static void an7581_pcm_desc_arm(struct an7581_pcm_stream *stream,
				unsigned int idx)
{
	struct an7581_pcm_hwdesc *desc = &stream->desc[idx];

	desc->chan_valid = (1 << stream->channels) - 1;
	desc->buf_addr = an7581_pcm_dma_addr(stream->bounce_dma +
					     idx * AN7581_PCM_BOUNCE_BYTES);
	dma_wmb();
	WRITE_ONCE(desc->status, DESC_OWN |
		   FIELD_PREP(DESC_SAMPLE_SIZE, stream->period_frames));
}

static void an7581_pcm_stream_kick(struct an7581_pcm *pcm, int dir)
{
	pcm->stats.kicks[dir]++;
	writel(1, pcm->base + (dir == SNDRV_PCM_STREAM_PLAYBACK ?
			       REG_TPDR : REG_RPDR));
}

static void an7581_pcm_dma_enable(struct an7581_pcm *pcm, int dir, bool on)
{
	u32 mask = dir == SNDRV_PCM_STREAM_PLAYBACK ? TRDCR_TXDMA_EN :
						      TRDCR_RXDMA_EN;
	u32 val = readl(pcm->base + REG_TRDCR);

	writel(on ? (val | mask) : (val & ~mask), pcm->base + REG_TRDCR);
}

static void an7581_pcm_tx_copy(struct an7581_pcm_stream *stream,
			       unsigned int idx)
{
	struct snd_pcm_runtime *runtime = stream->substream->runtime;
	unsigned int bytes = stream->period_frames * 2;
	unsigned int off = (stream->tx_fill_frames % runtime->buffer_size) * 2;
	u8 *bounce = stream->bounce_cpu + idx * AN7581_PCM_BOUNCE_BYTES;
	unsigned int c;

	for (c = 0; c < stream->channels; c++)
		memcpy(bounce + c * bytes,
		       runtime->dma_area + c * stream->chan_bytes + off,
		       bytes);
}

static unsigned int an7581_pcm_tx_fill(struct an7581_pcm *pcm,
				       struct an7581_pcm_stream *stream)
{
	struct snd_pcm_runtime *runtime = stream->substream->runtime;
	unsigned int armed = 0;
	unsigned int idx;
	u64 appl;

	if (!stream->running)
		return 0;

	while (stream->pending < AN7581_PCM_NUM_DESC) {
		appl = READ_ONCE(runtime->control->appl_ptr);
		if (appl < stream->tx_fill_frames + stream->period_frames)
			break;
		idx = (stream->hw_idx + stream->pending) % AN7581_PCM_NUM_DESC;
		an7581_pcm_tx_copy(stream, idx);
		an7581_pcm_desc_arm(stream, idx);
		an7581_pcm_stream_kick(pcm, SNDRV_PCM_STREAM_PLAYBACK);
		stream->tx_fill_frames += stream->period_frames;
		stream->pending++;
		armed++;
	}

	return armed;
}

static unsigned int an7581_pcm_tx_walk(struct an7581_pcm_stream *stream)
{
	unsigned int completed = 0;

	while (stream->pending &&
	       !(READ_ONCE(stream->desc[stream->hw_idx].status) & DESC_OWN)) {
		stream->hw_ptr_frames += stream->period_frames;
		stream->pending--;
		stream->hw_idx = (stream->hw_idx + 1) % AN7581_PCM_NUM_DESC;
		completed++;
	}

	return completed;
}

static unsigned int an7581_pcm_tx_reclaim(struct an7581_pcm *pcm,
					  struct an7581_pcm_stream *stream)
{
	unsigned int completed;
	unsigned int i, idx, skip;

	completed = an7581_pcm_tx_walk(stream);

	/*
	 * The engine consumes descriptors strictly in ring order, so a
	 * cleared descriptor beyond a still-owned hw_idx means the reclaim
	 * cursor fell behind the engine (a completion raced a stream stop).
	 * Drop the bypassed descriptors and resume from the engine's
	 * position; without this the JIT ring deadlocks: the driver waits
	 * on hw_idx while the engine waits past it for an owned descriptor.
	 */
	if (!completed && stream->pending &&
	    (READ_ONCE(stream->desc[stream->hw_idx].status) & DESC_OWN)) {
		skip = 0;
		for (i = 1; i < stream->pending; i++) {
			idx = (stream->hw_idx + i) % AN7581_PCM_NUM_DESC;
			if (!(READ_ONCE(stream->desc[idx].status) & DESC_OWN)) {
				skip = i;
				break;
			}
		}
		if (skip) {
			dev_warn_ratelimited(pcm->dev,
					     "tx ring resync: engine %u descs ahead\n",
					     skip);
			for (i = 0; i < skip; i++) {
				idx = (stream->hw_idx + i) %
				      AN7581_PCM_NUM_DESC;
				WRITE_ONCE(stream->desc[idx].status, 0);
				stream->hw_ptr_frames += stream->period_frames;
				stream->pending--;
				completed++;
			}
			stream->hw_idx = (stream->hw_idx + skip) %
					 AN7581_PCM_NUM_DESC;
			completed += an7581_pcm_tx_walk(stream);
		}
	}

	pcm->stats.completions[SNDRV_PCM_STREAM_PLAYBACK] += completed;

	return completed;
}

static unsigned int an7581_pcm_rx_service(struct an7581_pcm *pcm,
					  struct an7581_pcm_stream *stream)
{
	struct snd_pcm_runtime *runtime = stream->substream->runtime;
	unsigned int bytes = stream->period_frames * 2;
	unsigned int completed = 0;
	unsigned int off, c;
	u8 *bounce;

	while (stream->pending &&
	       !(READ_ONCE(stream->desc[stream->hw_idx].status) & DESC_OWN)) {
		dma_rmb();
		bounce = stream->bounce_cpu +
			 stream->hw_idx * AN7581_PCM_BOUNCE_BYTES;
		off = (stream->hw_ptr_frames % runtime->buffer_size) * 2;
		for (c = 0; c < stream->channels; c++)
			memcpy(runtime->dma_area + c * stream->chan_bytes + off,
			       bounce + c * bytes, bytes);
		stream->hw_ptr_frames += stream->period_frames;
		an7581_pcm_desc_arm(stream, stream->hw_idx);
		an7581_pcm_stream_kick(pcm, SNDRV_PCM_STREAM_CAPTURE);
		stream->hw_idx = (stream->hw_idx + 1) % AN7581_PCM_NUM_DESC;
		completed++;
	}

	pcm->stats.completions[SNDRV_PCM_STREAM_CAPTURE] += completed;

	return completed;
}

static void an7581_pcm_stream_start(struct an7581_pcm *pcm,
				    struct an7581_pcm_stream *stream, int dir)
{
	unsigned int i;

	/* per-channel sub-buffer stride is one period (matches aos 0xA0=160) */
	writel(stream->period_frames * 2, pcm->base + REG_CHBFOSR);
	writel((1 << stream->channels) - 1, pcm->base + REG_DCHENR);

	stream->hw_ptr_frames = 0;
	stream->reported_frames = 0;
	stream->tx_fill_frames = 0;
	stream->running = true;

	an7581_pcm_dma_enable(pcm, dir, true);

	if (dir == SNDRV_PCM_STREAM_PLAYBACK) {
		an7581_pcm_tx_fill(pcm, stream);
		return;
	}

	for (i = 0; i < AN7581_PCM_NUM_DESC; i++)
		an7581_pcm_desc_arm(stream, i);
	stream->pending = AN7581_PCM_NUM_DESC;
	an7581_pcm_stream_kick(pcm, dir);
}

static void an7581_pcm_stream_stop(struct an7581_pcm *pcm,
				   struct an7581_pcm_stream *stream, int dir)
{
	stream->running = false;
	an7581_pcm_dma_enable(pcm, dir, false);

	/*
	 * The engine can finish 1-2 in-flight descriptors after the DMA
	 * disable (each takes period_frames/8 ms of bus time), and trigger
	 * context cannot sleep that long. Leave the ring armed: zeroing it
	 * here races those late completions, and the reclaim cursor ends up
	 * behind the engine's (which survives DMA disable), deadlocking the
	 * JIT TX ring on the next start. The quiesce in prepare/hw_free
	 * syncs the cursor and cancels leftovers once the engine is idle.
	 */
	while (stream->pending &&
	       !(READ_ONCE(stream->desc[stream->hw_idx].status) & DESC_OWN)) {
		stream->pending--;
		stream->hw_idx = (stream->hw_idx + 1) % AN7581_PCM_NUM_DESC;
	}
}

static void an7581_pcm_stream_quiesce(struct an7581_pcm *pcm,
				      struct an7581_pcm_stream *stream)
{
	unsigned int period_ms = DIV_ROUND_UP(stream->period_frames, 8);
	unsigned long timeout = jiffies + msecs_to_jiffies(4 * period_ms + 20);
	unsigned int prev = UINT_MAX;
	unsigned int cur;
	unsigned long flags;
	unsigned int i;

	if (!stream->period_frames)
		return;

	/*
	 * Wait until the engine stops clearing OWN bits: one full descriptor
	 * duration with no progress means it is idle (it either consumed the
	 * in-flight descriptors or aborted without touching them; the cursor
	 * matches hw_idx in both cases). Only then is dropping the leftover
	 * armed state race-free.
	 */
	while (time_before(jiffies, timeout)) {
		spin_lock_irqsave(&pcm->lock, flags);
		while (stream->pending &&
		       !(READ_ONCE(stream->desc[stream->hw_idx].status) &
			 DESC_OWN)) {
			stream->pending--;
			stream->hw_idx = (stream->hw_idx + 1) %
					 AN7581_PCM_NUM_DESC;
		}
		cur = stream->pending;
		spin_unlock_irqrestore(&pcm->lock, flags);
		if (!cur || cur == prev)
			break;
		prev = cur;
		msleep(period_ms + 2);
	}

	spin_lock_irqsave(&pcm->lock, flags);
	stream->pending = 0;
	for (i = 0; i < AN7581_PCM_NUM_DESC; i++)
		WRITE_ONCE(stream->desc[i].status, 0);
	spin_unlock_irqrestore(&pcm->lock, flags);
}

static irqreturn_t an7581_pcm_irq(int irq, void *dev_id)
{
	struct an7581_pcm *pcm = dev_id;
	struct an7581_pcm_stream *stream;
	unsigned int done[2] = { 0, 0 };
	bool xrun[2] = { false, false };
	unsigned long flags;
	u32 isr;
	int dir;

	/* ISR is clear-on-read; read exactly once per interrupt */
	isr = readl(pcm->base + REG_ISR);
	if (!isr)
		return IRQ_NONE;

	pcm->stats.irq_total++;
	for (dir = 0; dir < 16; dir++)
		if (isr & BIT(dir))
			pcm->stats.isr_bits[dir]++;

	if (isr & INT_ERRORS)
		dev_warn_ratelimited(pcm->dev, "pcm error irq 0x%08x\n", isr);

	spin_lock_irqsave(&pcm->lock, flags);

	if (isr & (INT_TDESC_UPDATE | INT_TDESC_END)) {
		dir = SNDRV_PCM_STREAM_PLAYBACK;
		stream = &pcm->stream[dir];
		if (stream->running) {
			done[dir] = an7581_pcm_tx_reclaim(pcm, stream);
			an7581_pcm_tx_fill(pcm, stream);
		}
	}

	if (isr & (INT_RDESC_UPDATE | INT_RDESC_END)) {
		dir = SNDRV_PCM_STREAM_CAPTURE;
		stream = &pcm->stream[dir];
		if (stream->running) {
			done[dir] = an7581_pcm_rx_service(pcm, stream);
			if (isr & INT_RDESC_END)
				an7581_pcm_stream_kick(pcm, dir);
		}
	}

	if (isr & INT_AHB_BUS_ERR)
		for (dir = 0; dir < 2; dir++)
			xrun[dir] = pcm->stream[dir].running;

	spin_unlock_irqrestore(&pcm->lock, flags);

	/*
	 * Report completions strictly one period per period_elapsed call:
	 * the ALSA hw_ptr bookkeeping mis-tracks multi-period jumps when a
	 * batch spans the (small) buffer, so never expose one.
	 */
	for (dir = 0; dir < 2; dir++) {
		if (xrun[dir]) {
			snd_pcm_stop_xrun(pcm->stream[dir].substream);
			continue;
		}
		stream = &pcm->stream[dir];
		while (done[dir]) {
			done[dir]--;
			spin_lock_irqsave(&pcm->lock, flags);
			stream->reported_frames += stream->period_frames;
			spin_unlock_irqrestore(&pcm->lock, flags);
			snd_pcm_period_elapsed(stream->substream);
		}
	}

	return IRQ_HANDLED;
}

static int an7581_pcm_stats_show(struct seq_file *s, void *unused)
{
	static const char * const isr_names[16] = {
		[0] = "frame_boundary", [2] = "tdesc_update",
		[3] = "rdesc_update", [4] = "tdesc_end", [5] = "rdesc_end",
		[6] = "tbuf_underrun", [7] = "rbuf_overrun", [8] = "ahb_bus_err",
		[11] = "zsi", [12] = "isi", [14] = "slic",
	};
	static const char * const dir_names[2] = { "tx", "rx" };
	struct an7581_pcm *pcm = s->private;
	unsigned long flags;
	int dir, i;

	seq_printf(s, "irq_total %llu\n", pcm->stats.irq_total);
	for (i = 0; i < 16; i++) {
		if (!pcm->stats.isr_bits[i] && !isr_names[i])
			continue;
		seq_printf(s, "isr_bit%d_%s %llu\n", i,
			   isr_names[i] ? isr_names[i] : "unknown",
			   pcm->stats.isr_bits[i]);
	}
	for (dir = 0; dir < 2; dir++)
		seq_printf(s, "%s_completions %llu\n%s_kicks %llu\n",
			   dir_names[dir], pcm->stats.completions[dir],
			   dir_names[dir], pcm->stats.kicks[dir]);

	spin_lock_irqsave(&pcm->lock, flags);
	for (dir = 0; dir < 2; dir++) {
		struct an7581_pcm_stream *stream = &pcm->stream[dir];

		seq_printf(s, "%s running=%d hw_idx=%u pending=%u hw_ptr=%llu reported=%llu fill=%llu periods=%u period_frames=%u\n",
			   dir_names[dir], stream->running, stream->hw_idx,
			   stream->pending, stream->hw_ptr_frames,
			   stream->reported_frames, stream->tx_fill_frames,
			   stream->periods, stream->period_frames);
		if (!stream->desc)
			continue;
		for (i = 0; i < AN7581_PCM_NUM_DESC; i++)
			seq_printf(s, "%s_desc%d status=0x%08x chv=0x%08x buf=0x%08x\n",
				   dir_names[dir], i,
				   READ_ONCE(stream->desc[i].status),
				   stream->desc[i].chan_valid,
				   stream->desc[i].buf_addr);
		if (stream->bounce_cpu) {
			s16 *b = (s16 *)(stream->bounce_cpu +
					 stream->hw_idx * AN7581_PCM_BOUNCE_BYTES);

			seq_printf(s, "%s bounce_dma=%pad bounce[hw_idx]:",
				   dir_names[dir], &stream->bounce_dma);
			for (i = 0; i < 8; i++)
				seq_printf(s, " %d", b[i]);
			seq_puts(s, "\n");
		}
		if (stream->substream && stream->substream->runtime &&
		    stream->substream->runtime->dma_area) {
			s16 *a = (s16 *)stream->substream->runtime->dma_area;

			seq_printf(s, "%s dma_area:", dir_names[dir]);
			for (i = 0; i < 8; i++)
				seq_printf(s, " %d", a[i]);
			seq_puts(s, "\n");
		}
	}
	spin_unlock_irqrestore(&pcm->lock, flags);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(an7581_pcm_stats);

static void an7581_pcm_debugfs_remove(void *data)
{
	debugfs_remove(data);
}

static const struct snd_pcm_hardware an7581_pcm_hardware = {
	/*
	 * SYNC_APPLPTR is required: without this, appl_ptr 
	 * updates bypass the kernel and the .ack-driven TX
	 * descriptor arming never runs.
	 */
	.info			= SNDRV_PCM_INFO_MMAP |
				  SNDRV_PCM_INFO_MMAP_VALID |
				  SNDRV_PCM_INFO_NONINTERLEAVED |
				  SNDRV_PCM_INFO_BATCH |
				  SNDRV_PCM_INFO_SYNC_APPLPTR,
	.formats		= SNDRV_PCM_FMTBIT_S16_LE,
	.rates			= SNDRV_PCM_RATE_8000,
	.rate_min		= 8000,
	.rate_max		= 8000,
	.channels_min		= 1,
	.channels_max		= 2,
	.periods_min		= 2,
	.periods_max		= AN7581_PCM_NUM_DESC,
	.period_bytes_min	= 64,
	.period_bytes_max	= AN7581_PCM_MAX_FRAMES * 2 *
				  AN7581_PCM_MAX_CHANNELS,
	.buffer_bytes_max	= AN7581_PCM_NUM_DESC * AN7581_PCM_MAX_FRAMES *
				  2 * AN7581_PCM_MAX_CHANNELS,
	.fifo_size		= 0,
};

static int an7581_pcm_open(struct snd_soc_component *component,
			   struct snd_pcm_substream *substream)
{
	struct an7581_pcm *pcm = snd_soc_component_get_drvdata(component);
	struct an7581_pcm_stream *stream;
	int ret;

	snd_soc_set_runtime_hwparams(substream, &an7581_pcm_hardware);

	/* descriptor sample count is per channel and 10 bits wide */
	ret = snd_pcm_hw_constraint_minmax(substream->runtime,
					   SNDRV_PCM_HW_PARAM_PERIOD_SIZE,
					   16, AN7581_PCM_MAX_FRAMES);
	if (ret < 0)
		return ret;

	stream = an7581_pcm_substream_get(pcm, substream);
	stream->substream = substream;

	return 0;
}

static int an7581_pcm_hw_params(struct snd_soc_component *component,
				struct snd_pcm_substream *substream,
				struct snd_pcm_hw_params *params)
{
	struct an7581_pcm *pcm = snd_soc_component_get_drvdata(component);
	struct an7581_pcm_stream *stream, *other;

	stream = an7581_pcm_substream_get(pcm, substream);
	other = &pcm->stream[1 - substream->stream];

	/*
	 * DCHENR (channel enable) is a single register shared by both DMA
	 * directions, so they must agree on the channel count. The per-
	 * direction buffer/period sizes are independent (separate descriptor
	 * rings), and CHBFOSR only matters for multi-channel de-interleaving.
	 */
	if (other->channels && other->channels != params_channels(params))
		return -EBUSY;

	stream->channels = params_channels(params);
	stream->periods = params_periods(params);
	stream->period_frames = params_period_size(params);
	stream->chan_bytes = params_buffer_bytes(params) / stream->channels;

	return 0;
}

static int an7581_pcm_hw_free(struct snd_soc_component *component,
			      struct snd_pcm_substream *substream)
{
	struct an7581_pcm *pcm = snd_soc_component_get_drvdata(component);
	struct an7581_pcm_stream *stream;

	stream = an7581_pcm_substream_get(pcm, substream);
	an7581_pcm_stream_quiesce(pcm, stream);
	stream->channels = 0;

	return 0;
}

static int an7581_pcm_prepare(struct snd_soc_component *component,
			      struct snd_pcm_substream *substream)
{
	struct an7581_pcm *pcm = snd_soc_component_get_drvdata(component);
	struct an7581_pcm_stream *stream;

	stream = an7581_pcm_substream_get(pcm, substream);
	if (!stream->running)
		an7581_pcm_stream_quiesce(pcm, stream);

	return 0;
}

static int an7581_pcm_trigger(struct snd_soc_component *component,
			      struct snd_pcm_substream *substream, int cmd)
{
	struct an7581_pcm *pcm = snd_soc_component_get_drvdata(component);
	struct an7581_pcm_stream *stream;
	unsigned long flags;
	int ret = 0;

	stream = an7581_pcm_substream_get(pcm, substream);

	spin_lock_irqsave(&pcm->lock, flags);
	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_RESUME:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
		an7581_pcm_stream_start(pcm, stream, substream->stream);
		break;
	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
		an7581_pcm_stream_stop(pcm, stream, substream->stream);
		break;
	default:
		ret = -EINVAL;
	}
	spin_unlock_irqrestore(&pcm->lock, flags);

	return ret;
}

static snd_pcm_uframes_t an7581_pcm_pointer(struct snd_soc_component *component,
					    struct snd_pcm_substream *substream)
{
	struct an7581_pcm *pcm = snd_soc_component_get_drvdata(component);
	struct an7581_pcm_stream *stream;
	unsigned long flags;
	u64 pos;

	stream = an7581_pcm_substream_get(pcm, substream);

	spin_lock_irqsave(&pcm->lock, flags);
	pos = stream->reported_frames;
	spin_unlock_irqrestore(&pcm->lock, flags);

	return (snd_pcm_uframes_t)(pos % substream->runtime->buffer_size);
}

static int an7581_pcm_ack(struct snd_soc_component *component,
			  struct snd_pcm_substream *substream)
{
	struct an7581_pcm *pcm = snd_soc_component_get_drvdata(component);
	struct an7581_pcm_stream *stream;
	unsigned long flags;

	if (substream->stream != SNDRV_PCM_STREAM_PLAYBACK)
		return 0;

	stream = an7581_pcm_substream_get(pcm, substream);

	spin_lock_irqsave(&pcm->lock, flags);
	an7581_pcm_tx_fill(pcm, stream);
	spin_unlock_irqrestore(&pcm->lock, flags);

	return 0;
}

static int an7581_pcm_construct(struct snd_soc_component *component,
				struct snd_soc_pcm_runtime *rtd)
{
	snd_pcm_set_managed_buffer_all(rtd->pcm, SNDRV_DMA_TYPE_DEV,
				       component->dev,
				       an7581_pcm_hardware.buffer_bytes_max,
				       an7581_pcm_hardware.buffer_bytes_max);
	return 0;
}

static const struct snd_soc_component_driver an7581_pcm_component = {
	.name		= "an7581-pcm",
	.open		= an7581_pcm_open,
	.hw_params	= an7581_pcm_hw_params,
	.hw_free	= an7581_pcm_hw_free,
	.prepare	= an7581_pcm_prepare,
	.trigger	= an7581_pcm_trigger,
	.pointer	= an7581_pcm_pointer,
	.ack		= an7581_pcm_ack,
	.pcm_construct	= an7581_pcm_construct,
};

static struct snd_soc_dai_driver an7581_pcm_dais[] = {
	{
		.name = "an7581-pcm-dl",
		.playback = {
			.stream_name	= "an7581-pcm-playback",
			.channels_min	= 1,
			.channels_max	= 2,
			.rates		= SNDRV_PCM_RATE_8000,
			.formats	= SNDRV_PCM_FMTBIT_S16_LE,
		},
	}, {
		.name = "an7581-pcm-ul",
		.capture = {
			.stream_name	= "an7581-pcm-capture",
			.channels_min	= 1,
			.channels_max	= 2,
			.rates		= SNDRV_PCM_RATE_8000,
			.formats	= SNDRV_PCM_FMTBIT_S16_LE,
		},
	},
};

static void an7581_pcm_hw_init(struct an7581_pcm *pcm)
{
	u32 val;
	int i;

	writel(0, pcm->base + REG_IMR);
	writel(0, pcm->base + REG_TRDCR);

	/*
	 * cfg_valid must be low while the interface is (re)programmed and
	 * raised at least 520 hclk cycles later.
	 */
	/* FC_INT_CFG=1 only paces the (masked) frame-boundary interrupt;
	 * set it to make PICR byte-exact with the aos known-good 0x75050306. */
	val = FIELD_PREP(PICR_PROBE_SEL, 7) | PICR_SWRST_N |
	      FIELD_PREP(PICR_FC_INT_CFG, 1) |
	      PICR_BIT_ORDER_MSB | FIELD_PREP(PICR_FS_LEN, PICR_FS_LEN_16) |
	      FIELD_PREP(PICR_BIT_CLK, PICR_BIT_CLK_2048K);
	writel(val, pcm->base + REG_PICR);

	for (i = 0; i < AN7581_PCM_SLOTS / 2; i++) {
		u32 slot = TSCR_SLOT0_BW16 | TSCR_SLOT1_BW16 |
			   FIELD_PREP(TSCR_SLOT0_START,
				      (2 * i) * 16 + AN7581_PCM_SLOT_OFF) |
			   FIELD_PREP(TSCR_SLOT1_START,
				      (2 * i + 1) * 16 + AN7581_PCM_SLOT_OFF);

		writel(slot, pcm->base + REG_PTTSCR(i));
		writel(slot, pcm->base + REG_PRTSCR(i));
	}

	writel(an7581_pcm_dma_addr(pcm->desc_dma), pcm->base + REG_TDRBAR);
	writel(an7581_pcm_dma_addr(pcm->desc_dma +
				   AN7581_PCM_NUM_DESC *
				   sizeof(struct an7581_pcm_hwdesc)),
	       pcm->base + REG_RDRBAR);
	writel((AN7581_PCM_DESC_STRIDE_DW << 4) | AN7581_PCM_NUM_DESC,
	       pcm->base + REG_TRDRSR);
	writel(0, pcm->base + REG_CHBFOSR);
	writel(1, pcm->base + REG_DCHENR);

	usleep_range(1000, 2000);
	writel(val | PICR_CFG_VALID, pcm->base + REG_PICR);

	/*
	 * TDESC_END and TBUF_UNDERRUN stay masked: with just-in-time TX
	 * arming an idle line runs the TX ring dry as a matter of course
	 * and both would fire continuously (aos masks all TX interrupts).
	 */
	writel(INT_TDESC_UPDATE | INT_RDESC_UPDATE | INT_RDESC_END |
	       INT_ERRORS, pcm->base + REG_IMR);
}

static int an7581_pcm_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct an7581_pcm *pcm;
	struct regmap *scu;
	dma_addr_t bounce_dma;
	u8 *bounce_cpu;
	int ret;

	pcm = devm_kzalloc(dev, sizeof(*pcm), GFP_KERNEL);
	if (!pcm)
		return -ENOMEM;

	pcm->dev = dev;
	spin_lock_init(&pcm->lock);
	platform_set_drvdata(pdev, pcm);

	pcm->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(pcm->base))
		return PTR_ERR(pcm->base);

	pcm->irq = platform_get_irq(pdev, 0);
	if (pcm->irq < 0)
		return pcm->irq;

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
	if (ret)
		return ret;

	pcm->rst = devm_reset_control_get_optional_exclusive(dev, NULL);
	if (IS_ERR(pcm->rst))
		return PTR_ERR(pcm->rst);

	scu = syscon_regmap_lookup_by_phandle(dev->of_node, "airoha,chip-scu");
	if (IS_ERR(scu))
		return dev_err_probe(dev, PTR_ERR(scu),
				     "missing airoha,chip-scu\n");
	regmap_write(scu, CHIP_SCU_PCM_CLK, CHIP_SCU_PCM_CLK_CFG);

	scu = syscon_regmap_lookup_by_phandle(dev->of_node, "airoha,np-scu");
	if (IS_ERR(scu))
		return dev_err_probe(dev, PTR_ERR(scu),
				     "missing airoha,np-scu\n");
	regmap_clear_bits(scu, NP_SCU_SSR3, SSR3_PCM1_ISI_EN);

	pcm->desc_cpu = dmam_alloc_coherent(dev,
					    2 * AN7581_PCM_NUM_DESC *
					    sizeof(struct an7581_pcm_hwdesc),
					    &pcm->desc_dma, GFP_KERNEL);
	if (!pcm->desc_cpu)
		return -ENOMEM;

	pcm->stream[SNDRV_PCM_STREAM_PLAYBACK].desc = pcm->desc_cpu;
	pcm->stream[SNDRV_PCM_STREAM_CAPTURE].desc =
		pcm->desc_cpu + AN7581_PCM_NUM_DESC;

	bounce_cpu = dmam_alloc_coherent(dev, 2 * AN7581_PCM_NUM_DESC *
					 AN7581_PCM_BOUNCE_BYTES,
					 &bounce_dma, GFP_KERNEL);
	if (!bounce_cpu)
		return -ENOMEM;

	pcm->stream[SNDRV_PCM_STREAM_PLAYBACK].bounce_cpu = bounce_cpu;
	pcm->stream[SNDRV_PCM_STREAM_PLAYBACK].bounce_dma = bounce_dma;
	pcm->stream[SNDRV_PCM_STREAM_CAPTURE].bounce_cpu = bounce_cpu +
		AN7581_PCM_NUM_DESC * AN7581_PCM_BOUNCE_BYTES;
	pcm->stream[SNDRV_PCM_STREAM_CAPTURE].bounce_dma = bounce_dma +
		AN7581_PCM_NUM_DESC * AN7581_PCM_BOUNCE_BYTES;

	/*
	 * The en7581-scu reset controller implements only assert/deassert,
	 * so pulse the block reset manually (vendor timing: 5 ms assert,
	 * 5 ms settle).
	 */
	ret = reset_control_assert(pcm->rst);
	if (ret)
		return ret;
	usleep_range(5000, 6000);
	ret = reset_control_deassert(pcm->rst);
	if (ret)
		return ret;
	usleep_range(5000, 6000);

	an7581_pcm_hw_init(pcm);

	ret = devm_request_irq(dev, pcm->irq, an7581_pcm_irq, 0,
			       dev_name(dev), pcm);
	if (ret)
		return ret;

	pcm->debugfs = debugfs_create_dir("an7581-pcm", NULL);
	ret = devm_add_action_or_reset(dev, an7581_pcm_debugfs_remove,
				       pcm->debugfs);
	if (ret)
		return ret;
	debugfs_create_file("stats", 0444, pcm->debugfs, pcm,
			    &an7581_pcm_stats_fops);

	return devm_snd_soc_register_component(dev, &an7581_pcm_component,
					       an7581_pcm_dais,
					       ARRAY_SIZE(an7581_pcm_dais));
}

static const struct of_device_id an7581_pcm_of_match[] = {
	{ .compatible = "airoha,en7581-pcm" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, an7581_pcm_of_match);

static struct platform_driver an7581_pcm_driver = {
	.driver = {
		.name = "an7581-pcm-tdm",
		.of_match_table = an7581_pcm_of_match,
	},
	.probe = an7581_pcm_probe,
};
module_platform_driver(an7581_pcm_driver);

MODULE_DESCRIPTION("Airoha EN7581 telephony PCM ASoC platform driver");
MODULE_LICENSE("GPL");
