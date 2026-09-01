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
 * At 16 kHz the SLIC keeps the narrowband timeslot of line k at frame bit
 * k*16 and sends the second sample of each pair half a frame later, at bit
 * k*16 + 128. The driver gives every ALSA channel two engine channels at
 * those two frame bits and merges the two 8 kHz sample streams into one
 * 16 kHz stream in the bounce copy.
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
#include <linux/mutex.h>
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
/*
 * The engine holds 32 slot descriptors in 16 register pairs. Only the first
 * 16 fit the 256-bit frame at 16 bits each, and the reset values of the rest
 * are 8-bit slots at bits 128 to 248. That is where the second sample of a
 * wideband pair sits, so the 16 kHz path parks them past the frame.
 */
#define AN7581_PCM_HW_SLOTS		32
#define AN7581_PCM_RATE_NB		8000
#define AN7581_PCM_RATE_WB		16000
/* the second sample of a wideband pair sits half a 256-bit frame later */
#define AN7581_PCM_WB_PAIR_OFF		128
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
	unsigned int rate;
	unsigned int dma_channels;
	unsigned int periods;
	unsigned int period_frames;
	unsigned int desc_frames;
	unsigned int chan_bytes;
	unsigned int hw_idx;
	unsigned int pending;
	u64 hw_ptr_frames;
	u64 reported_frames;
	u64 tx_fill_frames;
	bool running;
};

struct an7581_pcm_cfg {
	unsigned int rate;
	u32 chbfosr;
	u32 dchenr;
};

struct an7581_pcm_stats {
	u64 irq_total;
	u64 isr_bits[16];
	u64 completions[2];
	u64 kicks[2];
	u64 resync_runs;
	u64 resync_skips_busy;
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
	struct mutex cfg_lock;
	struct an7581_pcm_cfg cfg;
	bool cfg_dirty;
	bool reprogramming;
};

static void an7581_pcm_hw_init(struct an7581_pcm *pcm);
static void an7581_pcm_slots_program(struct an7581_pcm *pcm);

static u32 an7581_pcm_dma_addr(dma_addr_t addr)
{
	/* descriptor and buffer addresses carry physical | BIT(31) */
	return lower_32_bits(addr) | BIT(31);
}

/*
 * aos pcmTsReSet() clears the channel enable before it writes the new mask,
 * on every remap, so the engine always sees a falling edge on the register.
 */
static void an7581_pcm_dchenr_set(struct an7581_pcm *pcm, u32 mask)
{
	writel(0, pcm->base + REG_DCHENR);
	writel(mask, pcm->base + REG_DCHENR);
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

	desc->chan_valid = (1 << stream->dma_channels) - 1;
	desc->buf_addr = an7581_pcm_dma_addr(stream->bounce_dma +
					     idx * AN7581_PCM_BOUNCE_BYTES);
	dma_wmb();
	WRITE_ONCE(desc->status, DESC_OWN |
		   FIELD_PREP(DESC_SAMPLE_SIZE, stream->desc_frames));
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

/*
 * A wideband line runs on two engine channels: the first carries the sample
 * the SLIC places at frame bit k*16, the second the sample it places half a
 * frame later, so the two 8 kHz streams interleave into one 16 kHz stream.
 */
static void an7581_pcm_wb_split(s16 *first, s16 *second, const s16 *src,
				unsigned int frames)
{
	unsigned int n;

	for (n = 0; n < frames; n++) {
		first[n] = src[2 * n];
		second[n] = src[2 * n + 1];
	}
}

static void an7581_pcm_wb_merge(s16 *dst, const s16 *first, const s16 *second,
				unsigned int frames)
{
	unsigned int n;

	for (n = 0; n < frames; n++) {
		dst[2 * n] = first[n];
		dst[2 * n + 1] = second[n];
	}
}

static void an7581_pcm_tx_copy(struct an7581_pcm_stream *stream,
			       unsigned int idx)
{
	struct snd_pcm_runtime *runtime = stream->substream->runtime;
	unsigned int bytes = stream->desc_frames * 2;
	unsigned int off = (stream->tx_fill_frames % runtime->buffer_size) * 2;
	u8 *bounce = stream->bounce_cpu + idx * AN7581_PCM_BOUNCE_BYTES;
	unsigned int c;

	if (stream->rate != AN7581_PCM_RATE_WB) {
		for (c = 0; c < stream->channels; c++)
			memcpy(bounce + c * bytes,
			       runtime->dma_area + c * stream->chan_bytes + off,
			       bytes);
		return;
	}

	for (c = 0; c < stream->channels; c++)
		an7581_pcm_wb_split((s16 *)(bounce + 2 * c * bytes),
				    (s16 *)(bounce + (2 * c + 1) * bytes),
				    (s16 *)(runtime->dma_area +
					    c * stream->chan_bytes + off),
				    stream->desc_frames);
}

static void an7581_pcm_rx_copy(struct an7581_pcm_stream *stream,
			       unsigned int idx)
{
	struct snd_pcm_runtime *runtime = stream->substream->runtime;
	unsigned int bytes = stream->desc_frames * 2;
	unsigned int off = (stream->hw_ptr_frames % runtime->buffer_size) * 2;
	u8 *bounce = stream->bounce_cpu + idx * AN7581_PCM_BOUNCE_BYTES;
	unsigned int c;

	if (stream->rate != AN7581_PCM_RATE_WB) {
		for (c = 0; c < stream->channels; c++)
			memcpy(runtime->dma_area + c * stream->chan_bytes + off,
			       bounce + c * bytes, bytes);
		return;
	}

	for (c = 0; c < stream->channels; c++)
		an7581_pcm_wb_merge((s16 *)(runtime->dma_area +
					    c * stream->chan_bytes + off),
				    (s16 *)(bounce + 2 * c * bytes),
				    (s16 *)(bounce + (2 * c + 1) * bytes),
				    stream->desc_frames);
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
	unsigned int completed = 0;

	while (stream->pending &&
	       !(READ_ONCE(stream->desc[stream->hw_idx].status) & DESC_OWN)) {
		dma_rmb();
		an7581_pcm_rx_copy(stream, stream->hw_idx);
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

	stream->hw_ptr_frames = 0;
	stream->reported_frames = 0;
	stream->tx_fill_frames = 0;
	stream->running = true;

	/*
	 * Arm before the DMA enable: aos treats a TX buffer underrun as fatal
	 * and resets the block, so the engine must never see the TX DMA
	 * enabled over an empty ring. Capture arms its whole ring first for
	 * the same reason.
	 */
	if (dir == SNDRV_PCM_STREAM_PLAYBACK) {
		an7581_pcm_tx_fill(pcm, stream);
		an7581_pcm_dma_enable(pcm, dir, true);
		an7581_pcm_stream_kick(pcm, dir);
		return;
	}

	for (i = 0; i < AN7581_PCM_NUM_DESC; i++)
		an7581_pcm_desc_arm(stream, i);
	stream->pending = AN7581_PCM_NUM_DESC;
	an7581_pcm_dma_enable(pcm, dir, true);
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

/*
 * trigger(STOP) is the only path that clears running, so a stream whose engine
 * never completed a descriptor stays latched when the application dies while
 * blocked. hw_free and close force the direction idle instead.
 */
static void an7581_pcm_stream_force_idle(struct an7581_pcm *pcm,
					 struct an7581_pcm_stream *stream,
					 int dir)
{
	unsigned long flags;

	spin_lock_irqsave(&pcm->lock, flags);
	if (stream->running)
		an7581_pcm_stream_stop(pcm, stream, dir);
	spin_unlock_irqrestore(&pcm->lock, flags);
}

static void an7581_pcm_stream_quiesce(struct an7581_pcm *pcm,
				      struct an7581_pcm_stream *stream)
{
	/* one engine channel carries one sample per 8 kHz frame at any rate */
	unsigned int period_ms = DIV_ROUND_UP(stream->desc_frames, 8);
	unsigned long timeout = jiffies + msecs_to_jiffies(4 * period_ms + 20);
	unsigned int prev = UINT_MAX;
	unsigned int cur;
	unsigned long flags;
	unsigned int i;

	if (!stream->desc_frames)
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

static void an7581_pcm_stats_bounce(struct seq_file *s,
				    struct an7581_pcm_stream *stream,
				    const char *name)
{
	unsigned int bytes = stream->desc_frames * 2;
	unsigned int i, k;
	u8 *b;

	if (!stream->bounce_cpu || !stream->dma_channels)
		return;

	b = stream->bounce_cpu + stream->hw_idx * AN7581_PCM_BOUNCE_BYTES;
	seq_printf(s, "%s bounce_dma=%pad\n", name, &stream->bounce_dma);
	for (k = 0; k < stream->dma_channels; k++) {
		s16 *p = (s16 *)(b + k * bytes);

		seq_printf(s, "%s_bounce%u:", name, k);
		for (i = 0; i < 4; i++)
			seq_printf(s, " %d", p[i]);
		seq_puts(s, "\n");
	}
}

static int an7581_pcm_stats_show(struct seq_file *s, void *unused)
{
	static const char * const isr_names[16] = {
		[0] = "frame_boundary", [2] = "tdesc_update",
		[3] = "rdesc_update", [4] = "tdesc_end", [5] = "rdesc_end",
		[6] = "tbuf_underrun", [7] = "rbuf_overrun", [8] = "ahb_bus_err",
		[9] = "hunt_overtime", [10] = "hunt_err_after_finish",
		[11] = "zsi", [12] = "isi", [14] = "slic",
	};
	static const char * const dir_names[2] = { "tx", "rx" };
	struct an7581_pcm *pcm = s->private;
	struct an7581_pcm_cfg cfg;
	unsigned long flags;
	bool dirty;
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
	seq_printf(s, "resync_runs %llu\nresync_skips_busy %llu\n",
		   pcm->stats.resync_runs, pcm->stats.resync_skips_busy);

	mutex_lock(&pcm->cfg_lock);
	cfg = pcm->cfg;
	dirty = pcm->cfg_dirty;
	mutex_unlock(&pcm->cfg_lock);

	seq_printf(s, "rate %u cfg_dirty %u want_chbfosr %u want_dchenr 0x%08x\n",
		   cfg.rate, dirty, cfg.chbfosr, cfg.dchenr);
	seq_printf(s, "picr 0x%08x trdcr 0x%08x dchenr 0x%08x chbfosr 0x%08x imr 0x%08x\n",
		   readl(pcm->base + REG_PICR), readl(pcm->base + REG_TRDCR),
		   readl(pcm->base + REG_DCHENR), readl(pcm->base + REG_CHBFOSR),
		   readl(pcm->base + REG_IMR));
	for (i = 0; i < AN7581_PCM_HW_SLOTS / 2; i++)
		seq_printf(s, "pttscr%d 0x%08x prtscr%d 0x%08x\n",
			   i, readl(pcm->base + REG_PTTSCR(i)),
			   i, readl(pcm->base + REG_PRTSCR(i)));

	spin_lock_irqsave(&pcm->lock, flags);
	for (dir = 0; dir < 2; dir++) {
		struct an7581_pcm_stream *stream = &pcm->stream[dir];

		seq_printf(s, "%s running=%d hw_idx=%u pending=%u hw_ptr=%llu reported=%llu fill=%llu periods=%u period_frames=%u rate=%u channels=%u dma_channels=%u desc_frames=%u\n",
			   dir_names[dir], stream->running, stream->hw_idx,
			   stream->pending, stream->hw_ptr_frames,
			   stream->reported_frames, stream->tx_fill_frames,
			   stream->periods, stream->period_frames,
			   stream->rate, stream->channels,
			   stream->dma_channels, stream->desc_frames);
		if (!stream->desc)
			continue;
		for (i = 0; i < AN7581_PCM_NUM_DESC; i++)
			seq_printf(s, "%s_desc%d status=0x%08x chv=0x%08x buf=0x%08x\n",
				   dir_names[dir], i,
				   READ_ONCE(stream->desc[i].status),
				   stream->desc[i].chan_valid,
				   stream->desc[i].buf_addr);
		an7581_pcm_stats_bounce(s, stream, dir_names[dir]);
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

/*
 * CHBFOSR and DCHENR are single registers that both directions share, and the
 * slot map depends on the line rate, so the engine configuration is latched
 * here and applied by one reprogram with both directions stopped. The caller
 * holds cfg_lock across the latch and the reprogram.
 */
static void an7581_pcm_cfg_update(struct an7581_pcm *pcm, unsigned int rate,
				  u32 chbfosr, u32 dchenr)
{
	lockdep_assert_held(&pcm->cfg_lock);

	if (pcm->cfg.rate != rate || pcm->cfg.chbfosr != chbfosr ||
	    pcm->cfg.dchenr != dchenr)
		pcm->cfg_dirty = true;
	pcm->cfg.rate = rate;
	pcm->cfg.chbfosr = chbfosr;
	pcm->cfg.dchenr = dchenr;
}

/*
 * The engine holds the receive framing phase that turns highway bits into
 * descriptor bytes, and a TRDCR receive-DMA disable does not clear it. A
 * restart that only re-enables the DMA can resume one byte late, which shifts
 * the whole capture stream by one byte until the interface restarts.
 *
 * This repeats the sequence that cleared the fault in the field, in the
 * hw_init order and with the hw_init values. It includes the interrupt mask
 * and DMA enable clear, the CFG_VALID drop, the slot registers, CHBFOSR, the
 * DCHENR clear-then-set transition, the CFG_VALID raise, and the interrupt
 * mask restore.
 *
 * It excludes one element of that sequence, the descriptor ring base and size
 * registers. The exclusion is safe: the software ring state stayed healthy
 * through the fault, because hw_ptr advanced at 100 periods a second and the
 * completions never desynced, so the ring needs no repair. A write to a ring
 * base register could move the engine's ring cursor away from hw_idx, which
 * the driver keeps across a stop and a start, so leaving those registers alone
 * removes that question by construction.
 *
 * The caller holds cfg_lock and calls this only with cfg_dirty clear, so
 * pcm->cfg describes the registers the hardware runs.
 */
static void an7581_pcm_iface_resync(struct an7581_pcm *pcm)
{
	u32 picr = readl(pcm->base + REG_PICR);
	u32 imr = readl(pcm->base + REG_IMR);

	writel(0, pcm->base + REG_IMR);
	writel(0, pcm->base + REG_TRDCR);
	writel(picr & ~PICR_CFG_VALID, pcm->base + REG_PICR);

	an7581_pcm_slots_program(pcm);
	writel(pcm->cfg.chbfosr, pcm->base + REG_CHBFOSR);
	an7581_pcm_dchenr_set(pcm, pcm->cfg.dchenr);

	usleep_range(1000, 2000);
	writel(picr | PICR_CFG_VALID, pcm->base + REG_PICR);
	writel(imr, pcm->base + REG_IMR);
}

/*
 * Both forms of re-init drop CFG_VALID, so neither must race a running engine,
 * and the engine must own no descriptor when one starts. They sleep, so callers
 * are process context and hold cfg_lock. A full re-init re-runs the whole
 * hardware setup for a changed configuration. A partial one repeats the
 * interface part of that setup and leaves the descriptor ring registers alone.
 */
static int an7581_pcm_engine_reinit_locked(struct an7581_pcm *pcm, bool full)
{
	unsigned long flags;
	bool busy;
	int dir;

	lockdep_assert_held(&pcm->cfg_lock);

	/*
	 * hw_params holds cfg_lock across the agreement check and this call,
	 * and the agreement covers the rate, the channel count and the period
	 * size, so a dirty config means the other direction has no hw_params
	 * of its own. A conforming caller therefore cannot trigger a stream
	 * between this check and hw_init. The ALSA core does not serialize the
	 * trigger ioctl against hw_params, so the same critical section also
	 * raises the reprogramming flag, which bars a START from any caller
	 * until the handshake ends.
	 */
	spin_lock_irqsave(&pcm->lock, flags);
	busy = pcm->stream[0].running || pcm->stream[1].running;
	if (!busy)
		pcm->reprogramming = true;
	else if (!full)
		pcm->stats.resync_skips_busy++;
	spin_unlock_irqrestore(&pcm->lock, flags);

	if (busy && full) {
		dev_warn_ratelimited(pcm->dev,
				     "reprogram refused, a stream is running\n");
		return -EBUSY;
	}
	if (busy) {
		dev_warn_ratelimited(pcm->dev,
				     "capture resync skipped, the peer stream runs; the restart proceeds without it\n");
		return -EBUSY;
	}

	/*
	 * trigger(STOP) leaves the ring armed on purpose, so the engine can
	 * still own descriptors of a stopped direction. Cancel them before
	 * CFG_VALID drops.
	 */
	for (dir = 0; dir < 2; dir++)
		an7581_pcm_stream_quiesce(pcm, &pcm->stream[dir]);

	if (full)
		an7581_pcm_hw_init(pcm);
	else
		an7581_pcm_iface_resync(pcm);

	spin_lock_irqsave(&pcm->lock, flags);
	pcm->reprogramming = false;
	if (!full)
		pcm->stats.resync_runs++;
	spin_unlock_irqrestore(&pcm->lock, flags);

	return 0;
}

static int an7581_pcm_reprogram_locked(struct an7581_pcm *pcm)
{
	int ret;

	lockdep_assert_held(&pcm->cfg_lock);

	if (!pcm->cfg_dirty)
		return 0;

	ret = an7581_pcm_engine_reinit_locked(pcm, true);
	if (ret)
		return ret;

	pcm->cfg_dirty = false;

	return 0;
}

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
	.rates			= SNDRV_PCM_RATE_8000 |
				  SNDRV_PCM_RATE_16000,
	.rate_min		= AN7581_PCM_RATE_NB,
	.rate_max		= AN7581_PCM_RATE_WB,
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

/*
 * At 16 kHz one ALSA period splits into two engine sample streams, so an odd
 * period has no whole descriptor sample count. Once the rate is fixed at
 * 16 kHz, keep the ends of the period interval even, the way the core's own
 * step constraint does.
 */
static int an7581_pcm_rule_wb_period(struct snd_pcm_hw_params *params,
				     struct snd_pcm_hw_rule *rule)
{
	struct snd_interval *period = hw_param_interval(params, rule->var);
	const struct snd_interval *rate;
	struct snd_interval t;

	rate = hw_param_interval_c(params, SNDRV_PCM_HW_PARAM_RATE);
	if (rate->min < AN7581_PCM_RATE_WB)
		return 0;

	snd_interval_any(&t);
	t.min = round_up(period->min + period->openmin, 2);
	t.max = round_down(period->max - period->openmax, 2);
	t.integer = 1;

	return snd_interval_refine(period, &t);
}

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

	ret = snd_pcm_hw_rule_add(substream->runtime, 0,
				  SNDRV_PCM_HW_PARAM_PERIOD_SIZE,
				  an7581_pcm_rule_wb_period, NULL,
				  SNDRV_PCM_HW_PARAM_RATE, -1);
	if (ret < 0)
		return ret;

	stream = an7581_pcm_substream_get(pcm, substream);
	stream->substream = substream;

	return 0;
}

static int an7581_pcm_close(struct snd_soc_component *component,
			    struct snd_pcm_substream *substream)
{
	struct an7581_pcm *pcm = snd_soc_component_get_drvdata(component);
	struct an7581_pcm_stream *stream;
	unsigned long flags;

	stream = an7581_pcm_substream_get(pcm, substream);
	an7581_pcm_stream_force_idle(pcm, stream, substream->stream);
	an7581_pcm_stream_quiesce(pcm, stream);

	spin_lock_irqsave(&pcm->lock, flags);
	stream->substream = NULL;
	stream->channels = 0;
	stream->rate = 0;
	spin_unlock_irqrestore(&pcm->lock, flags);

	return 0;
}

static int an7581_pcm_hw_params(struct snd_soc_component *component,
				struct snd_pcm_substream *substream,
				struct snd_pcm_hw_params *params)
{
	struct an7581_pcm *pcm = snd_soc_component_get_drvdata(component);
	unsigned int channels = params_channels(params);
	unsigned int rate = params_rate(params);
	unsigned int period_frames = params_period_size(params);
	unsigned int dma_channels = channels;
	unsigned int desc_frames = period_frames;
	struct an7581_pcm_stream *stream, *other;
	unsigned long flags;
	bool conflict;
	int ret;

	stream = an7581_pcm_substream_get(pcm, substream);
	other = &pcm->stream[1 - substream->stream];

	if (rate == AN7581_PCM_RATE_WB && period_frames % 2) {
		dev_err(pcm->dev, "16 kHz needs an even period, got %u\n",
			period_frames);
		return -EINVAL;
	}

	/* a wideband line spends two engine channels on one ALSA channel */
	if (rate == AN7581_PCM_RATE_WB) {
		dma_channels = 2 * channels;
		desc_frames = period_frames / 2;
	}

	mutex_lock(&pcm->cfg_lock);

	/*
	 * DCHENR (channel enable), CHBFOSR (channel stride) and the slot map
	 * are single registers that both DMA directions share, so the two
	 * directions must agree on the channel count, the line rate and the
	 * period size. The mutex covers the check, the latch and the
	 * reprogram, so two first calls cannot both read an unconfigured peer
	 * and then apply different geometries.
	 */
	spin_lock_irqsave(&pcm->lock, flags);
	conflict = other->channels &&
		   (other->channels != channels || other->rate != rate ||
		    other->period_frames != period_frames);
	spin_unlock_irqrestore(&pcm->lock, flags);
	if (conflict) {
		ret = -EBUSY;
		goto out;
	}

	an7581_pcm_cfg_update(pcm, rate, desc_frames * 2,
			      (1 << dma_channels) - 1);
	ret = an7581_pcm_reprogram_locked(pcm);
	if (ret)
		goto out;

	spin_lock_irqsave(&pcm->lock, flags);
	stream->channels = channels;
	stream->rate = rate;
	stream->dma_channels = dma_channels;
	stream->periods = params_periods(params);
	stream->period_frames = period_frames;
	stream->desc_frames = desc_frames;
	stream->chan_bytes = params_buffer_bytes(params) / channels;
	spin_unlock_irqrestore(&pcm->lock, flags);
out:
	mutex_unlock(&pcm->cfg_lock);

	return ret;
}

static int an7581_pcm_hw_free(struct snd_soc_component *component,
			      struct snd_pcm_substream *substream)
{
	struct an7581_pcm *pcm = snd_soc_component_get_drvdata(component);
	struct an7581_pcm_stream *stream;
	unsigned long flags;

	stream = an7581_pcm_substream_get(pcm, substream);
	an7581_pcm_stream_force_idle(pcm, stream, substream->stream);
	an7581_pcm_stream_quiesce(pcm, stream);

	spin_lock_irqsave(&pcm->lock, flags);
	stream->channels = 0;
	stream->rate = 0;
	spin_unlock_irqrestore(&pcm->lock, flags);

	return 0;
}

static int an7581_pcm_prepare(struct snd_soc_component *component,
			      struct snd_pcm_substream *substream)
{
	struct an7581_pcm *pcm = snd_soc_component_get_drvdata(component);
	struct an7581_pcm_stream *stream;

	stream = an7581_pcm_substream_get(pcm, substream);
	if (stream->running)
		return 0;

	an7581_pcm_stream_quiesce(pcm, stream);

	/*
	 * Only the capture direction disables the receive DMA, so only a
	 * capture restart can leave the engine one byte late. The device
	 * advertises neither PAUSE nor RESUME, so the core rejects every
	 * trigger START that this callback does not precede.
	 *
	 * A dirty configuration means pcm->cfg does not describe the running
	 * registers, so the full reprogram applies it. The partial resync
	 * rewrites the slot map and CHBFOSR from pcm->cfg and therefore runs
	 * only when the two agree.
	 *
	 * Both forms need both directions idle, because CFG_VALID cannot drop
	 * under a live stream. An unlinked capture start beside live playback
	 * proceeds without the resync and keeps the behaviour the driver had
	 * before. The stats file counts that case as resync_skips_busy.
	 * Production udsp links the two streams, so its prepares always find
	 * both directions idle and always resync.
	 */
	if (substream->stream != SNDRV_PCM_STREAM_CAPTURE)
		return 0;

	mutex_lock(&pcm->cfg_lock);
	if (pcm->cfg_dirty)
		an7581_pcm_reprogram_locked(pcm);
	else
		an7581_pcm_engine_reinit_locked(pcm, false);
	mutex_unlock(&pcm->cfg_lock);

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
		if (pcm->reprogramming) {
			ret = -EBUSY;
			break;
		}
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
	.close		= an7581_pcm_close,
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
			.rates		= SNDRV_PCM_RATE_8000 |
					  SNDRV_PCM_RATE_16000,
			.formats	= SNDRV_PCM_FMTBIT_S16_LE,
		},
	}, {
		.name = "an7581-pcm-ul",
		.capture = {
			.stream_name	= "an7581-pcm-capture",
			.channels_min	= 1,
			.channels_max	= 2,
			.rates		= SNDRV_PCM_RATE_8000 |
					  SNDRV_PCM_RATE_16000,
			.formats	= SNDRV_PCM_FMTBIT_S16_LE,
		},
	},
};

/*
 * The frame bit every engine channel owns. At 8 kHz channel k owns the k-th
 * 16-bit slot and channels 16 to 31, which the driver never enables, keep
 * their reset values. At 16 kHz line k owns two channels: the SLIC keeps the
 * narrowband timeslot of the line at bit k*16 and sends the second sample of
 * the pair half a frame later, so channel 2k owns bit k*16 and channel 2k+1
 * owns bit k*16 + 128. Channels 16 to 31 then park past the frame, because
 * their reset values are 8-bit slots in the half of the frame the pairs use.
 */
static unsigned int an7581_pcm_start_table(unsigned int rate, u16 *start)
{
	unsigned int k;

	if (rate != AN7581_PCM_RATE_WB) {
		for (k = 0; k < AN7581_PCM_SLOTS; k++)
			start[k] = k * 16 + AN7581_PCM_SLOT_OFF;

		return AN7581_PCM_SLOTS;
	}

	for (k = 0; k < AN7581_PCM_SLOTS / 2; k++) {
		start[2 * k] = k * 16 + AN7581_PCM_SLOT_OFF;
		start[2 * k + 1] = k * 16 + AN7581_PCM_SLOT_OFF +
				   AN7581_PCM_WB_PAIR_OFF;
	}

	for (k = AN7581_PCM_SLOTS; k < AN7581_PCM_HW_SLOTS; k++)
		start[k] = k * 16 + AN7581_PCM_SLOT_OFF;

	return AN7581_PCM_HW_SLOTS;
}

static void an7581_pcm_slots_program(struct an7581_pcm *pcm)
{
	u16 start[AN7581_PCM_HW_SLOTS];
	unsigned int slots;
	unsigned int i;

	slots = an7581_pcm_start_table(pcm->cfg.rate, start);

	for (i = 0; i < slots / 2; i++) {
		u32 slot = TSCR_SLOT0_BW16 | TSCR_SLOT1_BW16 |
			   FIELD_PREP(TSCR_SLOT0_START, start[2 * i]) |
			   FIELD_PREP(TSCR_SLOT1_START, start[2 * i + 1]);

		writel(slot, pcm->base + REG_PTTSCR(i));
		writel(slot, pcm->base + REG_PRTSCR(i));
	}
}

static void an7581_pcm_hw_init(struct an7581_pcm *pcm)
{
	u32 val;

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

	an7581_pcm_slots_program(pcm);

	writel(an7581_pcm_dma_addr(pcm->desc_dma), pcm->base + REG_TDRBAR);
	writel(an7581_pcm_dma_addr(pcm->desc_dma +
				   AN7581_PCM_NUM_DESC *
				   sizeof(struct an7581_pcm_hwdesc)),
	       pcm->base + REG_RDRBAR);
	writel((AN7581_PCM_DESC_STRIDE_DW << 4) | AN7581_PCM_NUM_DESC,
	       pcm->base + REG_TRDRSR);
	/*
	 * aos writes the channel stride and the channel enable inside the
	 * cfg_valid-low window (descInit, pcmConfigSetup) and the trigger path
	 * cannot: CHBFOSR is one register for both directions, so the
	 * direction that started last used to overwrite the other's stride.
	 */
	writel(pcm->cfg.chbfosr, pcm->base + REG_CHBFOSR);
	an7581_pcm_dchenr_set(pcm, pcm->cfg.dchenr);

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
	mutex_init(&pcm->cfg_lock);
	pcm->cfg.rate = AN7581_PCM_RATE_NB;
	pcm->cfg.dchenr = 1;
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
