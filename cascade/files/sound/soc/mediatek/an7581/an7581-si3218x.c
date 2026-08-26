// SPDX-License-Identifier: GPL-2.0
/*
 * ASoC machine driver binding the Airoha EN7581 telephony PCM engine to
 * the d2,slic-dummy-codec stub. The real SLIC (Si32184/Si32282) is
 * controlled from userspace over spidev; the kernel only moves PCM data.
 *
 * DT binding:
 *	sound_si3218x {
 *		compatible = "airoha,an7581-si3218x-sound";
 *		platform { sound-dai = <&voip_pcm>; };
 *		codec { sound-dai = <&dummy_codec>; };
 *	};
 */

#include <linux/module.h>
#include <linux/of.h>
#include <sound/soc.h>

SND_SOC_DAILINK_DEFS(playback,
	DAILINK_COMP_ARRAY(COMP_CPU("an7581-pcm-dl")),
	DAILINK_COMP_ARRAY(COMP_CODEC(NULL, "slic-dummy-aif")),
	DAILINK_COMP_ARRAY(COMP_EMPTY()));

SND_SOC_DAILINK_DEFS(capture,
	DAILINK_COMP_ARRAY(COMP_CPU("an7581-pcm-ul")),
	DAILINK_COMP_ARRAY(COMP_CODEC(NULL, "slic-dummy-aif")),
	DAILINK_COMP_ARRAY(COMP_EMPTY()));

static struct snd_soc_dai_link an7581_si3218x_dai_links[] = {
	{
		.name = "si3218x-playback",
		.stream_name = "si3218x-playback",
		.playback_only = 1,
		SND_SOC_DAILINK_REG(playback),
	},
	{
		.name = "si3218x-capture",
		.stream_name = "si3218x-capture",
		.capture_only = 1,
		SND_SOC_DAILINK_REG(capture),
	},
};

static struct snd_soc_card an7581_si3218x_card = {
	.name = "an7581-si3218x",
	.owner = THIS_MODULE,
	.dai_link = an7581_si3218x_dai_links,
	.num_links = ARRAY_SIZE(an7581_si3218x_dai_links),
};

static int an7581_si3218x_machine_probe(struct platform_device *pdev)
{
	struct snd_soc_card *card = &an7581_si3218x_card;
	struct device_node *platform_dai_node, *codec_dai_node;
	struct device_node *node;
	struct snd_soc_dai_link *dai_link;
	int ret, i;

	card->dev = &pdev->dev;

	node = of_get_child_by_name(pdev->dev.of_node, "platform");
	if (!node)
		return dev_err_probe(&pdev->dev, -EINVAL,
				     "property 'platform' missing\n");
	platform_dai_node = of_parse_phandle(node, "sound-dai", 0);
	of_node_put(node);
	if (!platform_dai_node)
		return dev_err_probe(&pdev->dev, -EINVAL,
				     "failed to parse platform/sound-dai\n");

	node = of_get_child_by_name(pdev->dev.of_node, "codec");
	if (!node) {
		ret = dev_err_probe(&pdev->dev, -EINVAL,
				    "property 'codec' missing\n");
		goto err_put_platform;
	}
	codec_dai_node = of_parse_phandle(node, "sound-dai", 0);
	of_node_put(node);
	if (!codec_dai_node) {
		ret = dev_err_probe(&pdev->dev, -EINVAL,
				    "failed to parse codec/sound-dai\n");
		goto err_put_platform;
	}

	for_each_card_prelinks(card, i, dai_link) {
		dai_link->cpus->of_node = platform_dai_node;
		dai_link->platforms->of_node = platform_dai_node;
		dai_link->codecs->of_node = codec_dai_node;
	}

	ret = devm_snd_soc_register_card(&pdev->dev, card);
	if (ret)
		dev_err_probe(&pdev->dev, ret, "failed to register card\n");

	of_node_put(codec_dai_node);
err_put_platform:
	of_node_put(platform_dai_node);
	return ret;
}

static const struct of_device_id an7581_si3218x_machine_dt_match[] = {
	{ .compatible = "airoha,an7581-si3218x-sound" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, an7581_si3218x_machine_dt_match);

static struct platform_driver an7581_si3218x_machine = {
	.driver = {
		.name = "an7581-si3218x",
		.of_match_table = an7581_si3218x_machine_dt_match,
	},
	.probe = an7581_si3218x_machine_probe,
};
module_platform_driver(an7581_si3218x_machine);

MODULE_DESCRIPTION("Airoha AN7581 SI3218X ALSA SoC machine driver");
MODULE_LICENSE("GPL");
