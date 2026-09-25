# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

# mt79xx SoC dtsi live in the kernel tree; an7581.dtsi comes from the
# upstream airoha target dts, mediatek board dtsi we do not modify from
# the upstream mediatek target dts. Local dts/ shadows both.
DTS_DIR := $(DTS_DIR)/mediatek
DTS_CPPFLAGS += -I$(TOPDIR)/target/linux/airoha/dts \
	-I$(TOPDIR)/target/linux/mediatek/dts

define Device/Default
  PROFILES = Default $$(DEVICE_NAME)
  KERNEL_NAME := Image
  KERNEL = kernel-bin | lzma | \
	fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb
  KERNEL_INITRAMFS = kernel-bin | lzma | \
	fit lzma $$(KDIR)/image-$$(firstword $$(DEVICE_DTS)).dtb with-initrd
  KERNEL_LOADADDR = 0x48000000
  FILESYSTEMS := squashfs
  DEVICE_DTS_DIR := $(DTS_DIR)
  IMAGES := sysupgrade.bin
  IMAGE/sysupgrade.bin := append-kernel | pad-to 128k | append-rootfs | \
	pad-rootfs | append-metadata
endef

include atf-artifacts.mk
include cascade.mk

# Create the mount points before the generic root.squashfs, so that it can
# serve as the .run root file system in Build/SrgDiskSquashfs.
define Image/Prepare
	mkdir -p $(TARGET_DIR)/mnt/FLASH $(TARGET_DIR)/mnt/boot \
		$(TARGET_DIR)/FLASH $(TARGET_DIR)/boot $(TARGET_DIR)/Boot
endef

define Image/Build
	$(call Image/Build/$(1),$(1))
endef

$(eval $(call BuildImage))
