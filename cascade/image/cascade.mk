.NOTPARALLEL:

SRGRUN:= TARGET_DIR=$(TARGET_DIR) KDIR=$(KDIR) STAGING_DIR=$(STAGING_DIR_HOST) BIN_DIR=$(BIN_DIR) PACKAGE_DIR=$(TOPDIR)/bin/packages/$(ARCH_PACKAGES) $(TARGET_DIR)/../flash-images/files/srg-image.sh
BINNAME:=$(IMG_PREFIX)-polecat-root.squashfs
VERNAME:=$(VERSION_NUMBER)-$(subst DEVICE_,,$(PROFILE))

# AN7581 DRAM starts at 0x80000000; those boards boot the same kernel
# binary from the k2 FIT node at this address
AIROHA_KERNEL_LOADADDR:=0x80200000

define Device/polecat
  KERNEL_LOADADDR = 0x43200000
  KERNEL_SUFFIX := -fit-multi.itb
  KERNEL_INSTALL := 1
  KERNEL_NAME := Image
  KERNEL = kernel-bin | lzma | SrgFit
  FILESYSTEMS := squashfs
  KERNEL_INITRAMFS :=
  DEVICE_VENDOR := SmartRG
  DEVICE_MODEL := SmartRG Target
  DEVICE_PACKAGES := kmod-hwmon-pwmfan kmod-i2c-gpio kmod-sfp kmod-usb-ohci kmod-usb2 kmod-usb3 kmod-ata-ahci-mtk e2fsprogs f2fsck mkf2fs
  DEVICE_DTS := mt7622-smartrg-srbpi
  DEVICE_DTS += mt7622-smartrg-834-5
  DEVICE_DTS += mt7622-smartrg-841-t6
  DEVICE_DTS += mt7622-smartrg-854-6
  DEVICE_DTS += mt7622-smartrg-854-6-sfp
  DEVICE_DTS += mt7622-smartrg-854-v6
  DEVICE_DTS += mt7622-smartrg-854-v6-sfp
  DEVICE_DTS += mt7622-smartrg-834-v6
  DEVICE_DTS += mt7986a-smartrg-bpi-r3
  DEVICE_DTS += mt7986a-smartrg-SDG-8612
  DEVICE_DTS += mt7986a-smartrg-SDG-8614
  DEVICE_DTS += mt7986a-smartrg-SDG-8622
  DEVICE_DTS += mt7986a-smartrg-SDG-8632
  DEVICE_DTS += mt7981b-smartrg-SDG-8610
  DEVICE_DTS += mt7988a-smartrg-SDG-8733
  DEVICE_DTS += mt7988a-smartrg-SDG-8733v
  DEVICE_DTS += mt7988a-smartrg-SDG-8734
  DEVICE_DTS += mt7988a-smartrg-SDG-8734v
  DEVICE_DTS += mt7988d-smartrg-SDG-8733A
  DEVICE_DTS += mt7988a-smartrg-SDG-8713
  DEVICE_DTS += mt7988a-smartrg-SDG-8713v
  DEVICE_DTS += mt7988a-smartrg-SDG-8733B
  DEVICE_DTS += mt7987a-smartrg-SDG-8712
  DEVICE_DTS += mt7987a-smartrg-SDG-8712v
  DEVICE_DTS += mt7987a-smartrg-SDG-8732
  DEVICE_DTS += mt7987a-smartrg-SDG-8732v
  DEVICE_DTS += mt7988a-smartrg-SDG-9000
  DEVICE_DTS += mt7988d-smartrg-SDG-9732i
  DEVICE_DTS += mt7988d-smartrg-SDG-9712o
  DEVICE_DTS += an7581-smartrg-SDG-8716v
  DEVICE_DTS += an7581-smartrg-SDG-8716v-eth
  DEVICE_DTS += an7581-smartrg-SDG-8736v
  DEVICE_DTS += an7581-smartrg-SDG-8736v-eth
  DEVICE_DTS_DIR := ../dts
  DEVICE_PACKAGES += kmod-i2c-an7581
  ARTIFACTS := emmc-preloader.bin emmc-bl31-uboot.fip \
	an7581-preloader.bin an7581-bl31-uboot.fip an7581-bl2-bl31-uboot.bin
  ARTIFACT/emmc-preloader.bin := mt7986-bl2 emmc-ddr4
  ARTIFACT/emmc-bl31-uboot.fip := mt7986-bl31-uboot smartrg_bonanza
  ARTIFACT/an7581-preloader.bin := an7581-preloader smartrg_dragontail
  ARTIFACT/an7581-bl31-uboot.fip := an7581-bl31-uboot smartrg_dragontail
  ARTIFACT/an7581-bl2-bl31-uboot.bin := an7581-emmc-bl2-bl31-uboot smartrg_dragontail
  DTC_FLAGS += -@
  IMAGES := root.squashfs img img.run
  IMAGE/root.squashfs := SrgDisk
  IMAGE/img := srgImage
  export DEVICE_DTS
endef
TARGET_DEVICES := polecat

# Dev-only AN7581 evb (not in production images): add to Device/polecat
#   DEVICE_DTS += an7581-smartrg-evb-emmc
# and to Build/SrgFit
#   -i "SDG-an7581-rfb" -d $(KDIR)/image-an7581-smartrg-evb-emmc.dtb.lzma -C lzma -h "crc32" -h "sha1" \
#   -c "303" -K k2 -R rdisk -D "SDG-an7581-rfb" \

define Build/SrgFit

	# lzma compress the dtb files
	$(eval $(foreach S,$(DEVICE_DTS),$(shell $(STAGING_DIR_HOST)/bin/lzma e -lc1 -lp2 -pb2 $(KDIR)/image-$(S).dtb $(KDIR)/image-$(S).dtb.lzma)))

	srg-mkits.sh -o $@.its -A $(LINUX_KARCH)  -v $(LINUX_VERSION) \
	   	-i "k1" -k $@ -a $(KERNEL_LOADADDR) -e $(if $(KERNEL_ENTRY),$(KERNEL_ENTRY),$(KERNEL_LOADADDR)) -C lzma -h "crc32" -h "sha1" \
		-i "k2" -k $@ -a $(AIROHA_KERNEL_LOADADDR) -e $(AIROHA_KERNEL_LOADADDR) -C lzma -h "crc32" -h "sha1" \
		-i "rdisk" -r $(STAGING_DIR_IMAGE)/$(IMG_PREFIX)-initramfs.cpio.gz -h "crc32" -h "sha1" \
		-i "srbpi" -d $(KDIR)/image-mt7622-smartrg-srbpi.dtb -h "crc32" -h "sha1" \
		-i "834-5" -d $(KDIR)/image-mt7622-smartrg-834-5.dtb -h "crc32" -h "sha1" \
		-i "841-t6" -d $(KDIR)/image-mt7622-smartrg-841-t6.dtb -h "crc32" -h "sha1" \
		-i "854-v6" -d $(KDIR)/image-mt7622-smartrg-854-v6.dtb -h "crc32" -h "sha1" \
		-i "854-v6-SFP" -d $(KDIR)/image-mt7622-smartrg-854-v6-sfp.dtb -h "crc32" -h "sha1" \
		-i "834-v6" -d $(KDIR)/image-mt7622-smartrg-834-v6.dtb -h "crc32" -h "sha1" \
		-i "854-6" -d $(KDIR)/image-mt7622-smartrg-854-6.dtb -h "crc32" -h "sha1" \
		-i "854-6-SFP" -d $(KDIR)/image-mt7622-smartrg-854-6-sfp.dtb -h "crc32" -h "sha1" \
		-i "srbpi-r3" -d $(KDIR)/image-mt7986a-smartrg-bpi-r3.dtb -h "crc32" -h "sha1" \
		-i "SDG-8612" -d $(KDIR)/image-mt7986a-smartrg-SDG-8612.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8614" -d $(KDIR)/image-mt7986a-smartrg-SDG-8614.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8622" -d $(KDIR)/image-mt7986a-smartrg-SDG-8622.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8632" -d $(KDIR)/image-mt7986a-smartrg-SDG-8632.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8610" -d $(KDIR)/image-mt7981b-smartrg-SDG-8610.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8733" -d $(KDIR)/image-mt7988a-smartrg-SDG-8733.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8733v" -d $(KDIR)/image-mt7988a-smartrg-SDG-8733v.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8734" -d $(KDIR)/image-mt7988a-smartrg-SDG-8734.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8734v" -d $(KDIR)/image-mt7988a-smartrg-SDG-8734v.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8733A" -d $(KDIR)/image-mt7988d-smartrg-SDG-8733A.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8713" -d $(KDIR)/image-mt7988a-smartrg-SDG-8713.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8713v" -d $(KDIR)/image-mt7988a-smartrg-SDG-8713v.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8733B" -d $(KDIR)/image-mt7988a-smartrg-SDG-8733B.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8712" -d $(KDIR)/image-mt7987a-smartrg-SDG-8712.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8712v" -d $(KDIR)/image-mt7987a-smartrg-SDG-8712v.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8732" -d $(KDIR)/image-mt7987a-smartrg-SDG-8732.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8732v" -d $(KDIR)/image-mt7987a-smartrg-SDG-8732v.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-9000" -d $(KDIR)/image-mt7988a-smartrg-SDG-9000.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-9732i" -d $(KDIR)/image-mt7988d-smartrg-SDG-9732i.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-9712o" -d $(KDIR)/image-mt7988d-smartrg-SDG-9712o.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8716v" -d $(KDIR)/image-an7581-smartrg-SDG-8716v.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8716v-eth" -d $(KDIR)/image-an7581-smartrg-SDG-8716v-eth.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8736v" -d $(KDIR)/image-an7581-smartrg-SDG-8736v.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-i "SDG-8736v-eth" -d $(KDIR)/image-an7581-smartrg-SDG-8736v-eth.dtb.lzma -C lzma -h "crc32" -h "sha1" \
		-c "300" -K k1 -R rdisk -D "srbpi" \
		-c "402" -K k1 -R rdisk -D "834-5" \
		-c "403" -K k1 -R rdisk -D "834-5" \
		-c "404" -K k1 -R rdisk -D "841-t6" \
		-c "405" -K k1 -R rdisk -D "854-v6" \
		-c "405-SFP" -K k1 -R rdisk -D "854-v6-SFP" \
		-c "406" -K k1 -R rdisk -D "854-v6" \
		-c "406-SFP" -K k1 -R rdisk -D "854-v6-SFP" \
		-c "407" -K k1 -R rdisk -D "834-v6" \
		-c "415" -K k1 -R rdisk -D "854-6" \
		-c "415-SFP" -K k1 -R rdisk -D "854-6-SFP" \
		-c "416" -K k1 -R rdisk -D "854-6" \
		-c "416-SFP" -K k1 -R rdisk -D "854-6-SFP" \
		-c "302" -K k1 -R rdisk -D "srbpi-r3" \
		-c "420" -K k1 -R rdisk -D "SDG-8612" -T "smartrg,sdg-8612" \
		-c "421" -K k1 -R rdisk -D "SDG-8614" -T "smartrg,sdg-8614" \
		-c "422" -K k1 -R rdisk -D "SDG-8622" -T "smartrg,sdg-8622" \
		-c "423" -K k1 -R rdisk -D "SDG-8632" -T "smartrg,sdg-8632" \
		-c "424" -K k1 -R rdisk -D "SDG-8610" -T "smartrg,sdg-8610" \
		-c "430" -K k1 -R rdisk -D "SDG-8733" -T "smartrg,sdg-8733" \
		-c "431" -K k1 -R rdisk -D "SDG-8733v" -T "smartrg,sdg-8733v" \
		-c "432" -K k1 -R rdisk -D "SDG-8734" -T "smartrg,sdg-8734" \
		-c "433" -K k1 -R rdisk -D "SDG-8734v" -T "smartrg,sdg-8734v" \
		-c "434" -K k1 -R rdisk -D "SDG-8733A" -T "smartrg,sdg-8733a" \
		-c "435" -K k1 -R rdisk -D "SDG-8713" -T "smartrg,sdg-8713" \
		-c "436" -K k1 -R rdisk -D "SDG-8713v" -T "smartrg,sdg-8713v" \
		-c "437" -K k1 -R rdisk -D "SDG-8733B" -T "smartrg,sdg-8733b" \
		-c "440" -K k1 -R rdisk -D "SDG-8712" -T "smartrg,sdg-8712" \
		-c "441" -K k1 -R rdisk -D "SDG-8712v" -T "smartrg,sdg-8712v" \
		-c "442" -K k1 -R rdisk -D "SDG-8732" -T "smartrg,sdg-8732" \
		-c "443" -K k1 -R rdisk -D "SDG-8732v" -T "smartrg,sdg-8732v" \
		-c "500" -K k1 -R rdisk -D "SDG-9000" -T "smartrg,sdg-9000" \
		-c "510" -K k1 -R rdisk -D "SDG-9732i" -T "smartrg,sdg-9732i" \
		-c "511" -K k1 -R rdisk -D "SDG-9712o" -T "smartrg,sdg-9712o" \
		-c "600" -K k2 -R rdisk -D "SDG-8716v" \
		-c "601" -K k2 -R rdisk -D "SDG-8736v" \
		-c "1600" -K k2 -R rdisk -D "SDG-8716v-eth" \
		-c "1601" -K k2 -R rdisk -D "SDG-8736v-eth" \
		-c "799" -K k1 -R rdisk -D "SDG-8712v" -T "smartrg,sdg-8712v"

	PATH=$(LINUX_DIR)/scripts/dtc:$(PATH) mkimage -f $@.its $@.new
	python3 $(TOPDIR)/target/linux/$(BOARD)/image/srg-fit-dedup.py $@.new kernel@k2 kernel@k1
	@mv -f $@.new $@

endef

define Build/SrgDiskSquashfs
	@echo "Creating SRG squashfs Image"
	mkdir -p $(TARGET_DIR)/mnt/FLASH
	mkdir -p $(TARGET_DIR)/mnt/boot
	mkdir -p $(TARGET_DIR)/FLASH
	mkdir -p $(TARGET_DIR)/boot
	mkdir -p $(TARGET_DIR)/Boot
	$(STAGING_DIR_HOST)/bin/mksquashfs4 $(TARGET_DIR) $(KDIR)/root.squashfs.run \
		-nopad -noappend -root-owned \
		-comp $(SQUASHFSCOMP) $(SQUASHFSOPT)
	$(CP) $(KDIR)/root.squashfs.run $(KDIR)/root.squashfs.run.bin
	dd if=/dev/zero bs=128k count=1 >> $(KDIR)/root.squashfs.run.bin
	sha256sum  $(KDIR)/root.squashfs.run.bin  | cut -d ' ' -f 1 | xargs echo -n  >> $(KDIR)/root.squashfs.run.bin
	$(CP) $(KDIR)/root.squashfs.run.bin $(KDIR)/$(BINNAME).run.bin

	sha256sum  $(BIN_DIR)/$(IMG_PREFIX)-polecat-fit-multi.itb | cut -d ' ' -f 1 | xargs echo -n  >> $(BIN_DIR)/$(IMG_PREFIX)-polecat-fit-multi.itb
	$(CP) $(BIN_DIR)/$(IMG_PREFIX)-polecat-fit-multi.itb $(TARGET_DIR)/Boot/fit-multi.itb
	$(STAGING_DIR_HOST)/bin/mksquashfs4 $(TARGET_DIR) $(KDIR)/root.squashfs \
		-nopad -noappend -root-owned \
		-comp $(SQUASHFSCOMP) $(SQUASHFSOPT)
	$(CP) $(KDIR)/root.squashfs $(KDIR)/root.squashfs.bin
	dd if=/dev/zero bs=128k count=1 >> $(KDIR)/root.squashfs.bin
	sha256sum  $(KDIR)/root.squashfs.bin  | cut -d ' ' -f 1 | xargs echo -n  >> $(KDIR)/root.squashfs.bin
	$(CP) $(KDIR)/root.squashfs.bin $(KDIR)/$(BINNAME).bin
	$(CP) $(KDIR)/root.squashfs.bin $(BIN_DIR)/
	ln -sfr $(BIN_DIR)/root.squashfs.bin $(BIN_DIR)/root.squashfs.img
	ln -sfr $(BIN_DIR)/$(IMG_PREFIX)-polecat-fit-multi.itb $(BIN_DIR)/fit-multi.itb
endef

define Build/SrgDisk
    $(call Build/SrgDiskSquashfs)
endef

define Build/srgImage
	@echo "Build generic image and .run image"
	bash -c "$(SRGRUN) SRGImages $(BINNAME).bin $(VERNAME)"
	bash -c "CDT= $(SRGRUN) RUNIMG $(BINNAME) $(VERNAME) $(IMG_PREFIX)"
	bash -c "CDT=factory $(SRGRUN) RUNIMG $(BINNAME) $(VERNAME) $(IMG_PREFIX)"
endef

define Build/srgImageRun
	rm -rf $(KDIR)/img_stage
	mkdir -p $(KDIR)/img_stage
	mkdir -p $(KDIR)/img_stage/cdt
	mkdir -p $(KDIR)/img_stage/allcdts
	rm -f $(KDIR)/metadata
	touch $(KDIR)/metadata
	if [ $(1) ]; then \
		if [ "$(1)" = "allcdts" ]; then\
			find $(wildcard $(PACKAGE_SUBDIRS)) -type f -name 'cdt-*.ipk' -exec cp "{}" $(KDIR)/img_stage/allcdts \; ; \
			echo "CDT=all" >> $(KDIR)/metadata; \
		else\
			CDT_IPK=`find $(wildcard $(PACKAGE_SUBDIRS)) -type f -name 'cdt-$(1)_*.ipk' -print -quit` ; \
			cp $$CDT_IPK $(KDIR)/img_stage/cdt ; \
			echo "CDT=\"$(1)\"" >> $(KDIR)/metadata; \
			echo "CDT_VERSION=\"$(CDT_VERSION)\"" >> $(KDIR)/metadata; \
		fi\
	else \
		echo "CDT=" >> $(KDIR)/metadata; \
	fi
	cat $(TARGET_DIR)/etc/openwrt_release | sed "s/'/\"/g" >> $(KDIR)/metadata
	cat $(TARGET_DIR)/../flash-images/files/scripts/arch_platforms.sh | grep PLATFORMS >> $(KDIR)/metadata
	# for debugging add
		# --keep --verbose
	$(STAGING_DIR_HOST)/bin/sos_bld_run.py \
		--lsm $(KDIR)/metadata \
		--img_type SOS_UPGRADE \
		--encrypt \
		--self_install self-upgrade.sh \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/self-upgrade.sh "." \
		--add_image_file $(KDIR)/img_stage/ "." \
		--add_image_file $(TARGET_DIR)/../flash-images/files/scripts/ check_scripts/ \
		--add_image_file $(TARGET_DIR)/Boot Boot/ \
		--add_image_file $(BIN_DIR)/$(IMG_PREFIX)-polecat-fit-multi.itb Boot/fit-multi.itb \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/img.sh scripts/ \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/flash-manage.sh scripts/ \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/emmc-manage.sh scripts/ \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/emmc-disk-layout-1.sh scripts/ \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/emmc-disk-layout-2.sh scripts/ \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/emmc-disk-layout-info.sh scripts/ \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/console_manage.sh scripts/ \
		--add_image_file $(TARGET_DIR)/etc/openwrt_release etc/ \
		--add_image_file $(KDIR)/root.squashfs.run.bin root.squashfs.bin \
		--out_file $(KDIR)/$(BINNAME).run
	$(CP) $(KDIR)/$(BINNAME).run $(BIN_DIR)/$(BINNAME)$(if $(1),-$(1)-$(CDT_VERSION),).run
	@echo "RUNNING BuildPackage alt-os-image"
	mkdir -p $(BIN_DIR)/alt-os-images
	$(STAGING_DIR_HOST)/bin/alt-os-images/transition.sh -f plumeos -t sos -i $(BIN_DIR)/$(BINNAME)$(if $(1),-$(1)-$(CDT_VERSION),).run -d $(BIN_DIR)/alt-os-images

	# Create SOS_HOT_FIX version. Will install image on the system without shutdown/reboot.
	# Next boot will use the installed image.
#	@echo "#!/usr/bin/env bash" > $(KDIR)/post_sos_hot_fix.sh
#	@echo "echo \"Running post_sos_hot_fix.sh\"" >> $(KDIR)/post_sos_hot_fix.sh
#	@echo "exit 1" >> $(KDIR)/post_sos_hot_fix.sh
#
#	$(STAGING_DIR_HOST)/bin/sos_bld_run.py \
		--lsm $(KDIR)/metadata \
		--img_type SOS_HOT_FIX \
		--encrypt \
		--self_install self-upgrade.sh \
		--add_image_file $(KDIR)/post_sos_hot_fix.sh "post_upgrade/" \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/self-upgrade.sh "." \
		--add_image_file $(KDIR)/img_stage/ "." \
		--add_image_file $(TARGET_DIR)/../flash-images/files/scripts/ check_scripts/ \
		--add_image_file $(TARGET_DIR)/Boot Boot/ \
		--add_image_file $(BIN_DIR)/$(IMG_PREFIX)-polecat-fit-multi.itb Boot/fit-multi.itb \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/img.sh scripts/ \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/flash-manage.sh scripts/ \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/emmc-manage.sh scripts/ \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/emmc-disk-layout-1.sh scripts/ \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/emmc-disk-layout-2.sh scripts/ \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/emmc-disk-layout-info.sh scripts/ \
		--add_image_file $(TARGET_DIR)/usr/srg/scripts/console_manage.sh scripts/ \
		--add_image_file $(TARGET_DIR)/etc/openwrt_release etc/ \
		--add_image_file $(KDIR)/root.squashfs.run.bin root.squashfs.bin \
		--out_file $(KDIR)/$(BINNAME)_HOT_FIX.run
#	$(CP) $(KDIR)/$(BINNAME)_HOT_FIX.run $(BIN_DIR)/$(BINNAME)$(if $(1),-$(1),)_HOT_FIX.run

endef

define Image/Flash/mkflash_emmc
	@echo "BUILD FLASH image CDT : $(1)"
	CDT_IPK=`find $(wildcard $(PACKAGE_SUBDIRS)) -type f -name 'cdt-$(1)_*.ipk' -print -quit` ; \
	OUT_DIR="$(BIN_DIR)/flashprogram_bins"; \
	mkdir -p $$OUT_DIR; \
	if [ $(3) ]; then \
		IMGFLAG="-i $(3)"; \
	else \
		IMGFLAG=""; \
	fi; \
	mk_emmc_mfg_image.sh $${IMGFLAG} -e $(2) -r $(TARGET_DIR) -R $(BIN_DIR)/root.squashfs.bin -b $(BIN_DIR) -c $$CDT_IPK -d $$OUT_DIR/$(IMG_PREFIX)-polecat-emmc-mfg-$(2)-$(1).bin
endef

#
# The following targets are called from the flash-images package Makefile
#  Each calls back to the flash-images SRGRUN=srg-image.sh
#  BINNAME and VERNAME are computed here locally.
#  CDT [ENUM] [IMGFLAG] are env variables passed on the cmdline.
#

flashme:
	@echo "Creating FLASH image"
	$(call Image/Flash/mkflash_emmc,$(CDT),$(ENUM),$(IMGFLAG))

cdt-image:
	@echo "Build CDT image $(CDT)"
	bash -c "CDT=$(CDT) $(SRGRUN) CDT $(BINNAME) $(VERNAME)"
	bash -c "CDT=$(CDT) $(SRGRUN) RUNIMG $(BINNAME) $(VERNAME)"

mini-cdt-image:
	@echo "Build Mini CDT image $(CDT)"
	bash -c "CDT=$(CDT) $(SRGRUN) miniCDT $(BINNAME) $(VERNAME)"

allcdt-image:
	@echo "Build ALL CDT image"
	bash -c "CDT=allcdts $(SRGRUN) ALLCDT $(BINNAME) $(VERNAME)"
	bash -c "CDT=allcdts $(SRGRUN) RUNIMG $(BINNAME) $(VERNAME) $(IMG_PREFIX)"

trans-image:
	@echo "Build SOS to PLOS transition image"
	bash -c "CDT=$(CDT) $(SRGRUN) TRANSIMG $(BINNAME) $(VERNAME) $(IMG_PREFIX)"


