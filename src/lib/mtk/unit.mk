##############################################################################
#
# nl80211 vendor specific helpers for Mediatek
#
##############################################################################
UNIT_NAME := mtk
UNIT_DISABLE := $(if $(CONFIG_PLATFORM_IS_MTK),n,y)
UNIT_TYPE := LIB
UNIT_SRC += src/mtk_ap_mld_info.c
UNIT_SRC += src/mtk_assoc_req_frm.c
UNIT_SRC += src/mtk_dfs_cac_req_frm.c
UNIT_SRC += src/mtk_family_id.c
UNIT_SRC += src/mtk_sta_mld_info.c
UNIT_SRC += src/mtk_vendor_cmd.c
UNIT_CFLAGS := -I$(UNIT_PATH)/inc
UNIT_CFLAGS += $(if $(LIBNL3_HEADERS),$(LIBNL3_HEADERS),-I$(TARGET_DIR)/usr/include/libnl3)
UNIT_LDFLAGS += -lnl-3
UNIT_LDFLAGS += -lnl-genl-3
UNIT_EXPORT_CFLAGS := $(UNIT_CFLAGS)
UNIT_EXPORT_LDFLAGS := $(UNIT_LDFLAGS)
UNIT_DEPS += src/lib/ds
UNIT_DEPS += src/lib/common
UNIT_DEPS += src/lib/cr
