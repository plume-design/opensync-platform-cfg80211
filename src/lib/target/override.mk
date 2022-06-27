###############################################################################
#
# Unit override for target library
#
###############################################################################

# Common target library sources
UNIT_SRC := $(TARGET_COMMON_SRC)

# Platform specific target library sources
UNIT_SRC_PLATFORM := $(OVERRIDE_DIR)
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_stats.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_cfg80211.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/wiphy_info.c

UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_nl80211_init.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_switch.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_mcproxy.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/hostapd_util.c
UNIT_SRC_TOP += $(UNIT_SRC_PLATFORM)/target_util.c
UNIT_SRC_TOP += $(OVERRIDE_DIR)/ssdk_util.c
UNIT_SRC_TOP += $(OVERRIDE_DIR)/mcproxy_util.c

UNIT_CFLAGS += -I$(OVERRIDE_DIR)
UNIT_CFLAGS += -I$(OVERRIDE_DIR)/inc

UNIT_LDFLAGS += -lnl-3
UNIT_LDFLAGS += -lnl-genl-3

ifeq ($(CONFIG_NL80211_INTERFACE_LAYER),y)
UNIT_DEPS += $(PLATFORM_DIR)/src/lib/nl80211
endif

UNIT_DEPS += $(PLATFORM_DIR)/src/lib/bsal
UNIT_DEPS += src/lib/hostap
UNIT_DEPS_CFLAGS += src/lib/crt
UNIT_DEPS_CFLAGS += src/lib/json_util
UNIT_DEPS_CFLAGS += src/lib/ovsdb
UNIT_DEPS_CFLAGS += src/lib/daemon

UNIT_EXPORT_CFLAGS := -I$(UNIT_PATH)
UNIT_EXPORT_LDFLAGS += $(SDK_LIB_DIR) -lm $(UNIT_LDFLAGS)

STAGING_USR_LIB ?= $(STAGING_DIR)/usr/lib

$(UNIT_BUILD)/os_unix.o: $(STAGING_USR_LIB)/os_unix.o
	cp $< $@

$(UNIT_BUILD)/wpa_ctrl.o: $(STAGING_USR_LIB)/wpa_ctrl.o
	cp $< $@

UNIT_OBJ += $(UNIT_BUILD)/os_unix.o
UNIT_OBJ += $(UNIT_BUILD)/wpa_ctrl.o

UNIT_EXPORT_CFLAGS := $(UNIT_CFLAGS)
