##############################################################################
#
# NL80211 interface abstraction layer
#
##############################################################################
UNIT_NAME := nl80211

UNIT_DISABLE := $(if $(CONFIG_NL80211_INTERFACE_LAYER),n,y)

UNIT_TYPE := LIB

UNIT_SRC := src/util.c
UNIT_SRC += src/nl_util.c
UNIT_SRC += src/nl80211_target.c
UNIT_SRC += src/nl80211_client.c
UNIT_SRC += src/nl80211_scan.c
UNIT_SRC += src/nl80211_survey.c
UNIT_SRC += src/nl80211_stats.c
UNIT_SRC += src/nl80211_device.c
UNIT_SRC += src/nl80211_bsal.c

UNIT_CFLAGS := -I$(UNIT_PATH)/inc
UNIT_CFLAGS += -I$(STAGING_DIR)/usr/include/libnl3/
UNIT_CFLAGS += -Isrc/lib/datapipeline/inc
UNIT_CFLAGS += -I$(UNIT_PATH)/../bsal/inc/

UNIT_LDFLAGS := -lev -lnl-3 -lnl-genl-3

UNIT_DEPS_CFLAGS := src/lib/target

UNIT_EXPORT_CFLAGS := $(UNIT_CFLAGS)
UNIT_EXPORT_LDFLAGS := $(UNIT_LDFLAGS)

UNIT_DEPS += src/lib/ds
UNIT_DEPS += src/lib/common
UNIT_DEPS += src/lib/schema
