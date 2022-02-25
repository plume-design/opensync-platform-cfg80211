##############################################################################
#
# OSP layer library override
#
##############################################################################

UNIT_SRC_TOP += $(if $(CONFIG_OSP_L2SWITCH_SWCONFIG),$(OVERRIDE_DIR)/src/osp_l2switch_swconfig.c)

UNIT_SRC_TOP += $(OVERRIDE_DIR)/src/osp_upgrade.c
UNIT_EXPORT_CFLAGS := $(UNIT_CFLAGS)
UNIT_EXPORT_LDFLAGS := -lcurl
