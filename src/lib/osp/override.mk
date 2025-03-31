##############################################################################
#
# OSP layer library override
#
##############################################################################

UNIT_SRC_TOP += $(OVERRIDE_DIR)/src/osp_temp_platform.c

UNIT_CFLAGS += -I$(OVERRIDE_DIR)/inc
