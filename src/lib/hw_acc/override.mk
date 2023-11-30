########################################################################
#
# Hardware Acceleration Flow Flush Libraries
#
########################################################################

UNIT_SRC := $(filter-out src/hw_acc.c,$(UNIT_SRC))
UNIT_SRC_TOP += $(OVERRIDE_DIR)/src/hw_acc.c

UNIT_DEPS := src/lib/log
UNIT_DEPS += src/lib/kconfig
UNIT_DEPS += src/lib/common
