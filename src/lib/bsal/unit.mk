##############################################################################
#
# Band Steering Abstraction Library
#
##############################################################################

UNIT_NAME := bsal
UNIT_TYPE := LIB

UNIT_SRC += src/bsal.c

UNIT_CFLAGS := -I$(UNIT_PATH)/inc
UNIT_CFLAGS += -I$(STAGING_DIR)/usr/include/libnl3/
UNIT_EXPORT_CFLAGS := $(UNIT_CFLAGS)

UNIT_DEPS_CFLAGS := src/lib/target

UNIT_DEPS += src/lib/common
UNIT_DEPS += src/lib/ds
UNIT_DEPS += src/lib/const
