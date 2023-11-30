
# Add flowtable handlers

UNIT_SRC_TOP += $(OVERRIDE_DIR)/src/nm2_flowtable.c

UNIT_LDFLAGS += -lpcap

UNIT_DEPS += src/lib/hw_acc
