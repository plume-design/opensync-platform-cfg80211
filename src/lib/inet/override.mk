UNIT_CFLAGS += -I$(OVERRIDE_DIR)/inc

ifdef CONFIG_QCA_USE_GRE_NSS
UNIT_SRC_TOP += $(OVERRIDE_DIR)/src/inet_nssgre.c
endif
