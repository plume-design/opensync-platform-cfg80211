#
# Override file for OSN
#


# Multicast OSN backend
ifneq "$(or $(CONFIG_OSN_BACKEND_IGMP_MTK),$(CONFIG_OSN_BACKEND_MLD_MTK))" ""
UNIT_CFLAGS += -I$(OVERRIDE_DIR)/inc
UNIT_SRC_TOP += $(OVERRIDE_DIR)/src/osn_mcast_bridge_mtk.c
endif

UNIT_SRC_TOP += $(if $(CONFIG_OSN_BACKEND_IGMP_MTK),$(OVERRIDE_DIR)/src/osn_igmp_mtk.c,)
UNIT_SRC_TOP += $(if $(CONFIG_OSN_BACKEND_MLD_MTK),$(OVERRIDE_DIR)/src/osn_mld_mtk.c,)
UNIT_SRC_TOP += $(if $(CONFIG_OSN_BACKEND_QOS_MTK),$(OVERRIDE_DIR)/src/osn_qos_mtk.c,)
