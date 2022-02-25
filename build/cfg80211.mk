CFLAGS += -I$(STAGING_DIR)/usr/include/protobuf-c

CC             = $(TOOLCHAIN_DIR)/bin/$(TOOLCHAIN_PREFIX)gcc
CXX            = $(TOOLCHAIN_DIR)/bin/$(TOOLCHAIN_PREFIX)g++
AR             = $(TOOLCHAIN_DIR)/bin/$(TOOLCHAIN_PREFIX)ar
STRIP          = $(TOOLCHAIN_DIR)/bin/$(TOOLCHAIN_PREFIX)strip -g
