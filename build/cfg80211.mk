OS_CFLAGS += -I$(STAGING_DIR)/usr/include/protobuf-c

CC             = $(TOOLCHAIN_DIR)/bin/$(TOOLCHAIN_PREFIX)gcc
CXX            = $(TOOLCHAIN_DIR)/bin/$(TOOLCHAIN_PREFIX)g++
AR             = $(TOOLCHAIN_DIR)/bin/$(TOOLCHAIN_PREFIX)ar
STRIP          = $(TOOLCHAIN_DIR)/bin/$(TOOLCHAIN_PREFIX)strip -g

SDK_MKSQUASHFS_CMD = $(STAGING_DIR)/../host/bin/mksquashfs4
SDK_MKSQUASHFS_ARGS = -noappend -root-owned -comp xz

# libnl3 (netlink lib) has separate dir
LIBNL3_HEADERS = -I/usr/include/libnl3
export LIBNL3_HEADERS
