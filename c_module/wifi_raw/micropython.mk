# Makefile fragment for MicroPython user C module: _wifi_raw
#
# Usage:  make USER_C_MODULES=/path/to/c_module/wifi_raw

WIFI_RAW_MOD_DIR := $(USERMOD_DIR)

SRC_USERMOD += $(WIFI_RAW_MOD_DIR)/wifi_raw.c

CFLAGS_USERMOD += -I$(WIFI_RAW_MOD_DIR)
