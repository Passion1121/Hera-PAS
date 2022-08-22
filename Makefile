# root directory
ROOT_DIR = $(shell pwd)

# some display variables
NORMAL="\\033[0;39m"
SUCCESS="\\033[1;32m]"
FAILURE="\\0033[1;31m"

# sub directory
SUBDIRS = common capture flow dissector

# sniffer library
SNIFFER_LIB =

# DPDK 17.02
DPDK_INCLUDE_PATH = ${RTE_SDK}/${RTE_TARGET}/include
DPDK_LIB_PATH = ${RTE_SDK}/${RTE_TARGET}/lib

DPDK_LIBS = $(DPDK_LIB_PATH)/librte_ethdev.a \
$(DPDK_LIB_PATH)/librte_acl.a \
$(DPDK_LIB_PATH)/librte_pmd_af_packet.a \

all: subdir dpdk_sniffer

help:
	@echo " "

# version name
ifndef VER
VER = $(shell data +%Y_%m_%d)
endif

subdir:
	@for dir in $(SUBDIRS);\
	do $(MAKE) -C $$dir || exit 1;\
	done

clean:
	@for dir in $(SUBDIRS);do $(MAKE) -C $$dir clean;done
	@rm -f dpdk-sniffer *.o
