KERNEL_VERSION	:= 6.8.0

ifeq ($(shell uname -s),Linux)
  
  # If the OS is Linux, set KERNEL_VERSION to the current kernel version
  KERNEL_VERSION := $(shell uname -r | cut -d- -f1)
endif

KDIR ?= /lib/modules/$(shell uname -r)/build

PWD				:= $(shell pwd)
EXTRA_CFLAGS	+= -DDEBUG
obj-m			+= ebpf_offload_riscv.o

CONFIG_ARCH_RV64I := y

ebpf_offload_riscv-y := \
	main.o \
	offload_prog.o \
	offload_maps.o \
	verifier.o
	#rv_jit/jit_core.o
	#rv_jit/jit_regs.o \
	#rv_jit/jit_codegen_generic.o \
	#rv_jit/bpf_jit_comp64.o \
	#rv_jit/memory.o \
	#rv_jit/utils.o

ifeq ($(CONFIG_ARCH_RV64I),y)
	obj-$(CONFIG_BPF_JIT) += rv_jit/bpf_jit_comp64.o
else
	obj-$(CONFIG_BPF_JIT) += rv_jit/bpf_jit_comp32.o
endif

# hide output unless V=1
ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

all: format ebpf_offload_riscv.ko

ebpf_offload_riscv.ko:
	$(call msg,MAKE,$@)
	$(Q) $(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	@echo
	@echo "--- Installing module address_book_nf ---"
	@echo

	sudo make -C $(KDIR) M=$(PWD) modules_install
	sudo depmod

load:
	@echo
	@echo "--- Loading module into the kernel ---"
	@echo

	sudo insmod $(PWD)/ebpf_offload_riscv.ko

unload:
	@echo
	@echo "--- Removing the module from the kernel ---"
	@echo

	sudo rmmod ebpf_offload_riscv

format:
	@echo
	@echo "--- Formatting the code ---"
	@echo
	clang-format -i -style=file rv_jit/*.c rv_jit/*.h *.c *.h

clean-module:
	@echo
	@echo "--- Cleaning ---"
	@echo
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: clean
clean: clean-module
	$(Q) rm -rf $(LINUX_PATH)

help:
	@echo targets:
	@echo	   build: compile the LKM
	@echo	   install: install the LKM
	@echo	   load: load the LKM into the running Linux OS
	@echo	   unload: remove the LKM from the Linux OS
	@echo
	@echo	   help: show this message
	@echo	   clean: clear all the files created by the compile process

# delete failed targets
.DELETE_ON_ERROR:
