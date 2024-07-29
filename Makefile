MOD_NAME := ebpf_offload_riscv

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
	base.o \
	offload_prog.o \
	verifier.o \
	prepare.o \
	jit.o \
	codegen_rv64.o \
	bpf_code.o \
	rv_insn_rv64.o \
	offload_maps.o
#	netdev.o

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

all: format $(MOD_NAME).ko

$(MOD_NAME).ko:
	$(call msg,MAKE,$@)
	$(Q) $(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	$(call msg,INSTALL,$(MOD_NAME))
	$(Q) sudo $(MAKE) -C $(KDIR) M=$(PWD) modules_install
	$(Q) sudo depmod

load:
	$(call msg,LOAD,$(MOD_NAME))
	$(Q) sudo insmod $(PWD)/$(MOD_NAME).ko

unload:
	$(call msg,RMMOD,$(MOD_NAME))
	$(Q) sudo rmmod $(MOD_NAME)

format:
	@echo
	@echo "--- Formatting the code ---"
	@echo
	clang-format -i -style=file *.c *.h

clean-module:
	$(call msg,CLEAN,$(MOD_NAME))
	$(Q) $(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: clean
clean: clean-module

compile_commands.json:
	$(call msg,GEN,$@)
	$(Q) intercept-build $(MAKE) $(MOD_NAME).ko

help:
	@echo targets:
	@echo      $(MOD_NAME).ko: compile the LKM
	@echo	   install: install the LKM
	@echo	   load: load the LKM into the running Linux Kernel
	@echo	   unload: remove the LKM from the Linux Kernel
	@echo
	@echo      compile_commands.json: generate compilation DB for vscode/jb
	@echo
	@echo	   clean-module: clean only module artifacts
	@echo	   clean: clear all the files created by the compile process
	@echo
	@echo	   help: show this message

# delete failed targets
.DELETE_ON_ERROR:
