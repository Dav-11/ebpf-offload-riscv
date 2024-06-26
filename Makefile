KDIR ?= /lib/modules/$(shell uname -r)/build

PWD				:= $(shell pwd)
EXTRA_CFLAGS	+= -DDEBUG
obj-m			+= ebpf_offload_riscv.o

address_book_nf-y := \
	main.o

all: build install load

build:
	@echo
	@echo '--- Building : KDIR=${KDIR} ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} EXTRA_CFLAGS=${EXTRA_CFLAGS} ---'
	@echo

	@# build
	$(MAKE) -C $(KDIR) M=$(PWD) modules

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

clean:
	@echo
	@echo "--- Cleaning ---"
	@echo
	$(MAKE) -C $(KDIR) M=$(PWD) clean

help:
	@echo targets:
	@echo	   build: compile the LKM
	@echo	   install: install the LKM
	@echo	   load: load the LKM into the running Linux OS
	@echo	   unload: remove the LKM from the Linux OS
	@echo
	@echo	   help: show this message
	@echo	   clean: clear all the files created by the compile process

