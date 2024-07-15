MOD_NAME := test

KDIR ?= /lib/modules/$(shell uname -r)/build
EXTRA_CFLAGS	+= -DDEBUG
obj-m			+= test.o

#test-y := \
#	test_bit.o
	
$(MOD_NAME).ko:
	echo $(CURDIR)
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

install:
	sudo $(MAKE) -C $(KDIR) M=$(CURDIR) modules_install
	sudo depmod

load:
	sudo insmod $(CURDIR)/$(MOD_NAME).ko

unload:
	sudo rmmod $(MOD_NAME)

clean-module:
	$(call msg,CLEAN,$(MOD_NAME))
	$(Q) $(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: clean
clean: clean-module