# Define the main module
obj-m := network_shadow.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) \
		EXTRA_CFLAGS="-I$(shell pwd)/../recovery_evaluator" \
		modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean