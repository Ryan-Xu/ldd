obj-m := kprobe_test.o
#globalmem-objs := globalmem.o
PWD := $(shell pwd)
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	rm -rf *.o *.ko *~ *.mod.c *.order *.symvers
