KDIR = /lib/modules/$(shell uname -r)/build

obj-m += ip_vs_csh.o

ip_vs_csh.ko: ip_vs_csh.c
	make -C $(KDIR) M=$(PWD) modules
