obj-m += firewall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	rm -r -f *.mod.c .*.cmd *.symvers *.o
clean:
	make -C /lib/modules/$(shell uname -r) M=$(PWD) clean

# sudo insmod firewall.ko
# sudo rmmod firewall
# dmesg