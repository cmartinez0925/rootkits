PWD				:= $(shell pwd)
KDIR			:= /lib/modules/$(shell uname -r)/build
obj-m			+= random_rootkit.o

# ccflags-y		+= -DDEBUG

all:
	make -C $(KDIR) M=$(PWD) modules

install:
	make -C $(KDIR) M=$(PWD) modules_install

clean:
	make -C $(KDIR) M=$(PWD) clean
