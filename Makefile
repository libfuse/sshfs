CC = gcc

CFLAGS := -Wall -W -g 
LDLIBS := -lpthread -ldl -rdynamic

PKGCONFIG := env PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config
FUSEVER := $(shell $(PKGCONFIG) --modversion fuse 2> /dev/null)
ifeq ($(FUSEVER),)
	LDLIBS += -lfuse
else
	CFLAGS += $(shell $(PKGCONFIG) --cflags fuse)
	LDLIBS += $(shell $(PKGCONFIG) --libs fuse)
endif

CPPFLAGS := -D_FILE_OFFSET_BITS=64
#CPPFLAGS += -DDEBUG

sshfs: sshfs.o 

clean:
	rm -f *.o sshfs
