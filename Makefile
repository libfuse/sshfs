CC = gcc

CFLAGS := -Wall -W -g 
LDLIBS := -lpthread -ldl -rdynamic

PKGCONFIG := env PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config
CFLAGS += $(shell $(PKGCONFIG) --cflags fuse)
LDLIBS += $(shell $(PKGCONFIG) --libs fuse)
CFLAGS += $(shell $(PKGCONFIG) --cflags glib-2.0)
LDLIBS += $(shell $(PKGCONFIG) --libs glib-2.0)

CPPFLAGS := -D_FILE_OFFSET_BITS=64 -D_REENTRANT

sshfs: sshfs.o 

clean:
	rm -f *.o sshfs
