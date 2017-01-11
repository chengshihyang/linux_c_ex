CFLAGS += 
LDFLAGS +=

all: dnssniff

dnssniff: dnssniff.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS) $(LDFLAGS)

romfs:
	$(ROMFSINST) /bin/dnssniff

clean:
	-rm -f lsusb *.o
