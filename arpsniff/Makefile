CFLAGS += 
LDFLAGS +=

all: arpsniff

arpsniff: arpsniff.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS) $(LDFLAGS)

romfs:
	$(ROMFSINST) /bin/arpsniff

clean:
	-rm -f lsusb *.o
