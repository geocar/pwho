PATH:=/usr/local/cross-tools/bin:$(PATH)
CC=i386-pc-linux-gcc
CFLAGS=-s -O2
pwho: pwho.o ht.o
	$(CC) $(CFLAGS) -o pwho pwho.o ht.o

install: pwho
	scp pwho icdn@inuit:cgi-bin/pwho
	scp pwho icdn@inuit:cgi-bin/nic2/pwho
	scp -oProtocol=1 pwho root@eskimo:/usr/nic2/pwho

clean:
	rm -f pwho pwho.o ht.o
