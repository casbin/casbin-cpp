ifdef OS
	RM = del
else
	ifeq ($(shell uname), Linux)
		RM = rm -f
	endif
endif

CC = g++
CFLAGS = -std=c++11

all: exceptions/parseException.h parser/allFF.h parser/byte.h parser/CIDR.h parser/CIDRMask.h parser/dtoi.h parser/equal.h parser/IP.h parser/IPMask.h parser/IPNet.h parser/Ipv4.h parser/parseCIDR.h parser/parseIP.h parser/parseIPv4.h parser/parseIPv6.h
	$(CC) $(CFLAGS) $?

clean:
	$(RM) examples\*.exe examples\*.out exceptions\*.gch parser\*.gch