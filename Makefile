CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -O2 -municode -w
LDFLAGS = -lole32 -ladvapi32 -s

SRCS    = main.c

all: cotato

cotato: $(OBJS)
	x86_64-w64-mingw32-gcc -o cotato.exe main.c $(CFLAGS) $(LDFLAGS)

clean:
	rm -f cotato.exe
