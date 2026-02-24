CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -O2 -municode -w
LDFLAGS = -lole32 -ladvapi32 -s

SRCS    = src/main.c src/resolve.c src/utils.c src/hook.c src/token.c src/pipe.c src/objref.c src/exec.c
# OBJS    = $(SRCS:.c=.o)

all: cotato

cotato: $(OBJS)
# 	$(CC) $(CFLAGS) -o cotato.exe $(OBJS) $(LDFLAGS)
	x86_64-w64-mingw32-gcc -o cotato.exe $(SRCS) $(CFLAGS) $(LDFLAGS)

# %.o: %.c
# 	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f cotato.exe $(OBJS)
