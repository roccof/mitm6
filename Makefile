PROG_NAME = mitm6

SRC = $(wildcard src/*.c)
HDR = $(wildcard src/*.h)
OBJS = $(patsubst %.c,%.o,$(SRC))

CFLAGS = -Wall -ggdb3 -I ./src -lm -lpcap -pthread

all: mitm6

install:
	@echo "TODO..."

$(OBJS): %.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

mitm6: $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG_NAME) $(OBJS)

clean:
	rm src/*.o $(PROG_NAME) *~ src/*~

.PHONY: clean
