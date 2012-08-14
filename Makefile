
SRC := $(wildcard src/*.c)
HDR := $(wildcard src/*.h)
OBJS := $(patsubst %.c,%.o,$(SRC))

CFLAGS := -Wall -ggdb3 -I ./src -lm -lpcap -pthread

all: mitm6

install:
	@echo "TODO..."

$(OBJS): %.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

mitm6: $(OBJS) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

clean:
	@rm -f src/*.o $(PROG_NAME) *~ src/*~

.PHONY: clean
