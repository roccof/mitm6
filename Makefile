
SRC := $(wildcard src/*.c)
HDR := $(wildcard src/*.h)
OBJS := $(patsubst %.c,%.o,$(SRC))

CFLAGS := -Wall -ggdb3 -I ./src -lm -lpcap -pthread

all: mitm6

install:
	@echo "TODO..."

$(OBJS): %.o: %.c $(HDR)
	$(CC) -c $(CFLAGS) -o $@ $<

mitm6: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

clean:
	@rm -f src/*.o ./mitm6 *~ src/*~

.PHONY: clean
