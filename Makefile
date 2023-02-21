OUTFILE = arpspoof
CC = gcc
LD = ld
CFLAGS = -O3

C_SRC = $(wildcard src/*.c src/net/*.c)
C_OBJ = $(patsubst %.c, %.o, $(C_SRC))

all: compile_src link_src clean
compile_src: $(C_OBJ)
link_src:
	$(CC) $(C_OBJ) -o $(OUTFILE)
clean:
	rm -rf $(C_OBJ)
