CC = clang
CFLAGS = -O3 -march=native -Werror -Wall -Wextra -Wpedantic -Wno-unused-parameter
CFLAGS += -I.

ctest : c/test.o crypto.o
	$(CC) -o $@ $^

clean:
	rm -f ctest *.o c/*.o
