blake3: reference_impl.c Makefile
	gcc reference_impl.c -g -Wall -pedantic -Werror -O3 -o blake3

clean:
	rm blake3
