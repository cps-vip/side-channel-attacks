CFLAGS ?= -O2 -Wall -Wextra -Wpedantic

libchecker.so: checker.c perf_cycles.c checker.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -fPIC -fno-lto -shared -o $@ checker.c perf_cycles.c
