CUDA_HOME ?= /usr/local/cuda
CC ?= cc
CFLAGS ?= -O2 -g

.PHONY: all test clean
all: cuda-ipc

cuda-ipc: cuda-ipc.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -Wextra -Werror -I$(CUDA_HOME)/include $< \
		$(LDFLAGS) -L$(CUDA_HOME)/lib64 -o $@ -lcuda

test: cuda-ipc
	python3 run.py

clean:
	rm -f cuda-ipc
