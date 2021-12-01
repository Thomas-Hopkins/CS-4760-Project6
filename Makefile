CC = gcc
CFLAGS = -Wall -g

EXE = oss user_proc
DEPS = shared.h queue.h config.h
OBJS = shared.o queue.o

CLEAN = $(EXE) *.o $(OBJS) *.log

all: $(EXE)

oss: oss.o $(OBJS) $(DEPS)
	$(CC) $(CFLAGS) -o $@ $< $(OBJS)

user_proc: user_proc.o $(OBJS) $(DEPS)
	$(CC) $(CFLAGS) -o $@ $< $(OBJS) 

%.o: %.c %.h
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONY: clean
clean:
	rm -f $(CLEAN)
