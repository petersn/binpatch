
all: counter counter.o counter_new counter_new.o

%_new.o: %.c Makefile
	$(CC) -c -o $@ $< -DNEW

%: %.o Makefile
	$(CC) -o $@ $<

.PHONY: clean
clean:
	rm -f *.o counter counter_new

