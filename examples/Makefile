
all: counter counter_new

%_new.o: %.c Makefile
	$(CC) -c -o $@ $< -DNEW

%: %.o Makefile
	$(CC) -o $@ $<

.PHONY: clean
clean:
	rm -f *.o counter counter_new

