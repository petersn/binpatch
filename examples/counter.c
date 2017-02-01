// Simple spin loop to inspect.

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

// This is the function that we'll patch from returning x + 1 to returning x + 2.
int func(int x) {
#ifndef NEW
	x += 1;
#else
	x += 2;
#endif
	return x;
}

int main(int argc, char** argv) {
	printf("My pid: %i\n", getpid());
	int counter = 0;
	while (1) {
		// Increment the counter by using our function, either by 1 or 2,
		// depending on whether or not we've been patched yet.
		counter = func(counter);
		// Print our incremented value.
		printf("Value: %i\n", counter);
		// Sleep for one second.
		usleep(1000000);
	}
}

