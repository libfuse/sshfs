#include <stdio.h>

int main(void) {
	fprintf(stderr, "\x1B[31m\e[1m"
		"This is not the command you are looking for.\n"
		"You probably want to run 'python3 -m pytest test/' instead"
		"\e[0m\n");
	return 1;
}
