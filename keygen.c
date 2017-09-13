/*
keygen.c
Author: Ryan Ruiz
Description: Creates a key file for use with otp_enc otp_enc_d otp_dec and otp_dec_d.
Creates an output of randomized valid characters to be used by programs mentioned before.
Usage: keygen keylength
*/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

int main(int argc, char *argv[])
{

	srand(time(NULL));

	char *keyfile;
	int random, keysize, i;

	/* Handle invalid arguments */
	if (argc < 2) {
		fprintf(stderr,"Usage: %s keylength\n", argv[0]);
		exit(1);
	}

	keysize = atoi(argv[1]);
     /* Inititialize keyfile string */
    keyfile = (char *) malloc((keysize + 2) * sizeof(char));
    if(keysize > 0)
    	memset(keyfile, '\0', sizeof(keyfile));

    for(i = 0; i < keysize; i++) {
    	random = rand() % 27;
    	if(random == 26) {
    		keyfile[i] = 32;
    	}
    	else {
    		keyfile[i] = random + 65;
    	}
    }

    keyfile[keysize] = '\n';

    printf("%s", keyfile);

    free(keyfile);

    return 0;
}