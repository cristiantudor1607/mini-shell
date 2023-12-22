/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _UTILS_H
#define _UTILS_H

#include "../util/parser/parser.h"


/* Useful macro for handling error codes. */
#define DIE(assertion, call_description)			\
	do {							\
		if (assertion) {				\
			fprintf(stderr, "(%s, %s, %d): ",	\
				__FILE__, __func__, __LINE__);	\
			perror(call_description);		\
			exit(EXIT_FAILURE);			\
		}						\
	} while (0)


typedef enum {
    CD,
    PWD,
    EXIT,
    EXTERNAL,
} command_type_t;

/**
 * Concatenate parts of the word to obtain the command.
 */
char *get_word(word_t *s);

/**
 * Concatenate command arguments in a NULL terminated list in order to pass
 * them directly to execv.
 */
char **get_argv(simple_command_t *command, int *size);

/**
 * Frees the memory allocated for
 */
void free_argv(char **argv, int argc);

/**
 * Chooses which type of command to perform
 */
command_type_t parse_command_type(char *command);

#endif /* _UTILS_H */
