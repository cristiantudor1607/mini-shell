// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

#define PATH_MAX    1024
/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
    if (!dir)
        return FAILURE;

    int words_counter = 0;
    word_t *iterator = dir;

    while (iterator) {
        words_counter++;
        iterator = iterator->next_word;
    }

    if (words_counter != 1)
        return FAILURE;

    char *new_path = get_word(dir);
    int ret = chdir(new_path);
    if (ret < 0)
        return FAILURE;

    return SUCCESS;
}

static int shell_pwd() {
    char wd[PATH_MAX];
    char *p = getcwd(wd, PATH_MAX);
    if (!p)
        return FAILURE;
    printf("pwd: %s\n", wd);

    return SUCCESS;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */

	return SHELL_EXIT;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
    if (!s || level < 0)
        return FAILURE;

    int args_no = -1;
    char **argv = get_argv(s, &args_no);
    char *command = argv[0];

	/* TODO: If builtin command, execute the command. */
    if (!strcmp(command, "cd"))
        return shell_cd(s->params);

    if (!strcmp(command, "pwd"))
        return shell_pwd();

    if (!strcmp(command, "exit") || !strcmp(command, "quit"))
        return shell_exit();

	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */

	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */

    return 0; /* TODO: Replace with actual exit status. */
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */

	return true; /* TODO: Replace with actual exit status. */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */

	return true; /* TODO: Replace with actual exit status. */
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
    if (!c || level < 0)
        return FAILURE;

    if (c->op == OP_NONE)
        return parse_simple(c->scmd, level, father);

    switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO: Execute the commands one after the other. */
		break;

	case OP_PARALLEL:
		/* TODO: Execute the commands simultaneously. */
		break;

	case OP_CONDITIONAL_NZERO:
		/* TODO: Execute the second command only if the first one
		 * returns non zero.
		 */
		break;

	case OP_CONDITIONAL_ZERO:
		/* TODO: Execute the second command only if the first one
		 * returns zero.
		 */
		break;

	case OP_PIPE:
		/* TODO: Redirect the output of the first command to the
		 * input of the second.
		 */
		break;

	default:
		return SHELL_EXIT;
	}

	return 0; /* TODO: Replace with actual exit code of command. */
}
