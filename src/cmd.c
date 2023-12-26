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

extern char **environ;

int stdout_backup;
int stdin_backup;
int stderr_backup;

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

	free(new_path);
	if (ret < 0)
		return FAILURE;

	return SUCCESS;
}

/**
 * Internal print-working-directory command.
 */
static int shell_pwd() {
	char wd[PATH_MAX];
	char *p = getcwd(wd, PATH_MAX);
	if (!p)
		return FAILURE;

	printf("%s\n", wd);

	return SUCCESS;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO: Add frees and closes */

	return SHELL_EXIT;
}

static bool redirect_to_same_file(word_t *out, word_t *err, int io_flags)
{
	if (!out || !err)
		return false;

	char *out_filename = get_word(out);
	char *err_filename = get_word(err);

	size_t k = strcmp(out_filename, err_filename);

	free(out_filename);
	free(err_filename);

	if (k != 0)
		return false;

	char *filename = get_word(out);
	int fd;

	if (io_flags == IO_REGULAR)
		fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	else
		fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0666);

	free(filename);
	DIE(fd < 0, "Failed open for write.\n");

	stdout_backup = dup(STDOUT_FILENO);
	stderr_backup = dup(STDERR_FILENO);

	if (dup2(fd, STDOUT_FILENO) < 0) {
		close(fd);
		DIE(1, "Failed dup2 for stdout redirecting.\n");
	}

	if (dup2(fd, STDERR_FILENO) < 0) {
		close(fd);
		DIE(1, "Failed dup2 for stderr redirecting.\n");
	}

	close(fd);
	return true;
}


static bool redirect_output(word_t *out_filename, int io_flags) {
	if (!out_filename)
	   return false;

	char *filename = get_word(out_filename);
	int out_file;
	if (io_flags == IO_REGULAR)
		 out_file = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	else
		out_file = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0666);

	free(filename);

	DIE(out_file < 0, "Failed open for write.\n");

	// Save the stdout
	stdout_backup = dup(STDOUT_FILENO);

	// Make a duplicate of the out_file and set it as STDOUT, using dup2
	int fd = dup2(out_file, STDOUT_FILENO);

	// Close the original file, because it is duplicated as stdout
	close(out_file);

	DIE(fd < 0, "Failed dup2 for stdout redirecting.\n");

	return true;
}

static void restore_stdout() {
	int fd = dup2(stdout_backup, STDOUT_FILENO);

	DIE(fd < 0, "Failed dup2.\n");
}

static bool redirect_error(word_t *err_filename, int io_falgs) {
	if (!err_filename)
		return false;

	char *filename = get_word(err_filename);

	int err_file;

	if (io_falgs == IO_REGULAR)
		err_file = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	else
		err_file = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0666);

	free(filename);
	DIE(err_file < 0, "Failed open for write.\n");

	stderr_backup = dup(STDERR_FILENO);

	int fd = dup2(err_file, STDERR_FILENO);

	close(err_file);
	DIE(fd < 0, "Failed dup2 for stderr redirecting.\n");

	return true;
}

static void restore_stderr() {
	int fd = dup2(stderr_backup, STDERR_FILENO);

	DIE(fd < 0, "Failed dup2.\n");
}



static bool redirect_input(word_t *in_filename)
{
	if (!in_filename)
		return false;

	char *filename = get_word(in_filename);

	int in_file = open(filename, O_RDONLY);

	free(filename);

	DIE(in_file < 0, "Failed open for read.\n");

	// Save the stdin
	stdin_backup = dup(STDIN_FILENO);

	// Make a duplicate of the input file, and set it as stdin, using dup2
	int fd = dup2(in_file, STDIN_FILENO);

	close(in_file);

	DIE(fd < 0, "Failed dup2 for stdin redirecting.\n");

	return true;
}

static void restore_stdin() {
	int fd = dup2(stdin_backup, STDIN_FILENO);

	DIE(fd < 0, "Failed dup2.\n");
}


/**
 * External command
 */
static int external_command(simple_command_t *s, int level, command_t *father)
{
	if (!s || level < 0)
		return FAILURE;

	int status = 0;

	int args_no = -1;
	char **argv = get_argv(s, &args_no);
	char *command = argv[0];

	pid_t pid = fork();

	DIE(pid < 0, "Failed fork.\n");

	int ret = 0;

	// Make the parent process wait for the child process
	if (pid > 0) {
		waitpid(pid, &status, 0);

		if (WIFEXITED(status))
			ret = WEXITSTATUS(status);

	} else {
		ret = execvp(command, argv);

		if (ret < 0)
			printf("Execution failed for \'%s\'\n", command);
	}

	free_argv(argv, args_no);
	return ret;
}

static int environment_assignment(simple_command_t *s)
{
	char *assignment = get_word(s->verb);

	if (!strchr(assignment, '='))
		return NOT_ASSIGNMENT;

	// An expression NAME= is invalid
	DIE(!s->verb->next_part->next_part, "Invalid variable assignment.\n");

	const char *name = s->verb->string;

	char *value = get_word(s->verb->next_part->next_part);

	int ret = setenv(name, value, 1);

	free(value);
	return ret;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	if (!s || level < 0)
		return FAILURE;

	int ret = 0;

	int args_no = -1;
	char **argv = get_argv(s, &args_no);
	char *command = argv[0];

	bool out_redirect = false, in_redirect = false, err_redirect = false;

	if (redirect_to_same_file(s->out, s->err, s->io_flags)) {
		out_redirect = true;
		err_redirect = true;
	} else {
		out_redirect = redirect_output(s->out, s->io_flags);
		err_redirect = redirect_error(s->err, s->io_flags);
	}

	in_redirect = redirect_input(s->in);


	switch (parse_command_type(command)) {
		case CD:
			ret = shell_cd(s->params);
			break;
		case PWD:
			ret = shell_pwd();
			break;
		case EXIT:
			ret = shell_exit();
			break;
		case EXTERNAL:
			if (environment_assignment(s) == NOT_ASSIGNMENT)
				ret = external_command(s, level, father);
			break;
	}

	if (out_redirect)
		restore_stdout();
	if (in_redirect)
		restore_stdin();
	if (err_redirect)
		restore_stderr();

	free_argv(argv, args_no);
	return ret;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static int run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int status_cmd1;
	int status_cmd2;

	pid_t cmd1_pid = fork();

	DIE(cmd1_pid < 0, "Failed fork.\n");

	// In parent create another fork for the second process
	if (cmd1_pid > 0) {
		pid_t cmd2_pid = fork();

		DIE(cmd2_pid < 0, "Failed fork.\n");

		// In parent wait for both processes
		if (cmd2_pid > 0) {
			waitpid(cmd1_pid, &status_cmd1, 0);
			waitpid(cmd2_pid, &status_cmd2, 0);

			if (WIFEXITED(status_cmd1) && WIFEXITED(status_cmd2)) {}
				return WEXITSTATUS(status_cmd1) & WEXITSTATUS(status_cmd2);
		}

		// In the child execute the second command
		if (cmd2_pid == 0) {
			int ret = parse_command(cmd2, level, father);
			exit(ret);
		}

	}

	// In the child execute the command
	if (cmd1_pid == 0) {
		int ret = parse_command(cmd1, level, father);
		exit(ret);
	}

	DIE(1, "Fatal error: Unreachable section.\n");
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static int run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int pipefd[2];
	int ret = pipe(pipefd);

	DIE(ret < 0, "Failed pipe.\n");

	int cmd1_status, cmd2_status;
	pid_t cmd1_pid = fork();

	DIE(cmd1_pid < 0, "Failed fork.\n");

	// In parent, we create another child process for the second command
	if (cmd1_pid > 0) {
		pid_t cmd2_pid = fork();

		DIE(cmd2_pid < 0, "Failed fork.\n");

		// In parent, we wait for the both processes to end
		if (cmd2_pid > 0) {
			close(pipefd[READ]);
			close(pipefd[WRITE]);

			waitpid(cmd1_pid, &cmd1_status, 0);
			waitpid(cmd2_pid, &cmd2_status, 0);

			if (WIFEXITED(cmd1_status) && WIFEXITED(cmd2_status))
				return WEXITSTATUS(cmd2_status);
		}

		// In child, we execute the second command, but it takes the input via read
		// "channel" of the pipe
		if (cmd2_pid == 0) {
			// We close the write "channel"
			close(pipefd[WRITE]);

			ret = dup2(pipefd[READ], STDIN_FILENO);
			if (ret < 0) {
				close(pipefd[READ]);
				DIE(1, "Failed dup2 for read via pipe.\n");
			}

			ret = parse_command(cmd2, level, father);

			close(pipefd[READ]);
			return ret;
		}

	}

	// In child, we execute the first command, and send it's output via write
	// "channel" of the pipe
	if (cmd1_pid == 0) {
		// We close the read "channel"
		close(pipefd[READ]);

		ret = dup2(pipefd[WRITE], STDOUT_FILENO);
		if (ret < 0) {
			close(pipefd[WRITE]);
			DIE(1, "Failed dup2 for write via pipe.\n");
		}

		ret = parse_command(cmd1, level, father);

		close(pipefd[WRITE]);
		return ret;
	}

	DIE(1, "Fatal error: Unreachable section.\n");
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	if (!c || level < 0)
		return FAILURE;

	int ret = SUCCESS;

	if (c->op == OP_NONE) {
		// Execute the command and return it's exit code
		ret = parse_simple(c->scmd, level, father);
		goto end;
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		// Execute both commands and return the exit code of the second one
		parse_command(c->cmd1, level + 1, c);
		ret = parse_command(c->cmd2, level + 1, c);
		break;
	case OP_PARALLEL:
		ret = run_in_parallel(c->cmd1, c->cmd2, level + 1, c);
		break;
	case OP_CONDITIONAL_NZERO:
		ret = parse_command(c->cmd1, level + 1, c);
		if (ret != SUCCESS)
			ret = parse_command(c->cmd2, level + 1, c);

		break;
	case OP_CONDITIONAL_ZERO:
		ret = parse_command(c->cmd1, level + 1, c);
		if (ret != FAILURE)
			ret =  parse_command(c->cmd2, level + 1, c);
		
		break;
	case OP_PIPE:
		ret = run_on_pipe(c->cmd1, c->cmd2, level + 1, c);
		break;
	default:
		ret = SHELL_EXIT;
	}

end:
	return ret;
}
