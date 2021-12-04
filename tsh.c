/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 * The shell supports redirection of input and (for non-built in commands and
 * builtin command jobs) output.
 * The program temprarily change the default
 * action of SIGCHLD, SIGINT and SIGTSTP. SIGINT and SIGTSTP share the same code
 * (sending the sig to child and let sig child handler deal with everything).
 * The shell will exit if included but not limited to follwing actions happen:
 * 1.User typed in command quit
 * 2.The program run by user send signal to quit the shell
 * 3.Abnormal open/dup2 instructions
 * There are at most one foreground job and the shell temporarily suspend until
 * foreground job completes.
 *
 * @author jiuqis@andrew.cmu.edu
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigint_handler(int sig);
void sigtstp_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);
int fg_pid(void);
int extract_id(char *arg, char *info);
int async_delete_job(int pid);
void handle(int sig);

sigset_t maskall, mask, prev, empty;

/**
 * @brief
 * Set the environment for the shell and exits if anything goes wrong.
 * Goes into a forever loop to wait for user commands and process them.
 * Exits(jumps out of the loop) if user quit the shell or some fatal error
 * happens.
 */
int main(int argc, char **argv) {
    char c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv("MY_ENV=42") < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/**
 * get the current foreground job's pid
 * return 0 is there is no foreground job.
 */
int fg_pid(void) {
    sigfillset(&maskall);
    sigprocmask(SIG_BLOCK, &maskall, NULL);
    jid_t jid = fg_job();
    if ((int)jid == 0) {
        return 0;
    }
    pid_t output = job_get_pid(jid);
    return (int)output;
}
/**
 * @param arg : user typed in commands
 * @param info : indicate whether the id belongs to fg or bg job
 * @result given user's bg/fg command and the correspoding jid/pid argument
 * @return -1 if there is no id argument /
 *  0 if user typed in pid has no corresponding jid or invalid id is provided /
 *  jid otherwise
 */
int extract_id(char *arg, char *info) {
    if (arg == NULL) {
        printf("%s command requires PID or %%jobid argument\n", info);
        return -1;
    }
    if (arg[0] == '%') {
        char *newstring = arg + 1;
        int jid = atoi(newstring);
        return jid;
    } else {
        int pid = atoi(arg);
        int jid;
        jid = (int)job_from_pid(pid);
        return jid;
    }
}

/**
 * @param pid : pid of the job that needs to be deleted from job list
 * @result delete the corresponding job from job list in a async-safe
 * environment
 * @return the corresponding jid;
 */
int async_delete_job(int pid) {
    sigprocmask(SIG_BLOCK, &maskall, NULL);
    int jid = job_from_pid(pid);
    delete_job(jid);
    sigprocmask(SIG_UNBLOCK, &maskall, NULL);
    return jid;
}

/**
 * @param sig signal number of terminate/stop signal
 * @result do nothing if there's no foreground job
 * send sig to foreground precess group otherwise
 */
void handle(int sig) {
    int save = errno;
    int pid;
    pid = fg_pid();
    if (pid == 0) {
        errno = save;
        return;
    } else {
        kill(-pid, sig);
    }
    errno = save;
}

/**
 * helper function for the eval function
 * arguments are parameters of eval function
 * deal with the condition if the command is not built-in
 */
void do_notbuiltin(struct cmdline_tokens token, parseline_return parse_result,
                   const char *cmdline) {
    int pid, inputfd, outputfd;
    job_state status;
    sigfillset(&maskall);
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);
    sigemptyset(&empty);
    // block sigchld,sigint and sigtstp
    sigprocmask(SIG_BLOCK, &mask, &prev);
    if ((pid = fork()) == 0) {
        // redirect input
        if (token.infile != NULL) {
            char *inputfilename = token.infile;
            if ((inputfd = open(inputfilename, O_RDONLY, 0)) == -1) {
                printf("%s: %s\n", inputfilename, strerror(errno));
                sigprocmask(SIG_SETMASK, &prev, NULL);
                exit(0);
            }
            if (dup2(inputfd, STDIN_FILENO) == -1) {
                printf("%s: dup2 err\n", inputfilename);
                exit(0);
            }
            if (close(inputfd) == -1) {
                printf("%s: %s", inputfilename, strerror(errno));
            }
        }
        // redirect output
        if (token.outfile != NULL) {
            char *outputfilename = token.outfile;
            if ((outputfd = open(outputfilename, O_WRONLY | O_CREAT | O_TRUNC,
                                 S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) ==
                -1) {
                printf("%s: %s\n", outputfilename, strerror(errno));
                sigprocmask(SIG_SETMASK, &prev, NULL);
                exit(0);
            }
            if (dup2(outputfd, STDOUT_FILENO) == -1) {
                printf("%s: dup2 err\n", outputfilename);
                exit(0);
            }
            if (close(outputfd) == -1) {
                printf("%s: %s", outputfilename, strerror(errno));
            }
        }
        // creat seperate process group
        setpgid(0, 0);
        sigprocmask(SIG_SETMASK, &empty, NULL);
        // execute command without any blocked signal
        if ((execve(token.argv[0], token.argv, environ) < 0)) {
            printf("%s: %s\n", token.argv[0], strerror(errno));
            exit(0);
        }
    }
    // set status to bg or fg
    status = (parse_result == PARSELINE_FG) ? FG : BG;
    // add job to job list with corresponding state
    sigprocmask(SIG_BLOCK, &maskall, NULL);
    add_job(pid, status, cmdline);
    sigprocmask(SIG_SETMASK, &mask, NULL);
    // wait for foreground job to finish
    if (status == FG) {
        while (fg_pid() > 0) {
            sigsuspend(&prev);
        }
    }
    // simply print info to user
    if (status == BG) {
        sigprocmask(SIG_BLOCK, &maskall, NULL);
        int jid = (int)job_from_pid(pid);
        sigprocmask(SIG_SETMASK, &empty, NULL);
        printf("[%d] (%d) %s\n", jid, pid, cmdline);
    }
    // unblock all signals
    sigprocmask(SIG_SETMASK, &empty, NULL);
}
/**
 * @brief <What does eval do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;
    int outputfd;

    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }
    // quit
    if (token.builtin == BUILTIN_QUIT) {
        exit(0);
    }
    // print out jobs
    // supports output redirection
    if (token.builtin == BUILTIN_JOBS) {
        sigfillset(&maskall);
        sigprocmask(SIG_BLOCK, &maskall, NULL);
        // redirect output
        if (token.outfile != NULL) {
            char *outputfilename = token.outfile;
            if ((outputfd = open(outputfilename, O_WRONLY | O_CREAT | O_TRUNC,
                                 S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) ==
                -1) {
                printf("%s: %s\n", outputfilename, strerror(errno));
                sigprocmask(SIG_UNBLOCK, &maskall, NULL);
                return;
            }
            if (!list_jobs(outputfd)) {
                printf("list job error\n");
            }
            if (close(outputfd) == -1) {
                printf("%s: %s", outputfilename, strerror(errno));
            }
            sigprocmask(SIG_UNBLOCK, &maskall, NULL);
            return;
        }
        // print job list
        if (!list_jobs(STDOUT_FILENO)) {
            printf("list job error\n");
        }
        sigprocmask(SIG_UNBLOCK, &maskall, NULL);
        return;
    }
    // built in bg command
    if (token.builtin == BUILTIN_BG) {
        sigfillset(&maskall);
        sigprocmask(SIG_BLOCK, &maskall, NULL);
        int jid = extract_id(token.argv[1], "bg");
        // if there is no valid argument return
        if (jid == -1) {
            sigprocmask(SIG_UNBLOCK, &maskall, NULL);
            return;
        }
        // if id is not valid print out error info and return
        if (jid == 0) {
            printf("bg: argument must be a PID or %%jobid\n");
            sigprocmask(SIG_UNBLOCK, &maskall, NULL);
            return;
        }
        // change the job's state and send SIGCONT to the process group
        if (job_exists(jid)) {
            job_set_state(jid, BG);
            int pid = job_get_pid(jid);
            if (kill(-pid, SIGCONT) == -1) {
                sio_printf("process no.%d: %s\n", pid, strerror(errno));
            }
            printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
            sigprocmask(SIG_UNBLOCK, &maskall, NULL);
            return;
        }
        printf("%%%d: No such job\n", jid);
        sigprocmask(SIG_UNBLOCK, &maskall, NULL);
    }
    // builtin fg command
    if (token.builtin == BUILTIN_FG) {
        sigfillset(&maskall);
        sigemptyset(&empty);
        sigprocmask(SIG_BLOCK, &maskall, NULL);
        int jid = extract_id(token.argv[1], "fg");
        // if there is no valid argument return
        if (jid == -1) {
            sigprocmask(SIG_UNBLOCK, &maskall, NULL);
            return;
        }
        // if id is not valid print out error info and return
        if (jid == 0) {
            printf("fg: argument must be a PID or %%jobid\n");
            sigprocmask(SIG_UNBLOCK, &maskall, NULL);
            return;
        }
        // change the job's state and send SIGCONT to the process group
        // wait for this job stop or terminate
        if (job_exists(jid)) {
            job_set_state(jid, FG);
            int pid = job_get_pid(jid);
            if (kill(-pid, SIGCONT) == -1) {
                sio_printf("process no.%d: %s\n", pid, strerror(errno));
            }
            while (fg_pid() > 0) {
                sigsuspend(&empty);
            }
            sigprocmask(SIG_UNBLOCK, &maskall, NULL);
            return;
        }
        printf("%%%d: No such job\n", jid);
        sigprocmask(SIG_UNBLOCK, &maskall, NULL);
    }
    // not a builtin command
    if (token.builtin == BUILTIN_NONE) {
        do_notbuiltin(token, parse_result, cmdline);
    }
}

/*****************
 * Signal handlers
 *****************/

/**
 * handle the signal if child normally exits, signaled to stop or signaled to
 * terminate
 */
void sigchld_handler(int sig) {
    int save = errno;
    int pid;
    int status;
    sigfillset(&maskall);
    // reap all stopped/terminated childs
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        // if it normally exits,simply delete from job list
        if (WIFEXITED(status)) {
            async_delete_job(pid);
        }
        // if it is signaled to terminate, delete from job list
        if (WIFSIGNALED(status)) {
            int signal = WTERMSIG(status);
            int jid = async_delete_job(pid);
            sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, pid,
                       signal);
        }
        // if it is signaled to stop, change the job state
        if (WIFSTOPPED(status)) {
            int signal = WSTOPSIG(status);
            sigprocmask(SIG_BLOCK, &maskall, NULL);
            int jid = job_from_pid(pid);
            job_set_state(jid, ST);
            sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid,
                       signal);
            sigprocmask(SIG_UNBLOCK, &maskall, NULL);
        }
    }
    errno = save;
}

/**
 * simply calls handle function
 */
void sigint_handler(int sig) {
    handle(sig);
}

/**
 * simply calls handle function
 */
void sigtstp_handler(int sig) {
    handle(sig);
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}