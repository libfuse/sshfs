/*
    Mount option parsing
    Copyright (C) 2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "opts.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>

static int process_option(char *arg, struct opt opts[], int case_sensitive)
{
    int i;
    char *eq = strchr(arg, '=');
    if (eq)
        *eq = '\0';

    for (i = 0; opts[i].optname != NULL; i++) {
        if (case_sensitive) {
            if (strcmp(opts[i].optname, arg) == 0)
                break;
        } else if (strcasecmp(opts[i].optname, arg) == 0)
            break;
    }
    if (opts[i].optname == NULL) {
        if (eq)
            *eq = '=';
        return 0;
    }
    opts[i].present = 1;
    if (eq) {
        if (opts[i].value)
            g_free(opts[i].value);
        opts[i].value = g_strdup(eq+1);
    }
    return 1;
}

static int process_option_group(char *arg, struct opt opts[],
                                int case_sensitive)
{
    int remove = 1;
    char *prevcomma = NULL;
    while (1) {
        int remove_one;
        char *comma = strchr(arg, ',');
        if (comma)
            *comma = '\0';
        remove_one = process_option(arg, opts, case_sensitive);
        if (remove_one) {
            if (comma)
                memmove(arg, comma + 1, strlen(comma + 1) + 1);
        } else {
            remove = 0;
            if (comma)
                arg = comma + 1;
        }
        if (!remove_one && prevcomma)
            *prevcomma = ',';
        if (!comma)
            break;
        prevcomma = comma;
    }
    return remove;
}

void process_options(int *argcp, char *argv[], struct opt opts[], 
                     int case_sensitive)
{
    int argctr;
    int newargctr;

    for (argctr = 1, newargctr = 1; argctr < *argcp; argctr++) {
        char *arg = argv[argctr];
        int removed = 0;
        if (arg[0] == '-' && arg[1] == 'o') {
            if (arg[2])
                removed = process_option_group(arg+2, opts, case_sensitive);
            else {
                if (argctr + 1 < *argcp) {
                    argctr++;
                    arg = argv[argctr];
                    removed = process_option_group(arg, opts, case_sensitive);
                    if (removed)
                        g_free(argv[argctr-1]);
                    else if (argctr != newargctr)
                        argv[newargctr++] = argv[argctr-1];
                    
                }
            }
        }
        if (removed)
            g_free(arg);
        else {
            if(argctr != newargctr)
                argv[newargctr] = arg;
            newargctr++;
        }
    }
    *argcp = newargctr;
}

int opt_get_unsigned(const struct opt *o, unsigned *valp)
{
    char *end;
    unsigned val;
    if (!o->value || !o->value[0]) {
        fprintf(stderr, "Missing value for '%s' option\n", o->optname);
        return -1;
    }
    val = strtoul(o->value, &end, 0);
    if (end[0]) {
        fprintf(stderr, "Invalid value for '%s' option\n", o->optname);
        return -1;
    }
    *valp = val;
    return 0;
}
