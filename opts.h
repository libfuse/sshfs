/*
    Mount option parsing
    Copyright (C) 2004  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

struct opt {
    const char *optname;
    int present;
    char *value;
};

void process_options(int *argcp, char *argv[], struct opt opts[], 
                     int case_sensitive);

int opt_get_unsigned(const struct opt *o, unsigned *valp);

char *opt_get_string(const struct opt *o);
