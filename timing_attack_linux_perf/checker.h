#ifndef CHECKER_H
#define CHECKER_H

#include <stddef.h>

typedef int password_check(const char *guess, size_t guess_length,
                           const char *secret, size_t secret_length);

password_check check_early_exit;
password_check check_fixed_work;

#endif
