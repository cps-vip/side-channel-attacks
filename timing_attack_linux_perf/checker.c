#include "checker.h"

/* Same early exit as the natural Rust checker, with a configurable lab secret. */
int check_early_exit(const char *guess, size_t guess_length,
                     const char *secret, size_t secret_length)
{
    if (guess_length != secret_length)
        return 0;

    for (size_t i = 0; i < secret_length; i++) {
        if (guess[i] != secret[i])
            return 0;
    }
    return 1;
}

int check_fixed_work(const char *guess, size_t guess_length,
                     const char *secret, size_t secret_length)
{
    unsigned int difference = 0;

    if (guess_length != secret_length)
        return 0;

    /* Remember any mismatch and keep going until we reach the end. */
    for (size_t i = 0; i < secret_length; i++)
        difference |= (unsigned char)guess[i] ^ (unsigned char)secret[i];

    return difference == 0;
}
