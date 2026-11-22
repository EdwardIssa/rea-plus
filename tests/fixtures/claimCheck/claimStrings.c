/*
 * Claim-check fixture source. The strings live in a dedicated section so
 * the test helper can derive ground truth from this file's constants plus
 * the section layout, never from an analyzer. "claim_unterminated" is
 * exactly eight bytes with no NUL after it (the next array follows
 * immediately), and "claim_tail" is the last array in the section, so its
 * stored bytes end exactly at the section boundary.
 */
#include <stdio.h>

#define CLAIM_SECTION __attribute__((section(".claimstrings"), used))

static const char claim_greeting[] CLAIM_SECTION = "claim-check-greeting";
static const char claim_unterminated[8] CLAIM_SECTION = {
    'N', 'O', 'T', 'E', 'R', 'M', '0', '1',
};
static const char claim_tail[] CLAIM_SECTION = "tail-at-section-end";

int main(void) {
    printf("%s %c %s\n", claim_greeting, claim_unterminated[0], claim_tail);
    return 0;
}
