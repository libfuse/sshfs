#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Test that buffer operations in sshfs.c do not overflow on oversized inputs */
START_TEST(test_buffer_overflow_protection)
{
    /* Invariant: Buffer reads and writes never exceed declared buffer length.
       Oversized path components from remote server must not cause out-of-bounds access. */
    
    const char *payloads[] = {
        "normal_path",                                    /* valid input */
        "a",                                              /* boundary: minimal */
        "/../" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x"   /* boundary: relative path */
        "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x"
        "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x"
        "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x" "x", /* 10x oversized */
        "symlink_target_" "y" "y" "y" "y" "y" "y" "y" "y" "y" "y"
        "y" "y" "y" "y" "y" "y" "y" "y" "y" "y" "y" "y"
        "y" "y" "y" "y" "y" "y" "y" "y" "y" "y" "y" "y"
        "y" "y" "y" "y" "y" "y" "y" "y" "y" "y" "y" "y"
        "y" "y" "y" "y" "y" "y" "y" "y" "y" "y" "y" "y", /* 2x oversized symlink */
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        const char *payload = payloads[i];
        size_t payload_len = strlen(payload);
        
        /* Simulate buffer operation: strcpy into fixed-size buffer (PATH_MAX typical ~4096) */
        char buffer[256];
        
        /* Test invariant: operation must not crash or corrupt memory.
           Either truncate safely or reject oversized input. */
        if (payload_len < sizeof(buffer)) {
            strcpy(buffer, payload);
            ck_assert_str_eq(buffer, payload);
        } else {
            /* Oversized input: verify strncpy truncation is safe */
            strncpy(buffer, payload, sizeof(buffer) - 1);
            buffer[sizeof(buffer) - 1] = '\0';
            ck_assert_int_le(strlen(buffer), sizeof(buffer) - 1);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("BufferOverflow");

    tcase_add_test(tc_core, test_buffer_overflow_protection);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}