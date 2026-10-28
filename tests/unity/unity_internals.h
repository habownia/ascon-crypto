#ifndef UNITY_INTERNALS_H
#define UNITY_INTERNALS_H

#include <stdio.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *current_test_name;
    int current_test_line;
    int test_failures;
    int test_ignores;
    int tests_run;
    jmp_buf abort_frame;
} unity_storage_t;

extern unity_storage_t Unity;

void UnityBegin(const char *filename);
int UnityEnd(void);
void UnityTestPass(void);
void UnityTestFail(const char *msg, int line);
void UnityTestIgnore(const char *msg, int line);
void UnityAssertEqualNumber(int64_t expected, int64_t actual, const char *msg, int line);
void UnityAssertEqualHex8Array(const uint8_t *expected, const uint8_t *actual, size_t length, const char *msg, int line);
void UnityAssertEqualString(const char *expected, const char *actual, const char *msg, int line);

#ifdef __cplusplus
}
#endif

#endif /* UNITY_INTERNALS_H */

