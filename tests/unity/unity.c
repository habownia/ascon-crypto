#include "unity.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

unity_storage_t Unity;

void UnityBegin(const char *filename) {
    Unity.current_test_name = NULL;
    Unity.current_test_line = 0;
    Unity.test_failures = 0;
    Unity.test_ignores = 0;
    Unity.tests_run = 0;
    printf("\n=== Uruchamianie testow jednostkowych: %s ===\n", filename);
}

int UnityEnd(void) {
    printf("\n----------------------------------------\n");
    printf("Wynik: %d uruchomionych testow, %d bledow, %d zignorowanych.\n",
           Unity.tests_run, Unity.test_failures, Unity.test_ignores);
    if (Unity.test_failures == 0) {
        printf("STATUS: OK (Wszystkie testy zaliczone)\n");
        return 0;
    } else {
        printf("STATUS: FAIL (%d testow nie powiodlo sie!)\n", Unity.test_failures);
        return 1;
    }
}

void UnityTestPass(void) {
    printf("[ PASS ] %s\n", Unity.current_test_name);
}

void UnityTestIgnore(const char *msg, int line) {
    (void)line;
    Unity.test_ignores++;
    printf("[ IGNORE ] %s: %s\n", Unity.current_test_name, msg);
    longjmp(Unity.abort_frame, 1);
}

void UnityTestFail(const char *msg, int line) {
    Unity.test_failures++;
    printf("[ FAIL ] %s:%d: w tescie '%s': %s\n",
           __FILE__, line, Unity.current_test_name, msg);
    longjmp(Unity.abort_frame, 1);
}

void UnityAssertEqualNumber(int64_t expected, int64_t actual, const char *msg, int line) {
    if (expected != actual) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s: Oczekiwano 0x%" PRIx64 " (%" PRId64 "), otrzymano 0x%" PRIx64 " (%" PRId64 ")",
                 msg, expected, expected, actual, actual);
        UnityTestFail(buf, line);
    }
}

void UnityAssertEqualHex8Array(const uint8_t *expected, const uint8_t *actual, size_t length, const char *msg, int line) {
    if (!expected || !actual) {
        UnityTestFail("Wskaznik NULL w porownaniu buforow", line);
    }
    for (size_t i = 0; i < length; ++i) {
        if (expected[i] != actual[i]) {
            char buf[256];
            snprintf(buf, sizeof(buf), "%s: Rozbieznosc na pozycji [%zu]: oczekiwano 0x%02X, otrzymano 0x%02X",
                     msg, i, expected[i], actual[i]);
            UnityTestFail(buf, line);
        }
    }
}

void UnityAssertEqualString(const char *expected, const char *actual, const char *msg, int line) {
    if (!expected || !actual || strcmp(expected, actual) != 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s: Napisy sie roznia: oczekiwano \"%s\", otrzymano \"%s\"",
                 msg, expected ? expected : "NULL", actual ? actual : "NULL");
        UnityTestFail(buf, line);
    }
}

