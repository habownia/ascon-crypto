
/**
 * @file unity.h
 * @brief Utworzenie makr pomocnych przy testach
 * 
 */


#ifndef UNITY_H
#define UNITY_H

#include "unity_internals.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

void setUp(void);
void tearDown(void);

#define UNITY_BEGIN() UnityBegin(__FILE__)
#define UNITY_END()   UnityEnd()

/**
 * @brief Makro uruchamiajace pojedynczy przypadek testowy w izolacji.
 * 
 * Wykorzystuje setjmp/longjmp:
 * 1. Zapisuje punkt powrotu w Unity.abort_frame.
 * 2. Wywoluje setUp() -> cialo testu func() -> tearDown().
 * 3. Jesli w ciele testu asercja zawiedzie, wywolywany jest longjmp,
 *    ktory bezposrednio przeskakuje do bloku 'else', wywoluje tearDown()
 *    i rejestruje niepowodzenie testu bez zawieszania aplikacji.
 */
#define RUN_TEST(func) \
    do { \
        Unity.current_test_name = #func; \
        Unity.current_test_line = __LINE__; \
        Unity.tests_run++; \
        if (setjmp(Unity.abort_frame) == 0) { \
            setUp(); \
            func(); \
            tearDown(); \
            UnityTestPass(); \
        } else { \
            tearDown(); \
        } \
    } while(0)


#define TEST_ASSERT(condition) \
    do { \
        if (!(condition)) { \
            UnityTestFail("Assertion failed: " #condition, __LINE__); \
        } \
    } while (0)

    
#define TEST_ASSERT_TRUE(condition) TEST_ASSERT(condition)
#define TEST_ASSERT_FALSE(condition) TEST_ASSERT(!(condition))


#define TEST_ASSERT_EQUAL(expected, actual) \
    UnityAssertEqualNumber((int64_t)(expected), (int64_t)(actual), #actual, __LINE__)

    
#define TEST_ASSERT_NOT_EQUAL(expected, actual) \
    do { \
        if ((int64_t)(expected) == (int64_t)(actual)) { \
            UnityTestFail("Assertion failed: values are equal", __LINE__); \
        } \
    } while(0)


#define TEST_ASSERT_EQUAL_INT(expected, actual) TEST_ASSERT_EQUAL(expected, actual)
#define TEST_ASSERT_EQUAL_HEX8(expected, actual) TEST_ASSERT_EQUAL((uint8_t)(expected), (uint8_t)(actual))
#define TEST_ASSERT_EQUAL_HEX64(expected, actual) TEST_ASSERT_EQUAL((uint64_t)(expected), (uint64_t)(actual))


/**
 * @brief Asercja porownania dwoch buforow bajtowych
 * 
 * Porownuje 'length' bajtow miedzy 'expected' i 'actual'.
 * W przypadku rozbieznosci wypisuje dokladny indeks bajtu oraz oczekiwana i otrzymana wartosc w HEX.
 */
#define TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, actual, length) \
    UnityAssertEqualHex8Array((const uint8_t *)(expected), (const uint8_t *)(actual), (size_t)(length), #actual, __LINE__)


#define TEST_ASSERT_EQUAL_STRING(expected, actual) \
    UnityAssertEqualString((expected), (actual), #actual, __LINE__)


/**
 * @brief Wymuszenie bledu testu z wlasnym komunikatem.
 */
#define TEST_FAIL_MESSAGE(msg)   UnityTestFail((msg), __LINE__)

/**
 * @brief Zignorowanie testu z podaniem przyczyny.
 */
#define TEST_IGNORE_MESSAGE(msg) UnityTestIgnore((msg), __LINE__)

#ifdef __cplusplus
}
#endif

#endif /* UNITY_H */

