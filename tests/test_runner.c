/**
 * @file test_runner.c
 * @brief Glowny program wykonawczy (Test Runner) zestawu testow TDD dla kryptografii Ascon.
 * 
 * Zwraca:
 * - 0: wszystkie 23 scenariusze testowe zakonczone sukcesem (STATUS: OK).
 * - 1: przynajmniej jeden test zakonczony niepowodzeniem (STATUS: FAIL).
 */

#include "unity/unity.h"
#include <stdio.h>
#include <string.h>

/* Deklaracje funkcji uruchamiajacych poszczegolne moduly testowe */
extern void run_permutation_tests(void);
extern void run_hash_tests(void);
extern void run_aead_tests(void);

/**
 * @brief Punkt wejscia srodowiska testowego.
 * 
 * Opcjonalne argumenty wiersza polecen umozliwiaja uruchomienie wybranego modulu:
 * - brak argumentow / "all": uruchamia wszystkie testy
 * - "permutation" / "perm": tylko testy permutacji Ascon-p
 * - "hash": tylko testy Ascon-Hash256 / XOF128
 * - "aead": tylko testy Ascon-AEAD128
 */
int main(int argc, char *argv[]) {
    printf("============================================================\n");
    printf("                           TEST                             \n");
    printf("============================================================\n");

    int run_all = (argc <= 1);
    int run_perm = run_all;
    int run_hash = run_all;
    int run_aead = run_all;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "permutation") == 0 || strcmp(argv[i], "test-permutation") == 0 || strcmp(argv[i], "perm") == 0) {
            run_perm = 1;
        } else if (strcmp(argv[i], "hash") == 0 || strcmp(argv[i], "test-hash") == 0) {
            run_hash = 1;
        } else if (strcmp(argv[i], "aead") == 0 || strcmp(argv[i], "test-aead") == 0) {
            run_aead = 1;
        } else if (strcmp(argv[i], "all") == 0 || strcmp(argv[i], "test") == 0) {
            run_perm = run_hash = run_aead = 1;
        } else {
            printf("[WARN] Nieznany modul testowy: '%s' (dozwolone: permutation, hash, aead, all)\n", argv[i]);
        }
    }

    /* Inicjalizacja kontekstu frameworku Unity */
    UNITY_BEGIN();

    /* Uruchomienie wybranych modulow testowych w izolacji */
    if (run_perm) {
        run_permutation_tests();
    }
    if (run_hash) {
        run_hash_tests();
    }
    if (run_aead) {
        run_aead_tests();
    }

    /* Podsumowanie wynikow i zwrot kodu zakonczenia (0 = sukces, >0 = blad) */
    return UNITY_END();
}

