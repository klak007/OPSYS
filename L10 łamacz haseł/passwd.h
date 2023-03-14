#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <signal.h>
#include <pthread.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>

#define MAXRESULTS 2000
#define MAXCHARS 30
#define MAXTHREADS 100
#define MAXTEMPLATELEN 12
#define MAXHASHES 200
#define MODICODES_COUNT 40
#define CLIENTTHREAD_NUMBER 99

#define ACTIVE 1
#define INACTIVE 0
#define UPCASE_ALL 0
#define UPCASE_SELECTED 1
#define UPCASE_FIRST 2

#define WORD_1 0
#define WORD_2 1
#define UPLOW_1 2
#define UPLOW_2 3
#define CHAR_1 4
#define CHAR_2 5
#define CHAR_3 6
#define CHAR_4 7
#define CHAR_5 8
#define CHAR_6 9

#define POSITION_WORD_1_START 0
#define POSITION_WORD_2_START 1
#define POSITION_WORD_1_END 2
#define POSITION_WORD_2_END 3
#define POSITION_PLACEHOLDER_END 4
#define POSITION_CHAR_1 5
#define POSITION_CHAR_2 6
#define POSITION_CHAR_3 7
#define POSITION_CHAR_4 8
#define POSITION_CHAR_5 9
#define POSITION_CHAR_6 10
#define POSITION_SHIFT 1

#define REFRESH_TIME 10

typedef struct
{
    char modifier_code[10];
    int aux;
    int job_number;
    int job_started;
    int job_finished;
    int job_time;
    double operations_per_s;
    long long searches;
    int hits;
    char word[2][30];
    int compare_result;
    char expanded_password[30];        // template przechowujący słowa ze słownika oraz znaki dodatkowe np.: "0Alek00KLK"
    char hashed_expanded_password[34]; // zahashowane hasło
    int index[20];                     // przechowuje indeksy do iteracji w poszczególnych pętlach modyfikujących
    int index_from[20];                // przechowuje indeksy poczatkowe dla poszczególnych pętli modyfikujących
    int index_to[20];                  // przechowuje indeksy koncowe dla poszczególnych pętli modyfikujących
    int loop_active[20];               // przechowuje znacznik aktywności danej pętli modyfikującej
    int positions[20];                 // przechowuje pozycje słów ze słownika oraz znaków dodatkowych w placeholderze
    int upcase_mode[2];                // przechowuje trub działania funkcji case_variant.. dla słowa 1 i 2
    pthread_t threadid;
} tmodifier_control;

typedef struct
{
    char password[MAXRESULTS][30];
    char hashed_password[MAXRESULTS][40];
    int password_tag[MAXRESULTS];
    int index;
    int last_read;
    int jobs_running;
    int job_just_finished; // powiadomienie o zakończeniu jakiegoś jobu;
    int thread_id[MAXRESULTS];
    int job_id[MAXRESULTS];
    char modifier_code[MAXRESULTS][10];
} tresults;

tresults results;
char hashes[MAXHASHES][34]; // 34 = length of hash +\0
int n_hashes;
char *hashes_ptr[MAXHASHES];
int tags[MAXHASHES];
long long step, step2, step3, step4, step5, step6, step7, step10, step8, step9;
char char_table[30] = "0123456789#&"; //%$>;;; #%$>&"; // 0123456789#%$>&"; // globalne !@^*()
int char_table_len;
char modifierer_codes[MODICODES_COUNT][10] = {
    "S",
    "SC",
    "CCS",
    "FCC",
    "CS",
    "SCC",
    "FCCC",
    "CCWCC",
    "CFCC",
    "WCCC",
    "WCW",
    "",
    "WCCF",
    "FCCW",
    "FCCF",
    "CCWCCSCC",
    "SCCCC",
    "CCCCS",
    "WC",
    "CW",
    "WCC",
    "CCW",
    "WCCC",
    "CCCW",
    "CWC",
    "C",
    "WW",
    "WCW",
    "CWCW",
    "CWCWC",
    "WWC",
    "SSCC",
    "A",
    "AC",
    "SSCCC",
    "CCSSCC",
    "CCSCCSCC",
    "",
    "",
    ""};
/*
char modifierer_codes[MODICODES_COUNT][10] = {
    "W",
    "S",
    "CS",
    "CCS",
    "CCCS",
    "SC",
    "SCC",
    "SCCC",
    "CSC",
    "CCSC",
    "CSCC",
    "CCCSC",
    "CSCCC",
    "CCSCC",
    "SCCCC",
    "CCCCS",
    "WC",
    "CW",
    "WCC",
    "CCW",
    "WCCC",
    "CCCW",
    "CWC",
    "C",
    "",
    "",
    "",
    ""};
*/
unsigned int upcase_variants[16][5] = {{0b10, 0b10, 0b10, 0b00, 0b01}, {0b100, 0b00, 0b01, 0b10, 0b11}, {0b00, 0b01, 0b100, 0b101, 0b111}, {0b00, 0b01, 0b1000, 0b1001, 0b1111}, {0b00, 0b01, 0b10000, 0b10001, 0b11111}, {0b00, 0b01, 0b100000, 0b100001, 0b111111}, {0b00, 0b01, 0b1000000, 0b1000001, 0b1111111}, {0b00, 0b01, 0b10000000, 0b10000001, 0b11111111}, {0b00, 0b01, 0b100000000, 0b100000001, 0b111111111}, {0b00, 0b01, 0b1000000000, 0b1000000001, 0b1111111111}, {0b00, 0b01, 0b10000000000, 0b10000000001, 0b11111111111}, {0b00, 0b01, 0b100000000000, 0b100000000001, 0b111111111111}, {0b00, 0b01, 0b1000000000000, 0b1000000000001, 0b1111111111111}, {0b00, 0b01, 0b10000000000000, 0b10000000000001, 0b11111111111111}, {0b00, 0b01, 0b100000000000000, 0b100000000000001, 0b111111111111111}, {0b00, 0b01, 0b1000000000000000, 0b1000000000000001, 0b1111111111111111}};

char **password_dictionary;
size_t n_password_dictionary;

pthread_mutex_t lock, lock2, lock3;
int last_job_started;
time_t time_previous, time_current, time_start;

int found_at_tag;
tmodifier_control modifier_control[MAXTHREADS];

int get_hashes(char *filename, char hashes[][34], int tags[]);                                                  // wczytuje tablice haszów do porównania
void get_password_dictionary(const char *filename, char ***password_dictionary, size_t *n_password_dictionary); // wczytuje tablice haseł
void build_template(tmodifier_control *mdc);

// void case_variant_in_substring(char *x, int *variant_index, int start_pos, int end_pos, int mode);
void case_variant_in_substring(tmodifier_control *mdc, int word_number);
void decode_modifier(tmodifier_control *mdc);
void build_hash_compare(tmodifier_control *mdc);
void hash_it(tmodifier_control *mdc);
int compare_it(tmodifier_control *mdc, int n_hashes_arg, char **hashes_arg);
void *crack(void *i);
void *client(void *i);
