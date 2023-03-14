#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <signal.h>
#include <pthread.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include "passwd.h"

int get_hashes(char *filename, char hashes[][34], int tags[]) // wczytuje tablice haszów do porównania
{
    char line[100];
    int i = 0;

    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        printf("Error opening file!\n");
        return 0;
    }

    while (fgets(line, sizeof(line), file))
    {
        int tag;
        char *token = strtok(line, " \t");
        sscanf(token, "%d", &tag);

        tags[i] = tag;
        token = strtok(NULL, " \t");

        strcpy(hashes[i], token);
        i++;
    }

    fclose(file);
    return i;
}

void get_password_dictionary(const char *filename, char ***password_dictionary, size_t *n_password_dictionary) // wczytuje tablice haseł
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        printf("Error opening file\n");
        exit(1);
    }

    // Count the number of password_dictionary in the file
    size_t capacity = 16;
    *password_dictionary = malloc(capacity * sizeof(char *));
    *n_password_dictionary = 0;
    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, file) != -1)
    {
        // printf("Line read before modification: %s\n", line);
        if (*n_password_dictionary == capacity)
        {
            capacity *= 2;
            *password_dictionary = realloc(*password_dictionary, capacity * sizeof(char *));
        }

        if (line[strlen(line) - 1] == '\r')
        {
            line[strlen(line) - 1] = '\0';
        }
        if (line[strlen(line) - 1] == '\n')
        {
            line[strlen(line) - 1] = '\0';
        }
        if (strlen(line) > 10)
        {
            line[10] = '\0';
        }

        // printf("Line read after modification: %s\n", line);
        (*password_dictionary)[*n_password_dictionary] = line;
        (*n_password_dictionary)++;
        line = NULL;
        len = 0;
    }

    free(line);
    fclose(file);
}

void decode_modifier(tmodifier_control *mdc)
{

    //  ustawia aktywność poszczególnych pętli modyfikujących czyli mdc->loop_active[]

    int modifier_code_index;
    int modifier_code_len = strlen(mdc->modifier_code);

    // printf("modifier_code_len: %d\n", modifier_code_len);

    int c = 0, w = 0;
    int i;

    for (i = 0; i < 6; i++)
    {
        mdc->positions[POSITION_CHAR_1 + i] = -1;
        mdc->loop_active[CHAR_1 + i] = INACTIVE;
    }
    for (i = 0; i < 2; i++)
    {
        mdc->positions[POSITION_WORD_1_START + i] = -1;
        mdc->positions[POSITION_WORD_1_END + i] = -1;
        mdc->loop_active[WORD_1 + i] = INACTIVE;
        mdc->upcase_mode[i] = UPCASE_ALL;
    }

    for (modifier_code_index = 0; modifier_code_index < modifier_code_len; modifier_code_index++)
    {
        if (mdc->modifier_code[modifier_code_index] == 'C')
        {

            mdc->loop_active[CHAR_1 + c] = ACTIVE;
            c++;
        }
        if ((mdc->modifier_code[modifier_code_index] == 'W') || (mdc->modifier_code[modifier_code_index] == 'A') || (mdc->modifier_code[modifier_code_index] == 'S') || (mdc->modifier_code[modifier_code_index] == 'F'))
        {
            /*
                        if (w == 0) // dla słowa 0 popchnij indeks "C" na poz.2
                        {
                            c = 2;
                        }
                        if (w == 1) // dla słowa 1 popchnij indeks "C" na poz.4
                        {
                            c = 4;
                        }*/
            switch (mdc->modifier_code[modifier_code_index])
            {
            case 'W':

                mdc->loop_active[UPLOW_1 + w] = INACTIVE;
                mdc->loop_active[WORD_1 + w] = ACTIVE;
                mdc->upcase_mode[w] = UPCASE_ALL; // nieistotne bo W nie robi upcase

                break;
            case 'A':

                mdc->loop_active[UPLOW_1 + w] = ACTIVE;
                mdc->loop_active[WORD_1 + w] = ACTIVE;
                mdc->upcase_mode[w] = UPCASE_ALL; // wszystkie wariany upcase

                break;
            case 'S':

                mdc->loop_active[UPLOW_1 + w] = ACTIVE;
                mdc->loop_active[WORD_1 + w] = ACTIVE;
                mdc->upcase_mode[w] = UPCASE_SELECTED; // 5 wariantów upcase

                break;
            case 'F':

                mdc->loop_active[UPLOW_1 + w] = INACTIVE;
                mdc->loop_active[WORD_1 + w] = ACTIVE;
                mdc->upcase_mode[w] = UPCASE_FIRST; // 1 wariant, pierwsza z wielkiej

                break;
            }
            w++;
        }
    }
    // printf("akt0 %2d akt1 %2d mode0 %2d mode1 %2d\n", mdc->loop_active[UPLOW_1], mdc->loop_active[UPLOW_2], mdc->upcase_mode[0], mdc->upcase_mode[1]);
}

void build_template(tmodifier_control *mdc)
{
    // funkcja tworzy szablon do wypełnienia wariantowego np.:
    // build_template(tmodifier_control *mdc)
    // w wyniku działania powstaje
    int modifier_code_index;
    int modifier_code_len = strlen(mdc->modifier_code);
    int moving_end_index = -1;
    int wordlen[2] = {0, 0};

    int c = 0, w = 0;
    int i;

    // printf("%d, %s, %c\n", modifier_code_len, mdc->modifier_code, modifier_code[0]);

    for (i = 0; i < 6; i++)
    {
        mdc->positions[POSITION_CHAR_1 + i] = -1;
        // mdc->loop_active[CHAR_1 + i] = INACTIVE;
    }
    for (i = 0; i < 2; i++)
    {
        mdc->positions[POSITION_WORD_1_START + i] = -1;
        mdc->positions[POSITION_WORD_1_END + i] = -1;
    }

    if (mdc->loop_active[WORD_1])
    {
        wordlen[0] = strlen(mdc->word[0]);
    }
    else
        wordlen[0] = 0;

    if (mdc->loop_active[WORD_2])
    {
        wordlen[1] = strlen(mdc->word[1]);
    }
    else
        wordlen[1] = 0;

    for (modifier_code_index = 0; modifier_code_index < modifier_code_len; modifier_code_index++)
    {
        if (mdc->modifier_code[modifier_code_index] == 'C')
        {
            moving_end_index++;
            mdc->positions[POSITION_CHAR_1 + c] = moving_end_index;
            mdc->expanded_password[moving_end_index] = '0';
            // printf("meindex: %d expanded_password: %c \n", moving_end_index, mdc->expanded_password[moving_end_index]);
            // mdc->loop_active[CHAR_1 + c] = ACTIVE;
            c++;
        }
        if ((mdc->modifier_code[modifier_code_index] == 'W') || (mdc->modifier_code[modifier_code_index] == 'A') || (mdc->modifier_code[modifier_code_index] == 'S') || (mdc->modifier_code[modifier_code_index] == 'F'))
        {
            if (mdc->loop_active[WORD_1 + w])
            {
                moving_end_index++;
                mdc->positions[POSITION_WORD_1_START + w] = moving_end_index;
                moving_end_index += wordlen[w] - 1;
                mdc->positions[POSITION_WORD_1_END + w] = moving_end_index;
                // if (mdc->loop_active[WORD_1] || mdc->loop_active[WORD_2])
                // {
                for (i = mdc->positions[POSITION_WORD_1_START + w]; i <= mdc->positions[POSITION_WORD_1_END + w]; i++)
                {
                    mdc->expanded_password[i] = mdc->word[w][i - mdc->positions[POSITION_WORD_1_START + w]];

                    // printf("[W]: %d, %d, %d, %d \n", w, i, mdc->positions[POSITION_WORD_1_START + w], mdc->positions[POSITION_WORD_1_END + w]);
                }
                if (mdc->upcase_mode[w] == UPCASE_FIRST)
                    mdc->expanded_password[mdc->positions[POSITION_WORD_1_START + w]] = toupper(mdc->expanded_password[mdc->positions[POSITION_WORD_1_START + w]]);
                //}
                /*
                                if (w == 0)
                                {
                                    c = 2;
                                }
                                if (w == 1)
                                {
                                    c = 4;
                                }
                */
                w++;
            }
        }
    }
    mdc->expanded_password[++moving_end_index] = '\0';
    // printf("template:->%s<-\n", mdc->expanded_password);
}

void case_variant_in_substring(tmodifier_control *mdc, int word_number)
{
    // ta funkcja realizuje zmianę na dużą/małą literę w obrębie substringu w stringu x
    // x jest templatem, który przechowuje między innymi słowa podlegające wariantowaniu upper/lowercase
    // z zawiera również znaki poprzedzające, separujące i następujące ale nie są one wariantowane przy pomocy upper/lower case
    // variant_index jest liczbą z zakresu 0..2^n, gdzie n to długość warinatowanego substringu
    // start_pos to pozycja początkowa substringu w placeholderze
    // end_pos to pozycja końcowa substringu w placeholderze
    // upcase_mode 0 - wykonuje wszystkie wariany up/lo
    // upcase_mode 1 - wykonuje tylko warianty up/lo na wszystkich i na skrajnych czyli aleks, ALEKS, AlekS, alekS, AlekS
    // przykład: case_variant_in_substring
    // "00jarek000",5,2,6,0)
    // "00JaRek000"
    // "5=101"
    // case_variant_in_substring(mdc->expanded_password, &mdc->index[UPLOW_1], mdc->positions[POSITION_WORD_1_START], mdc->positions[POSITION_WORD_1_END], 1);

    int word_len = mdc->positions[POSITION_WORD_1_END + word_number] - mdc->positions[POSITION_WORD_1_START + word_number];
    int char_index = 0;

    for (char_index = 0; char_index <= word_len; char_index++)
    {
        if (mdc->index[UPLOW_1 + word_number] & 1 << char_index)
        {
            mdc->expanded_password[char_index + mdc->positions[POSITION_WORD_1_START + word_number]] = toupper(mdc->expanded_password[char_index + mdc->positions[POSITION_WORD_1_START + word_number]]);
        }
        else
        {
            mdc->expanded_password[char_index + mdc->positions[POSITION_WORD_1_START + word_number]] = tolower(mdc->expanded_password[char_index + mdc->positions[POSITION_WORD_1_START + word_number]]);
        }
    }
    if (mdc->upcase_mode[word_number])
    {
        if (mdc->index[UPLOW_1 + word_number] == upcase_variants[word_len][3])
            mdc->index[UPLOW_1 + word_number] = upcase_variants[word_len][4] - 1;
        if (mdc->index[UPLOW_1 + word_number] == upcase_variants[word_len][2])
            mdc->index[UPLOW_1 + word_number] = upcase_variants[word_len][3] - 1;
        if (mdc->index[UPLOW_1 + word_number] == upcase_variants[word_len][1])
            mdc->index[UPLOW_1 + word_number] = upcase_variants[word_len][2] - 1;
        if (mdc->index[UPLOW_1 + word_number] == upcase_variants[word_len][0])
            mdc->index[UPLOW_1 + word_number] = upcase_variants[word_len][1] - 1;
    }
}

void build_hash_compare(tmodifier_control *mdc)
{
    size_t len;

    if (mdc->loop_active[WORD_1])
    {
        mdc->index_to[WORD_1] = n_password_dictionary;
    }
    else
    {
        mdc->index_to[WORD_1] = 1;
    }

    if (mdc->loop_active[WORD_2])
    {
        mdc->index_to[WORD_2] = n_password_dictionary;
    }
    else
    {
        mdc->index_to[WORD_2] = 1;
    }

    for (mdc->index[WORD_1] = 0; mdc->index[WORD_1] < mdc->index_to[WORD_1]; mdc->index[WORD_1]++)
    {
        for (mdc->index[WORD_2] = 0; mdc->index[WORD_2] < mdc->index_to[WORD_2]; mdc->index[WORD_2]++)
        {

            // len = strlen(password_dictionary[mdc->index[WORD_1]]);
            strcpy(mdc->word[0], password_dictionary[mdc->index[WORD_1]]);

            if (mdc->loop_active[WORD_2])
            {
                // len = strlen(password_dictionary[mdc->index[WORD_2]]);

                strcpy(mdc->word[1], password_dictionary[mdc->index[WORD_2]]);
            }

            build_template(mdc);

            if (!mdc->loop_active[UPLOW_1])
            {
                mdc->index_to[UPLOW_1] = 1;
            }
            else
            {
                mdc->index_to[UPLOW_1] = 1 << (mdc->positions[POSITION_WORD_1_END] - mdc->positions[POSITION_WORD_1_START] + 1);
            }

            for (mdc->index[UPLOW_1] = 0; mdc->index[UPLOW_1] < mdc->index_to[UPLOW_1]; mdc->index[UPLOW_1]++)
            {
                if (mdc->loop_active[UPLOW_1])
                {

                    case_variant_in_substring(mdc, 0);
                }

                if (!mdc->loop_active[UPLOW_2])
                {
                    mdc->index_to[UPLOW_2] = 1;
                }
                else
                {
                    mdc->index_to[UPLOW_2] = 1 << (mdc->positions[POSITION_WORD_2_END] - mdc->positions[POSITION_WORD_2_START] + 1);
                }

                for (mdc->index[UPLOW_2] = 0; mdc->index[UPLOW_2] < mdc->index_to[UPLOW_2]; mdc->index[UPLOW_2]++)
                {

                    if (mdc->loop_active[UPLOW_2])
                    {
                        case_variant_in_substring(mdc, 1);
                    }
                    /*############################################### CHAR 1 ###########################################*/
                    if (!mdc->loop_active[CHAR_1])
                    {
                        mdc->index_to[CHAR_1] = 1;
                    }
                    else
                    {
                        mdc->index_to[CHAR_1] = char_table_len;
                    }
                    // printf("mdc: %s\n", mdc->expanded_password);
                    for (mdc->index[CHAR_1] = 0; mdc->index[CHAR_1] < mdc->index_to[CHAR_1]; mdc->index[CHAR_1]++)
                    {
                        // printf("a\n");
                        if (mdc->loop_active[CHAR_1])
                        {
                            mdc->expanded_password[mdc->positions[POSITION_CHAR_1]] = char_table[mdc->index[CHAR_1]];
                        }
                        /*############################################### CHAR 2 ###########################################*/
                        if (!mdc->loop_active[CHAR_2])
                        {
                            mdc->index_to[CHAR_2] = 1;
                        }
                        else
                        {
                            mdc->index_to[CHAR_2] = char_table_len;
                        }

                        for (mdc->index[CHAR_2] = 0; mdc->index[CHAR_2] < mdc->index_to[CHAR_2]; mdc->index[CHAR_2]++)
                        {
                            if (mdc->loop_active[CHAR_2])
                            {
                                mdc->expanded_password[mdc->positions[POSITION_CHAR_2]] = char_table[mdc->index[CHAR_2]];
                            }
                            /*############################################### CHAR 3 ###########################################*/
                            if (!mdc->loop_active[CHAR_3])
                            {
                                mdc->index_to[CHAR_3] = 1;
                            }
                            else
                            {
                                mdc->index_to[CHAR_3] = char_table_len;
                            }

                            for (mdc->index[CHAR_3] = 0; mdc->index[CHAR_3] < mdc->index_to[CHAR_3]; mdc->index[CHAR_3]++)
                            {
                                if (mdc->loop_active[CHAR_3])
                                {
                                    mdc->expanded_password[mdc->positions[POSITION_CHAR_3]] = char_table[mdc->index[CHAR_3]];
                                }
                                /*############################################### CHAR 4 ###########################################*/
                                if (!mdc->loop_active[CHAR_4])
                                {
                                    mdc->index_to[CHAR_4] = 1;
                                }
                                else
                                {
                                    mdc->index_to[CHAR_4] = char_table_len;
                                }

                                for (mdc->index[CHAR_4] = 0; mdc->index[CHAR_4] < mdc->index_to[CHAR_4]; mdc->index[CHAR_4]++)
                                {
                                    if (mdc->loop_active[CHAR_4])
                                    {
                                        mdc->expanded_password[mdc->positions[POSITION_CHAR_4]] = char_table[mdc->index[CHAR_4]];
                                    }
                                    /*############################################### CHAR 5 ###########################################*/
                                    if (!mdc->loop_active[CHAR_5])
                                    {
                                        mdc->index_to[CHAR_5] = 1;
                                    }
                                    else
                                    {
                                        mdc->index_to[CHAR_5] = char_table_len;
                                    }

                                    for (mdc->index[CHAR_5] = 0; mdc->index[CHAR_5] < mdc->index_to[CHAR_5]; mdc->index[CHAR_5]++)
                                    {
                                        if (mdc->loop_active[CHAR_5])
                                        {
                                            mdc->expanded_password[mdc->positions[POSITION_CHAR_5]] = char_table[mdc->index[CHAR_5]];
                                        }

                                        /*############################################### CHAR 6 ###########################################*/
                                        if (!mdc->loop_active[CHAR_6])
                                        {
                                            mdc->index_to[CHAR_6] = 1;
                                        }
                                        else
                                        {
                                            mdc->index_to[CHAR_6] = char_table_len;
                                        }

                                        for (mdc->index[CHAR_6] = 0; mdc->index[CHAR_6] < mdc->index_to[CHAR_6]; mdc->index[CHAR_6]++)
                                        {
                                            if (mdc->loop_active[CHAR_6])
                                            {
                                                mdc->expanded_password[mdc->positions[POSITION_CHAR_6]] = char_table[mdc->index[CHAR_6]];
                                            }
                                            hash_it(mdc);
                                            /*step++;
                                            step3 = mdc->index[UPLOW_1];
                                            step4 = mdc->index[UPLOW_2];
                                            step5 = mdc->index[CHAR_1];
                                            step6 = mdc->index[CHAR_2];
                                            step7 = mdc->index[CHAR_3];
                                            step8 = mdc->index[CHAR_4];
                                            step9 = mdc->index[CHAR_5];
                                            step10 = mdc->index[CHAR_6];*/

                                            mdc->compare_result = compare_it(mdc, n_hashes, hashes_ptr);
                                            // printf("step1: %-10lld; step2: %-10lld; step3: %-10lld,step4: %-10lld,step5: %-10lld,step6: %-10lld,step7: %-10lld,step8: %-10lld,step9: %-10lld,step10: %-10lld\n", step, step2, step3, step4, step5, step6, step7, step8, step9, step10);

                                            // printf("HASHED: %-34s; PASSWD: %-34s \n", mdc->hashed_expanded_password, mdc->expanded_password);
                                            // printf("mdc: %-10s, %-10s, Placeholder: %-20s , index: %-2d, index 2: %-2d, index uplow 1 %-2d,  index uplow 2 %-2d, position start %-2d, position end %-2d  \n", mdc->word[0], mdc->word[1], mdc->expanded_password, mdc->index[WORD_1], mdc->index[WORD_2], mdc->index[UPLOW_1], mdc->index[UPLOW_2], mdc->positions[POSITION_WORD_2_START], mdc->positions[POSITION_WORD_2_END]);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

void hash_it(tmodifier_control *mdc) //(const char *data, int len, char *hashed_expanded_password_arg) // haszuje i zwraca zahaszowane
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, mdc->expanded_password, strlen(mdc->expanded_password));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);
    int md5_len = 0;

    for (i = 0; i < md_len; i++)
    {
        md5_len += snprintf(&(mdc->hashed_expanded_password[md5_len]), 33 - md5_len, "%02x", md_value[i]);
    }
    mdc->hashed_expanded_password[32] = '\0';
    // printf(""mdc->hashed_expanded_password)
}

int compare_it(tmodifier_control *mdc, int n_hashes_arg, char **hashes_arg) // porownuje zahaszowane hasło ze wszystkimi elementami tablicy hashes
{
    // printf("HASHED: %-34s; PASSWD: %-34s; HASHES ARG: %-34s \n", mdc->hashed_expanded_password, mdc->expanded_password, *(hashes_arg));

    for (int i = 0; i < n_hashes_arg; i++)
    {
        mdc->searches++;
        // printf("Search: %4lld passwd: %-20s, exp.pass %20s, %-2d, %2d\n", mdc->searches, mdc->expanded_password, mdc->hashed_expanded_password, i, n_hashes_arg);

        if (strcmp(mdc->hashed_expanded_password, *(hashes_arg + i)) == 0)
        {
            pthread_mutex_lock(&lock);
            results.index++;
            results.password_tag[results.index] = tags[i];
            results.thread_id[results.index] = mdc->threadid;
            results.job_id[results.index] = mdc->job_number;
            strcpy(results.modifier_code[results.index], mdc->modifier_code);
            strcpy(results.password[results.index], mdc->expanded_password);
            strcpy(results.hashed_password[results.index], mdc->hashed_expanded_password);
            mdc->hits++;

            // printf("NEW PASSWORD: %-2d; THREADID: %-3d; RESULT INDEX: %-3d; MODIFIER_CODE: %-10s; FOUND PASSWORD: %-20s; HASHED PASSWORD: %-34s; TAG %-3d \n", results.last_read + 1, results.thread_id[results.last_read + 1], results.index, results.modifier_code[results.last_read + 1], results.password[results.last_read + 1], results.hashed_password[results.last_read + 1], results.password_tag[results.last_read + 1]);
            // printf("step: %-20lld; step2: %-20lld; step3: %-20lldtags: %-2d; THREADID: %-20ld; mdc->modifier_code %-10s; mdc->expanded_password: %-10s;  \n", step, step2, step3, tags[i], mdc->threadid, mdc->modifier_code, mdc->expanded_password);
            // printf("step1: %-10lld; step2: %-10lld; step3: %-10lld,step4: %-10lld,step5: %-10lld,step6: %-10lld,step7: %-10lld,step8: %-10lld,step9: %-10lld,step10: %-10lld,", step, step2, step3, step4, step5, step6, step7, step8, step9, step10);
            pthread_mutex_unlock(&lock);
            return 0;
        }
    }
    return 1;
}

void *crack(void *i)
{
    tmodifier_control *mdc;
    mdc = i;
    decode_modifier(mdc);
    build_hash_compare(mdc);
    pthread_mutex_lock(&lock);
    // printf("========== %3d\n", mdc->job_number);
    mdc->job_finished = 1;
    mdc->job_started = 0;
    results.job_just_finished = 1;
    time(&time_current);
    mdc->job_time = time_current - time_start;
    if (mdc->job_time)
        mdc->operations_per_s = (double)mdc->searches / (double)mdc->job_time;
    pthread_mutex_unlock(&lock);
    return (void *)i;
}

void *client(void *i)
{
    tmodifier_control *mdc;
    mdc = i;
    int k;
    while (1)
    {

        pthread_mutex_lock(&lock);
        time(&time_current);
        while (results.last_read < results.index)
        {
            printf("---NEW PASSWORD: %-2d; JOB: %-3d; MODICODE: %-10s; FOUND PASSWORD: %-20s; HASHED PASSWORD: %-34s; TAG %-3d \n", results.last_read + 1, results.job_id[results.last_read + 1], results.modifier_code[results.last_read + 1], results.password[results.last_read + 1], results.hashed_password[results.last_read + 1], results.password_tag[results.last_read + 1]);
            results.last_read++;
        }
        if (results.job_just_finished || (time_current >= time_previous + REFRESH_TIME))
        {
            system("clear");
            time_previous = time_current;
            results.job_just_finished = 0;
            results.last_read = -1;
            for (k = 0; k <= last_job_started; k++)
            {
                if (modifier_control[k].job_finished)
                {
                    printf("JOB FINISHED: %3d THREAD ID: %10ld MODICODE:%10s searches %20lld  hits: %3d job time: %10d ops/s: %.0lf\n", k, modifier_control[k].threadid, modifier_control[k].modifier_code, modifier_control[k].searches, modifier_control[k].hits, modifier_control[k].job_time, modifier_control[k].operations_per_s);
                }
            }
            printf("\n");
            for (k = 0; k <= last_job_started; k++)
            {

                if (modifier_control[k].job_started)
                {
                    modifier_control[k].job_time = time_current - time_start;
                    if (modifier_control[k].job_time)
                        modifier_control[k].operations_per_s = (double)modifier_control[k].searches / (double)modifier_control[k].job_time;
                    printf("JOB STARTED : %3d THREAD ID: %10ld MODICODE:%10s searches: %20lld  hits: %3d job time: %10d ops/s: %.0lf\n", k, modifier_control[k].threadid, modifier_control[k].modifier_code, modifier_control[k].searches, modifier_control[k].hits, modifier_control[k].job_time, modifier_control[k].operations_per_s);
                }
            }
            printf("\n");
        }
        pthread_mutex_unlock(&lock);
        usleep(100000); // 100 ms
    }
    return (void *)i;
}

void init_all(void)
{
    int i, j;
    time(&time_current);
    time_previous = time_current;
    time_start = time_current;
    last_job_started = -1;
    system("clear");
    for (i = 0; i < MAXTHREADS; i++)
    {
        modifier_control[i].job_started = 0;
        modifier_control[i].job_finished = 0;
        modifier_control[i].upcase_mode[0] = 0;
        modifier_control[i].upcase_mode[1] = 0;
        modifier_control[i].searches = 0;
        modifier_control[i].hits = 0;
        modifier_control[i].job_time = 0;
        modifier_control[i].operations_per_s = 0.0;
        for (j = 0; j < 20; j++)
        {
            modifier_control[i].loop_active[j] = 0;
        }
    }

    for (i = 0; i < MAXRESULTS; i++)
    {
        strcpy(results.password[i], "");
        strcpy(results.hashed_password[i], "");
        strcpy(results.modifier_code[i], "");
    }
    results.index = -1;
    results.last_read = -1;
    results.jobs_running = 0;
    results.job_just_finished = 0;
    char_table_len = strlen(char_table); // globalne

    n_hashes = get_hashes("hash.txt", hashes, tags);                                   // diff-data.txt
    get_password_dictionary("dict.txt", &password_dictionary, &n_password_dictionary); // test-dict-mini-copy

    for (int i = 0; i < n_hashes; i++)
    {
        hashes_ptr[i] = hashes[i];
    }
    for (i = 0; i < MODICODES_COUNT; i++)
    {
        strcpy(modifier_control[i].modifier_code, modifierer_codes[i]);
    }
    pthread_mutex_init(&lock, NULL);
    pthread_mutex_init(&lock2, NULL);
}

void run_threads()
{
    int thread_index = 0;
    while ((strlen(modifier_control[thread_index].modifier_code)) && thread_index < MAXTHREADS - 1 && thread_index <= MODICODES_COUNT)
    {
        modifier_control[thread_index].job_number = thread_index;
        last_job_started = thread_index;
        modifier_control[thread_index].job_started = 1;
        pthread_create(&(modifier_control[thread_index].threadid), NULL, crack, (void *)&(modifier_control[thread_index]));
        printf("JOB STARTED: %3d THREAD ID: %10ld MODICODE:%10s\n", thread_index, modifier_control[thread_index].threadid, modifier_control[thread_index].modifier_code);
        thread_index++;
    }

    pthread_create(&(modifier_control[CLIENTTHREAD_NUMBER].threadid), NULL, client, (void *)&(modifier_control[CLIENTTHREAD_NUMBER]));
}

void close_all(void)
{
    int thread_index;
    //  pthread_join(tid[1], NULL);
    pthread_join(modifier_control[99].threadid, NULL);

    pthread_mutex_destroy(&lock);
    pthread_mutex_destroy(&lock2);
    free(password_dictionary);

    for (thread_index = 0; thread_index < last_job_started; thread_index++)
    {
        pthread_join(modifier_control[thread_index].threadid, NULL);
    }
    pthread_join(modifier_control[CLIENTTHREAD_NUMBER].threadid, NULL);
}

int main()
{
    init_all();
    run_threads();

    while (1)
    {
        usleep(2000000); // 10 ms
    }

    close_all();

    return 0;
}