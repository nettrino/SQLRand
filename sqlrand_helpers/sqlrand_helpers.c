/*
 * Copyright (c) 2014, Columbia University
 * All rights reserved.
 *
 * This software was developed by Theofilos Petsios <theofilos@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in September 2014.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "postgresql/libpq-fe.h"
#include "mysql/mysql.h"

#include "sqlrand_helpers.h"

int
isKeyword(char *word, int mysql)
{
	if (!word)
		return 0;

	int i = 0;

	if (mysql == 1) {
		for (i = 0; ; i++) {
			if (MYSQL_KEYWORDS[i] == NULL)
				return 0;
			if (strcasecmp(word, MYSQL_KEYWORDS[i]) == 0)
				return 1;
		}
	} else {
		for (i = 0; ; i++) {
			if (PSQL_KEYWORDS[i] == NULL)
				return 0;
			if (strcasecmp(word, PSQL_KEYWORDS[i]) == 0)
				return 1;
		}
	}

	return 0;
}

void
convert_to_plaintext(char *hash, int is_mysql)
{
	if (!hash)
		return;

	char *line = NULL;
	char *token = NULL;
	FILE *fp;
	size_t len = 0;
	ssize_t read;

	if (is_mysql == 1)
		fp = fopen(MYSQL_MAPPING_FILE, "r");
	else
		fp = fopen(PGSQL_MAPPING_FILE, "r");

	if (fp == NULL) {
		perror("Could not open mapping file");
		exit(EXIT_FAILURE);
	}

	while((read = getline(&line, &len, fp)) != -1) {
		token = NULL;
		token = strtok(line, " ");
		if (strncasecmp(token, hash, strlen(token)) == 0) {
			token = strtok(NULL, " ");
			strncpy(hash, token, strlen(hash));
			break;
		}
	}

	free(line);
	fclose(fp);
}

void log_exit(char *input_str)
{
	FILE *fp;
	char *log     = "/sqlrand_exit.log";

	char *tc_root = getenv(SS_TC_ROOT);
	if (tc_root == NULL) {
		/* if no $SS_TC_ROOT use tmp */
		char *tc_root = calloc(1, (strlen(TMP_FILE) + 1) * sizeof(char));
		if (tc_root == NULL) {
			perror("calloc str failed!");
			exit(EXIT_FAILURE);
		}
		strncat(tc_root, TMP_FILE, strlen(TMP_FILE));
	}


	char *ofile = calloc(1, (strlen(tc_root) + strlen(log) + 1) * sizeof(char));
	if (ofile == NULL) {
		perror("calloc str failed!");
		exit(EXIT_FAILURE);
	}

	strncpy(ofile, tc_root, strlen(tc_root));
	strncat(ofile, log, strlen(log));
	printf("%s\n", ofile);

	fp = fopen(ofile, "w");
	if (fp == NULL) {
		perror("Could not open log file");
		exit(EXIT_FAILURE);
	}

	fprintf(fp, "CONTROLLED_EXIT: SQL Injection Detected. Aborting..\n");
	fprintf(fp, "Input string was: \n\n %s", input_str);
	fclose(fp);
	free(ofile);
}

/*
* Check if input is clean from SQL injection and return plaintext
*/
void
get_plaintext_from_string(char *input, int is_mysql)
{
	if (!input)
		return;

	/* Copy input in another string and work with that */
	char *hashed_str = (char *) calloc(1, (strlen(input) + 1) * sizeof(char));
	if (hashed_str == NULL) {
		perror("calloc str failed!");
		exit(EXIT_FAILURE);
	}

	strcpy(hashed_str, input);

	/* make room for plaintext */
	char *plain = calloc(1, (strlen(input) + 1) * sizeof(char));
	if (plain == NULL) {
		perror("plain str failed!");
		exit(EXIT_FAILURE);
	}

	/* read all strings in input */
	int str_start = 0;
	char *str = NULL;
	unsigned int i = 0;
	unsigned int j;
	while(i < strlen(input)) {
		if (isalnum(input[i])) {
			/* If we found the beginning of a string, go all the way
			 * and sanitize it if it is a keyword. Ignore anything not
			 * alphanumeric and append to plain */
			str_start = i;
			while (isalnum(input[i]) || input[i] == '_')
				i++;

			if (str)
				free(str);
			/* proper as now i is the \0 character */
			str = calloc(1, (i - str_start) * sizeof(char));
			for (j = str_start; j < i; j++) {
				str[j - str_start] = input[j];
			}
			/* If we found a keyword abort */
			if (isKeyword(str, is_mysql)) {
				/* log */
				log_exit(input);
				exit(EXIT_FAILURE);
			}
			convert_to_plaintext(str, is_mysql);
			strncat(plain, str, i - str_start);
		}
		plain[i] = input[i++];
	}

	strncpy(input, plain, strlen(input));

	if (str)
		free(str);
	free(plain);
	free(hashed_str);
}

int
__sqlrand_mysql_real_query(MYSQL *sql, const char *input, unsigned long length)
{
	char *plain = calloc(1, (strlen(input) + 1) * sizeof(char));
	strcpy(plain, input);

	get_plaintext_from_string(plain, 1);

	int mysql_ret = mysql_real_query(sql, plain, length);

	free(plain);
	return mysql_ret;
}

int
__sqlrand_mysql_query(MYSQL *sql, const char *input)
{
	char *plain = calloc(1, (strlen(input) + 1) * sizeof(char));
	strcpy(plain, input);

	get_plaintext_from_string(plain, 1);

	int mysql_ret = mysql_query(sql, plain);

	free(plain);
	return mysql_ret;
}

PGresult *
__sqlrand_PQexec(PGconn *conn, const char *input)
{
	char *plain = calloc(1, (strlen(input) + 1) * sizeof(char));
	strcpy(plain, input);

	get_plaintext_from_string(plain, 0);

	PGresult *pq_ret = PQexec(conn, plain);

	free(plain);
	return pq_ret;
}
