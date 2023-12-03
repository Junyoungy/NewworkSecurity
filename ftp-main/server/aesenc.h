
#ifndef _AESENC_H_
#define _AESENC_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h> 
#include <fcntl.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>

void handleErrors(void);
int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char *iv, unsigned char* ciphertext);
int decrypt(unsigned char* ciphertext, int ciphertextg_len, unsigned char* key, unsigned char *iv, unsigned char* recovered);
void error_handling(char *msg);
int RSAES_key_generator();
void read_childproc(int sig);

#endif

