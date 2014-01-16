#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>



#ifndef WIN32
#include <pthread.h>
#define THREAD_CC   * 
#define THREAD_TYPE                    pthread_t
#define THREAD_CREATE(tid, entry, arg) pthread_create(&(tid), NULL, \
                                                      (entry), (arg))
#else
#include <windows.h>
#define THREAD_CC                      __cdecl
#define THREAD_TYPE                    DWORD
#define THREAD_CREATE(tid, entry, arg) do { _beginthread((entry), 0, (arg));\
                                            (tid) = GetCurrentThreadId();   \
                                       } while (0)
#endif

#define PORT            "8888"
#define SERVER          "localhost"
#define CLIENT          "localhost"
#define READSIZE 1024

#define int_error(msg)  handle_error(__FILE__, __LINE__, msg)
void handle_error(const char *file, int lineno, const char *msg);
int seed_prng(int bytes);

void init_OpenSSL(void);
int verify_callback(int ok, X509_STORE_CTX *store);
long post_connection_check(SSL *ssl, char *host);
#include <openssl/evp.h>
// #define EVP_MAX_BLOCK_LENGTH                24
void select_random_key(char *key, int b);
void select_random_iv (char *iv, int b);
char * encrypt_example (EVP_CIPHER_CTX * ctx, char *data, int inl, int *rb);
char * decrypt_example (EVP_CIPHER_CTX * ctx, char *ct, int inl);
void    incremental_send (char *buf, int ol);
unsigned char * process_file (FILE * f, unsigned int *olen);
int process_stdin (void);
unsigned char * simple_digest (char *alg, char *buf, unsigned int len, int *olen);
void
print_hex (unsigned char *bs, unsigned int n);
int process_file_by_name (char *fname);
unsigned char * read_file (FILE * f, int *len);

int binary_cmp (unsigned char *s1, unsigned int len1,
            unsigned char *s2, unsigned int len2);


void set_nonblocking(SSL * ssl);
void set_blocking(SSL * ssl);
void check_availability(SSL *a, unsigned int *read_a, unsigned int *write_a, SSL *b, unsigned int *read_b, unsigned int *write_b);
