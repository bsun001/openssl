/*
    To compile: gcc example0.c -o example0 -lcrypto
 */

#include <stdio.h>
 
#include </usr/include/openssl/conf.h>
#include </usr/include/openssl/evp.h>

int main(int arc, char *argv[])
{ 
  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();

  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();

  /* Load config file, and other important initialisation */
  OPENSSL_config(NULL);

  /* ... Do some crypto stuff here ... */
  printf("Do something here...\n");

  /* Clean up */

  /* Removes all digests and ciphers */
  EVP_cleanup();

  /* Remove error strings */
  ERR_free_strings();

  return 0;
}
