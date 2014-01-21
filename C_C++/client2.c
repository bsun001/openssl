/*
    To compile:
    gcc client2.c common.c -o client2 -lcrypto -lssl -lpthread

    This code uses OpenSSL; it uses an SSL certificate, and try to validate it.
    Still, no SSL options are selected, nor are the cipher suits.
 */
#include "common.h"
 
#define CAFILE "root.pem"
#define CADIR NULL
#define CERTFILE "client.pem"
#define KEYFILE "clientkey.pem"
//#define CAFILE NULL
//#define CADIR "/root/prog/openssl"
#define KEYFILE "clientkey.pem"
#define CIPHERLIST "AES128-SHA"
#define PASSWORD "hello"

SSL_CTX *setup_client_ctx(void)
{
    SSL_CTX *ctx;
    STACK_OF(X509_NAME) *cert_names;

    /* initialize SSL libraries */
    SSL_library_init();

    ctx = SSL_CTX_new(SSLv23_method(  ));
    if (!ctx)
        int_error("Error creating SSL context");

    /* set cipher list */
    if (SSL_CTX_set_cipher_list(ctx, CIPHERLIST) <= 0) {
        int_error("Error setting the cipher list.");
    }

    /* set certificate */
    if (SSL_CTX_use_certificate_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1)
        int_error("Error loading certificate from file");
    /* load password */
    SSL_CTX_set_default_passwd_cb_userdata(ctx, PASSWORD);

    /*Indicate the key file to be used*/
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYFILE, SSL_FILETYPE_PEM) <= 0) {
        int_error("Error setting the key file.");
    }

    /*Make sure the key and certificate file match*/
    if (SSL_CTX_check_private_key(ctx) == 0)
        int_error("Private key does not match the certificate public key");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL); // verify_callback);

    /* Load certificates of trusted CAs based on file provided*/
    if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
        int_error("Error loading CA file and/or directory");

    /* Set CA list used for client authentication. */
    if ((cert_names = SSL_load_client_CA_file(CAFILE))  == NULL) {
        int_error("Error loading CA file CAFILE.");
    }
    SSL_CTX_set_client_CA_list(ctx, cert_names);

    SSL_CTX_set_verify_depth(ctx, 0);
    return ctx;
}
 
int do_client_loop(SSL *ssl)
{
    int  err, nwritten;
    char buf[80];
 
    for (;;)
    {
        if (!fgets(buf, sizeof(buf), stdin))
            break;
        for (nwritten = 0;  nwritten < sizeof(buf);  nwritten += err)
        {
            err = SSL_write(ssl, buf + nwritten, strlen(buf) - nwritten);
            if (err <= 0)
                return 0;
        }
    }
    return 1;
}
 
int main(int argc, char *argv[])
{
    BIO     *conn;
    SSL     *ssl;
    SSL_CTX *ctx;
    long    err;

    init_OpenSSL(  );
    seed_prng( 1024 );
 
    ctx = setup_client_ctx(  );
 
    int_info("client starts new connection");
    conn = BIO_new_connect(SERVER ":" PORT);
    if (!conn)
        int_error("Error creating connection BIO");
 
    if (BIO_do_connect(conn) <= 0)
        int_error("Error connecting to remote machine");
 
    int_info("From client2. Calling SSL_new()");
    ssl = SSL_new(ctx);
    int_info("From client2. Calling SSL_set_bio()");
    SSL_set_bio(ssl, conn, conn);
    if (SSL_connect(ssl) <= 0) {
        const long double sysTime = time(0);
        printf("Current time: %Lf seconds since the Epoch\n", sysTime);
        struct timeb tmb;
        ftime(&tmb);
        printf("tmb.time     = %ld (seconds)\n", tmb.time);
        printf("tmb.millitm  = %d (mlliseconds)\n", tmb.millitm);
//      sprintf(str, "client current time: %s", current_time);
//      int_info(str);
        int_error("Error connecting SSL object");
    }
    if ((err = post_connection_check(ssl, SERVER)) != X509_V_OK)
    {
        fprintf(stderr, "-Error: peer certificate: %s\n",
                X509_verify_cert_error_string(err));
        int_error("Error checking SSL object after connection");
    }
    fprintf(stderr, "SSL Connection opened\n");
    if (do_client_loop(ssl))
        SSL_shutdown(ssl);
    else
        SSL_clear(ssl);
    fprintf(stderr, "SSL Connection closed\n");
 
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
