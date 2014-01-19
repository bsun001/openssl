/*
    To compile:
    gcc server2.c common.c -o server2 -lcrypto -lssl -lpthread

    This code uses OpenSSL; it uses an SSL certificate, and try to validate it.
    Still, no SSL options are selected, nor are the cipher suits.
 */
#include "common.h"
 
#define CAFILE1 "root.pem"
#define CAFILE2 "serverCA.pem"
//#define CAFILE NULL
#define CADIR NULL
//#define CADIR "/root/prog/openssl"
#define CERTFILE "server.pem"
SSL_CTX *setup_server_ctx(void)
{
    SSL_CTX *ctx;
 
    ctx = SSL_CTX_new(SSLv23_method(  ));
    if (SSL_CTX_load_verify_locations(ctx, CAFILE1, CADIR) != 1)
        int_error("Error loading CA file and/or directory");
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        int_error("Error loading default CA file and/or directory");
    if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
        int_error("Error loading certificate from file");
    if (SSL_CTX_use_PrivateKey_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1)
        int_error("Error loading private key from file");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_callback);
    int_info("server starts verification");
    SSL_CTX_set_verify_depth(ctx, 4);
    int_info("server finishes verification");
    return ctx;
}
 
int do_server_loop(SSL *ssl)
{
    int  err, nread;
    char buf[80];
 
    for (;;)
    {
        for (nread = 0;  nread < sizeof(buf);  nread += err)
        {
            err = SSL_read(ssl, buf + nread, sizeof(buf) - nread);
            if (err <= 0)
                break;
        }
        fwrite(buf, 1, nread, stdout);
    }
    return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1 : 0;
}
  
void THREAD_CC server_thread(void *arg)
{
    SSL *ssl = (SSL *)arg;
    long err;
 
#ifndef WIN32
    pthread_detach(pthread_self(  ));
#endif
    int_info("From server. Calling SSL_accept()");
    if (SSL_accept(ssl) <= 0) {
        const long double sysTime = time(0);
        printf("Current time: %Lf seconds since the Epoch\n", sysTime);
        struct timeb tmb;
        ftime(&tmb);
        printf("tmb.time     = %ld (seconds)\n", tmb.time);
        printf("tmb.millitm  = %d (mlliseconds)\n", tmb.millitm);
//      sprintf(&str[0], "server current time: %s", current_time);
//      int_info(&str[0]);
        int_error("Error accepting SSL connection");
    }
    if ((err = post_connection_check(ssl, CLIENT)) != X509_V_OK)
    {
        fprintf(stderr, "-Error: peer certificate: %s\n",
                X509_verify_cert_error_string(err));
        int_error("Error checking SSL object after connection");
    }
    fprintf(stderr, "SSL Connection opened\n");
    if (do_server_loop(ssl))
        SSL_shutdown(ssl);
    else
        SSL_clear(ssl);
    fprintf(stderr, "SSL Connection closed\n");
    SSL_free(ssl);
    ERR_remove_state(0);
#ifdef WIN32
    _endthread(  );
#endif
return 0;
}
 
int main(int argc, char *argv[])
{
    BIO     *acc, *client;
    SSL     *ssl;
    SSL_CTX *ctx;
    THREAD_TYPE tid;

    init_OpenSSL(  );
    seed_prng( 1024 );
 
    ctx = setup_server_ctx(  );
 
    acc = BIO_new_accept(PORT);
    if (!acc)
        int_error("Error creating server socket");
 
    if (BIO_do_accept(acc) <= 0)
        int_error("Error binding server socket");
 
    for (;;)
    {
        if (BIO_do_accept(acc) <= 0)
            int_error("Error accepting connection");
 
        client = BIO_pop(acc);
        if (!(ssl = SSL_new(ctx)))
        int_error("Error creating SSL context");
        SSL_set_accept_state(ssl);
        SSL_set_bio(ssl, client, client);
        THREAD_CREATE(tid, server_thread, ssl);
    }
 
    SSL_CTX_free(ctx);
    BIO_free(acc);
    return 0;
}
