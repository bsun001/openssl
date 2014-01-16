/*
    gcc server.c common.c -o server -lcrypto -lssl -lpthread
 */
#include "common.h"
 
void do_server_loop(BIO *conn)
{
    int   err;
    char buf[8000];
 
    do
    {
        err = BIO_read(conn, buf , sizeof(buf));
        fwrite(buf, 1, err, stdout);
    }
    while (err > 0);
}
 
void THREAD_CC server_thread(void *arg)
{
    BIO *client = (BIO *)arg;
 
#ifndef WIN32
    pthread_detach(pthread_self(  ));
#endif
    fprintf(stderr, "Connection opened.\n");
    do_server_loop(client);
    fprintf(stderr, "Connection closed.\n");

    BIO_free(client);
    ERR_remove_state(0);
#ifdef WIN32
    _endthread(  );
#endif
    return 0;
}
 
int main(int argc, char *argv[])
{
    BIO         *acc, *client;
    THREAD_TYPE tid;
 
    init_OpenSSL(  );
 
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
        THREAD_CREATE(tid, server_thread,  client);

    }
 
    BIO_free(acc);
    return 0;
}

