//#include <tpf/tpfeq.h>
//#include <tpf/tpfio.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <openssl/ssl.h>

/* define HOME to be dir for key and certificate files... */
#define HOME "./"
/* Make these what you want for certificate & key files */
#define CERT_FILE "server.pem"
#define KEY_FILE "serverkey.pem"

/*Cipher list to be used*/
#define CIPHER_LIST "AES128-SHA"

/*Trusted CAs location*/
#define CA_FILE "root.pem"
#define CA_DIR  NULL

/*Password for the key file*/
#define KEY_PASSWD "hello"


void QSSL()
{
  int listener_socket;
  int connection_socket;
  int err, count;
  char buff[32];
  unsigned char aoapgm[4]={'Q','S','S','L'};
  unsigned char aoaparm[8];
  STACK_OF(X509_NAME) *cert_names;

  /*SSL PART*/
  SSL_METHOD *meth;
  SSL_CTX  *ctx;
  SSL  *myssl;


  /* Get information from the AOA call*/

//(void)memcpy(&listener_socket,&(ecbptr()->ebw004),sizeof(listener_socket));
//(void)memcpy(&connection_socket,&(ecbptr()->ebw008),sizeof(connection_socket));
  activate_on_accept(listener_socket,aoaparm,aoapgm,0);

  /* Initialize the SSL libraries*/
  SSL_library_init();

  /*Set SSLv23 for the connection*/
  meth=(SSL_METHOD *)SSLv23_server_method();

  /* Create the new CTX with the method */
  ctx=SSL_CTX_new(meth);
  if (!ctx) {
    printf("Error creating the context.\n");
    exit(0);
  }

  /*Set the Cipher List*/
  if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) <= 0) {
    printf("Error setting the cipher list.\n");
    exit(0);
  }

  /*Set the certificate to be used.*/
  if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
    printf("Error setting the certificate file.\n");
    exit(0);
  }

  /*Load the password for the Private Key*/
  SSL_CTX_set_default_passwd_cb_userdata(ctx,KEY_PASSWD);

  /*Indicate the key file to be used*/
  if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
    printf("Error setting the key file.\n");
    exit(0);
  }

  /*Make sure the key and certificate file match*/
  if (SSL_CTX_check_private_key(ctx) == 0) {
    printf("Private key does not match the certificate public key\n");
    exit(0);
  }

  /*Used only if client authentication will be used*/
  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,NULL);

  /* Load certificates of trusted CAs based on file provided*/
  if (SSL_CTX_load_verify_locations(ctx,CA_FILE,CA_DIR)<1) {
    printf("Error setting the verify locations.\n");
    exit(0);
  }

  /* Set CA list used for client authentication. */
  cert_names = SSL_load_client_CA_file(CA_FILE);
  if (cert_names != NULL)
    SSL_CTX_set_client_CA_list(ctx, cert_names);
  else {
    printf("Error setting the verify locations.\n");
    exit(0);
  }

  if (SSL_ctx_load_and_set_client_CA_file(ctx,CA_FILE) <1) {
    printf("Error setting CA list.\n");
    exit(0);
  }

  /*Create new ssl object*/
  myssl=SSL_new(ctx);

  if(!myssl) {
    printf("Error creating SSL structure.\n");
    exit(0);
  }

  /* Bind the ssl object with the socket*/
  SSL_set_fd(myssl,connection_socket);

  /*Do the SSL Handshake*/
  err=SSL_accept(myssl);

  /* Check for error in handshake*/
  if (err<1) {
    err=SSL_get_error(myssl,err);
    printf("SSL error #%d in SSL_accept,program terminated\n",err);
    if(err==5){printf("sockerrno is:%d\n",5);}
      close(connection_socket);
      SSL_CTX_free(ctx);
      exit(0);
  }

  /* Check for Client authentication error */
  if (SSL_get_verify_result(myssl) != X509_V_OK) {
      printf("SSL Client Authentication error\n");
      SSL_free(myssl);
      close(connection_socket);
      SSL_CTX_free(ctx);
      exit(0);
  }

  /*Print out connection details*/
  printf("SSL connection on socket %x,Version: %s, Cipher: %s\n",
  connection_socket,
  SSL_get_version(myssl),
  SSL_get_cipher(myssl));

  /*Read message from the client.*/
  err = SSL_read (myssl, buff, sizeof(buff));

  /*Check for error in read.*/
  if(err<1) {
    err=SSL_get_error(myssl,err);
    printf("Error #%d in read,program terminated\n",err);

    /********************************/
    /* If err=6 it means the client */
    /* issued an SSL_shutdown. You  */
    /* must respond with a shutdown */
    /* to complete a graceful       */
    /* shutdown                     */
    /********************************/

    if(err==6)
      SSL_shutdown(myssl);

    SSL_free(myssl);
    close(connection_socket);
    SSL_CTX_free(ctx);
    exit(0);
  }
  printf("Client said: %s\n",buff);

  /*Send response to client.*/
  err=SSL_write(myssl,"I Hear You",sizeof("I Hear You")+1);

  /*Check for error in write.*/
  if(err<1) {
    err=SSL_get_error(myssl,err);
    printf("Error #%d in write,program terminated\n",err);

    /********************************/
    /* If err=6 it means the client */
    /* issued an SSL_shutdown. You  */
    /* must respond with a shutdown */
    /* to complete a graceful       */
    /* shutdown                     */
    /********************************/

    if(err==6)
      SSL_shutdown(myssl);

    SSL_free(myssl);
    close(connection_socket);
    SSL_CTX_free(ctx);
    exit(0);
  }

  err=SSL_shutdown(myssl);
  count = 1;

  /***********************************/
  /* Try SSL_shutdown() 5 times to   */
  /* wait for the remote application */
  /* to issue SSL_shutdown().        */
  /***********************************/

  while(err != 1) {
    err=SSL_shutdown(myssl);
    if(err != 1)
      count++;
    if (count == 5)
      break;
    sleep(1);
  }

  if(err<0)
    printf("Error in shutdown\n");
  else if(err==1)
    printf("Client exited gracefully\n");

  SSL_free(myssl);
  close(connection_socket);
  SSL_CTX_free(ctx);
  exit(0);
}
