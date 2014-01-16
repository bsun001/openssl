#include "common.h"

void handle_error(const char *file, int lineno, const char *msg)
{
    fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

void init_OpenSSL(void)
{
    if (!THREAD_setup() || !SSL_library_init())
    {
        fprintf(stderr, "** OpenSSL initialization failed!\n");
        exit(-1);
    }
    SSL_load_error_strings();
}

#if defined(WIN32)
    #define MUTEX_TYPE HANDLE
    #define MUTEX_SETUP(x) (x) = CreateMutex(NULL, FALSE, NULL)
    #define MUTEX_CLEANUP(x) CloseHandle(x)
    #define MUTEX_LOCK(x) WaitForSingleObject((x), INFINITE)
    #define MUTEX_UNLOCK(x) ReleaseMutex(x)
    #define THREAD_ID GetCurrentThreadId( )
#elif defined (_POSIX_THREADS)
    /* _POSIX_THREADS is normally defined in unistd.h if pthreads are available
       on your platform. */
    #define MUTEX_TYPE pthread_mutex_t
    #define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
    #define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
    #define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
    #define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
    #define THREAD_ID pthread_self( )
#else
    #error You must define mutex operations appropriate for your platform!
#endif

/* This array will store all of the mutexes available to OpenSSL. */
static MUTEX_TYPE *mutex_buf = NULL ;

static void locking_function(int mode, int n, const char * file, int line)
{
  if (mode & CRYPTO_LOCK)
    MUTEX_LOCK(mutex_buf[n]);
  else
    MUTEX_UNLOCK(mutex_buf[n]);
}

static unsigned long id_function(void)
{
  return ((unsigned long)THREAD_ID);
}

int THREAD_setup(void)
{
  int i;
  mutex_buf = (MUTEX_TYPE *) malloc(CRYPTO_num_locks( ) * sizeof(MUTEX_TYPE));
  if(!mutex_buf)
    return 0;
  for (i = 0; i < CRYPTO_num_locks( ); i++)
    MUTEX_SETUP(mutex_buf[i]);
  CRYPTO_set_id_callback(id_function);
  CRYPTO_set_locking_callback(locking_function);
  return 1;
}

int THREAD_cleanup(void)
{
  int i;
  if (!mutex_buf)
    return 0;
  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (i = 0; i < CRYPTO_num_locks( ); i++)
    MUTEX_CLEANUP(mutex_buf[i]);
  free(mutex_buf);
  mutex_buf = NULL;
  return 1;
}

int seed_prng(int bytes)
{
  if (!RAND_load_file("./random.pem", bytes))
    return 0;
  return 1;
}


int verify_callback(int ok, X509_STORE_CTX *store)
{
    char data[256];
 
    if (!ok)
    {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int  depth = X509_STORE_CTX_get_error_depth(store);
        int  err = X509_STORE_CTX_get_error(store);
 
        fprintf(stderr, "-Error with certificate at depth: %i\n", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        fprintf(stderr, "  issuer   = %s\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        fprintf(stderr, "  subject  = %s\n", data);
        fprintf(stderr, "  err %i:%s\n", err, X509_verify_cert_error_string(err));
    }
 
    return ok;
}


long post_connection_check(SSL *ssl, char *host)
{
    X509      *cert;
    X509_NAME *subj;
    char      data[256];
    int       extcount;
    int       ok = 0;
 
    /* Checking the return from SSL_get_peer_certificate here is not strictly
     * necessary.  With our example programs, it is not possible for it to return
     * NULL.  However, it is good form to check the return since it can return NULL
     * if the examples are modified to enable anonymous ciphers or for the server
     * to not require a client certificate.
     */
    if (!(cert = SSL_get_peer_certificate(ssl)) || !host)
        goto err_occured;
    if ((extcount = X509_get_ext_count(cert)) > 0)
    {
        int i;
 
        for (i = 0;  i < extcount;  i++)
        {
            char              *extstr;
            X509_EXTENSION    *ext;
 
            ext = X509_get_ext(cert, i);
            extstr = (char *) OBJ_nid2sn(OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
 
            if (!strcmp(extstr, "subjectAltName"))
            {
                int                  j;
                unsigned char        *data;
                STACK_OF(CONF_VALUE) *val;
                CONF_VALUE           *nval;
                X509V3_EXT_METHOD    *meth;
 
                if (!(meth = (X509V3_EXT_METHOD*)X509V3_EXT_get(ext)))
                    break;
                data = ext->value->data;
 
                val = meth->i2v(meth, 
                                meth->d2i(NULL, (const unsigned char **)(&data), ext->value->length),
                                NULL);
                for (j = 0;  j < sk_CONF_VALUE_num(val);  j++)
                {
                    nval = sk_CONF_VALUE_value(val, j);
                    if (!strcmp(nval->name, "DNS") && !strcmp(nval->value, host))
                    {
                        ok = 1;
                        break;
                    }
                }
            }
            if (ok)
                break;
        }
    }
 
    if (!ok && (subj = X509_get_subject_name(cert)) &&
        X509_NAME_get_text_by_NID(subj, NID_commonName, data, 256) > 0)
    {
        data[255] = 0;
        if (strcasecmp(data, host) != 0)
            goto err_occured;
    }
 
    X509_free(cert);
    return SSL_get_verify_result(ssl);
 
err_occured:
    if (cert)
        X509_free(cert);
    return X509_V_ERR_APPLICATION_VERIFICATION;
}


unsigned char *
read_file (FILE * f, int *len)
{
  unsigned char *buf = NULL, *last = NULL;
  unsigned char inbuf[READSIZE];
  int tot, n;

  tot = 0;
  for (;;)
    {
      n = fread (inbuf, sizeof (unsigned char), READSIZE, f);
      if (n > 0)
        {
          last = buf;
          buf = (unsigned char *) malloc (tot + n);
          memcpy (buf, last, tot);
          memcpy (&buf[tot], inbuf, n);
          if (last)
            free (last);
          tot += n;
          if (feof (f) > 0)
            {
              *len = tot;
              return buf;
            }
        }
      else
        {
          if (buf)
            free (buf);
          break;
        }
    }
  return NULL;
}

void
print_hex (unsigned char *bs, unsigned int n)
{
  int i;

  for (i = 0; i < n; i++)
    printf ("%02x", bs[i]);
}

/* Return 0 if equal, -1 if unequal */
int
binary_cmp (unsigned char *s1, unsigned int len1,
            unsigned char *s2, unsigned int len2)
{
  int i, c, x;

  if (len1 != len2)
    return -1;

  c = len1 / sizeof (x);
  for (i = 0; i < c; i++)
    {
      if (*(unsigned long *) (s1 + (i * sizeof (x))) !=
          *(unsigned long *) (s2 + (i * sizeof (x))))
        {
          return -1;
        }
    }
  for (i = c * sizeof (x); i < len1; i++)
    {
      if (s1[i] != s2[i])
        return -1;
    }

  return 0;
}


void set_nonblocking(SSL * ssl)
{
  int fd, flags;

  /* SSL_get_rfd returns -1 on error */
  if( (fd = SSL_get_rfd(ssl)) )
  {
    flags = fcntl(fd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
  }
    
  /* SSL_get_wfd returns -1 on error */
  if( (fd = SSL_get_wfd(ssl)) )
  {
    flags = fcntl(fd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
  }
}

void set_blocking(SSL * ssl)
{
  int fd, flags;      

  /* SSL_get_rfd returns -1 on error */
  if( (fd = SSL_get_rfd(ssl)) )       
  { 
    flags = fcntl(fd, F_GETFL);
    flags &= ~O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
  } 

  /* SSL_get_wfd returns -1 on error */  
  if( (fd = SSL_get_wfd(ssl)) )      
  {
    flags = fcntl(fd, F_GETFL);
    flags &= ~O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
  }
}

void check_availability(SSL *a, unsigned int *read_a, unsigned int *write_a,
                        SSL *b, unsigned int *read_b, unsigned int *write_b)
{
  int a_rfd, a_wfd, b_rfd, b_wfd;
  fd_set read_fds, write_fds;

  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);

  if( (a_rfd = SSL_get_rfd(a)) )
    FD_SET(a_rfd, &read_fds);
  if( (a_wfd = SSL_get_wfd(a)) )
    FD_SET(a_wfd, &write_fds);
  
  if( (b_rfd = SSL_get_rfd(b)) )
    FD_SET(b_rfd, &read_fds);
  if( (b_wfd = SSL_get_wfd(b)) )
    FD_SET(b_wfd, &write_fds);
  
  select(2, &read_fds, &write_fds, 0, 0);

  if(a_rfd && FD_ISSET(a_rfd, &read_fds))
    *read_a = 1;
  else
    *read_a = 0;
 
  if(a_wfd && FD_ISSET(a_wfd, &write_fds))
    *write_a = 1;
  else
    *write_a = 0;
  
  if(b_rfd && FD_ISSET(b_rfd, &read_fds))
    *read_b = 1;
  else
    *read_b = 0;
 
  if(b_wfd && FD_ISSET(b_wfd, &write_fds))
    *write_b = 1;
  else
    *write_b = 0;
}

