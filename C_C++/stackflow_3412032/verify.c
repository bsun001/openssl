/*
    gcc -lssl -lcrypto -o verify verify.c
 */
#include <openssl/bio.h>                               /* openssl IO class */
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

static int verify(const char* certfile, const char* CAfile[], const int CAfilesize);
static X509 *load_cert(const char *file);
static int check(X509_STORE *ctx, const char *file);

int verify(const char* certfile, const char* CAfile[], const int CAfilesize)
{
    int ret = 0, i;
    X509_STORE *cert_ctx = NULL;                        /* X.509 certificate store, used for chain verification */
    X509_LOOKUP *lookup = NULL;                         /**/ 

    /* initialize X509 certificate store */
    cert_ctx = X509_STORE_new();
    if (cert_ctx == NULL) goto end;

    /* load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* prepare to load files */
    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
    if (lookup == NULL) {
        printf("X509_STORE_add_lookup(cert_ctx,X509_LOOKUP_file()) Failed\n");
        goto end;
    }

    /* load CA files into store */
    for (i = 0; i < CAfilesize; i++) {
        if(!X509_LOOKUP_load_file(lookup, CAfile[i], X509_FILETYPE_PEM)) {
            printf("X509_LOOKUP_load_file() Failed. CAfile: %s\n", CAfile[i]);
            goto end;
        }
    }

    /* prepare to load file directory */
    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
    if (lookup == NULL) {
        printf("X509_STORE_add_lookup(cert_ctx,X509_LOOKUP_hash_dir()) Failed\n");
        goto end;
    }

    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

    /* check certificate */
    ret = check(cert_ctx, certfile);
end:
    if (cert_ctx != NULL) X509_STORE_free(cert_ctx);

    return ret;
}

static X509 *load_cert(const char *file)
{
    X509 *x = NULL;
    BIO *cert;

    if ((cert = BIO_new(BIO_s_file())) == NULL) {
        printf("BIO_new(BIO_s_file()) Failed\n");
        goto end;
    }

    if (BIO_read_filename(cert, file) <= 0) {
        printf("BIO_read_filename(cert, file)  Failed\n");
        goto end;
    }

    x = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
end:
    if (cert != NULL) BIO_free(cert);
    return(x);
}

static int check(X509_STORE *ctx, const char *file)
{
    X509 *x = NULL;
    int i = 0,ret = 0;
    X509_STORE_CTX *csc;

    x = load_cert(file);
    if (x == NULL) {
        printf("load_cert(file) Failed\n");
        goto end;
    }

    /* X509 store context */
    csc = X509_STORE_CTX_new();
    if (csc == NULL) {
        printf("X509_STORE_CTX_new() Failed\n");
        goto end;
    }
    /* set X509 store flags */
    X509_STORE_set_flags(ctx, 0);
    if(!X509_STORE_CTX_init(csc, ctx, x, 0)) {
        printf("X509_STORE_set_flags(ctx, 0) Failed\n");
        goto end;
    }

    /* verify certificate */
    i=X509_verify_cert(csc);
    if (i == 0) {
        BIO* outbio = BIO_new(BIO_s_file());
        printf("Verification result text: %s\n", X509_verify_cert_error_string(csc->error));    /*  get the offending certificate causing the failure */
        X509* error_cert  = X509_STORE_CTX_get_current_cert(csc);
        X509_NAME* certsubject = X509_NAME_new();
        certsubject = X509_get_subject_name(error_cert);
        BIO_printf(outbio, "Verification failed cert:\n");
        X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
        BIO_printf(outbio, "\n");

        BIO_free_all(outbio);
    }
    printf("i = %d\n", i);
    X509_STORE_CTX_free(csc);

    ret=0;
end:
    ret = (i > 0);
    if (x != NULL)
        X509_free(x);

    return(ret);
}

int main (int argc, char* argv[]) {
    int i;

    if (argc < 3) {
        printf("argc = %d. Usage: ./verify CERTFILE CAFILE1 CAFILE2 ...\n", argc);
        exit(-1);
    }
    printf("cert file: %s\n", argv[1]);

//  const char ca_bundlestr[] = "ca-bundle.pem";
//  const char ca_bundlestr2[] = "ca-bundle2.pem";
//  const char cert_filestr[] = "cert-file.pem";
    const char** ca_bundlestr;
    const char* cert_filestr = argv[1];
    ca_bundlestr = (const char**)malloc((argc - 2) * sizeof(char*));
    for (i = 2; i < argc; i++) {
        ca_bundlestr[i - 2] = argv[i];
    }
    printf("Calling verify\n");
    int ret = verify(cert_filestr, ca_bundlestr, i - 2);
    if (ret > 0)
        printf("Verification successful\n");
    else
        printf("Verification failed\n");

    return 0;
}
