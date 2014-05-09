/*
 * cmain -- wrapper to construct cruft and call EST client module
 *
 * Copyright (c) Dan Harkins, 2014
 *
 *  Copyright holder grants permission for redistribution and use in source 
 *  and binary forms, with or without modification, provided that the 
 *  following conditions are met:
 *     1. Redistribution of source code must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in all source files.
 *     2. Redistribution in binary form must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *
 *  This permission does not include a grant of any permissions, rights,
 *  or licenses by any employers or corporate entities affiliated with
 *  the copyright holder.
 *
 *  "DISCLAIMER OF LIABILITY
 *  
 *  THIS SOFTWARE IS PROVIDED BY DAN HARKINS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INDUSTRIAL LOUNGE BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE."
 *
 * This license and distribution terms cannot be changed. In other words,
 * this code cannot simply be copied and put under a different distribution
 * license (including the GNU public license).
 */
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "cest.h"

/*
 * Add the response from /cacerts to the TADB.
 * This is called when we are unable to authenticate the server
 * because the signer of its certificate is not trusted.
 * Query the user and only add it if user approves.
 */
void
add_certs_to_tadb(char *tadb)
{
    char buf[256], answer[10], taentry[80], strhash[20], *p;
    unsigned char fingerp[SHA256_DIGEST_LENGTH], pem[PEM_BUFSIZE];
    unsigned long subjhash;
    long lpem;
    X509 *x509 = NULL;
    DIR *cadird, *tadird;
    struct dirent *cadire, *tadire;
    BIO *bio = NULL;
    int num, i;

    if ((cadird = opendir(".")) == NULL) {
        fprintf(stderr, "cannot add new certificates to TADB\n");
        return;
    }
    while ((cadire = readdir(cadird)) != NULL) {
        /*
         * search through the directory where /cacerts is stored (".")
         * for files name cacert.0..n
         */
#ifdef __linux__
        /*
         * linux just _has_ to make stupid and gratuitous changes
         * to things doesn't it?
         */
        if ((cadire->d_reclen > strlen("cacerts")) &&
#else
        if ((cadire->d_namlen > strlen("cacerts")) &&
#endif
            (strncmp(cadire->d_name, "cacerts", strlen("cacerts")) == 0)) {
            if ((bio = BIO_new_file(cadire->d_name, "r+")) == NULL) {
                fprintf(stderr, "unable to read certificate in %s\n", cadire->d_name);
                continue;
            }
            /*
             * read in the PEM-encoded cert and get a SHA256 fingerprint
             */
            lpem = BIO_read(bio, pem, PEM_BUFSIZE);
            SHA256(pem, lpem, fingerp);
            (void)BIO_reset(bio);

            x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
            BIO_free(bio);
            if (x509 == NULL) {
                continue;
            }
            /*
             * extract a certificate and see if this should be added
             */
            X509_NAME_oneline(X509_get_subject_name(x509), buf, sizeof(buf));
            printf("\nUntrusted certificate:\n");
            printf("certificate subject name: %s\n", buf);
            X509_NAME_oneline(X509_get_issuer_name(x509), buf, sizeof(buf));
            printf("issued by: %s\nfingerprint: ", buf);
            for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                printf("%02x", fingerp[i]);
                if (i == 15) {  /* make an attempt to pretty-print the fingerprint */
                    printf("\n             ");
                } else {
                    printf("%c", (i+1) == SHA256_DIGEST_LENGTH ? '\n' : ':');
                }
            }
            printf("add to %s? <y/n>: ", tadb); fflush(stdout);
            (void)scanf("%s", answer);
            if (answer[0] != 'y') {
                X509_free(x509);
                continue;
            }
            /*
             * if so then see if there are similar hash identifiers 
             * in the TADB
             */
            subjhash = X509_subject_name_hash(x509);
            sprintf(strhash, "%08lx", subjhash);
            if ((tadird = opendir(tadb)) == NULL) {
                fprintf(stderr, "unable to open TADB directory at %s\n", tadb);
                X509_free(x509);
                break;
            }
            /*
             * go through all the entries in the TADB looking for a match
             */
            num = 0;
            while ((tadire = readdir(tadird)) != NULL) {
                memset(taentry, 0, sizeof(taentry));
#ifdef __linux__
                /*
                 * linux just _has_ to make stupid and gratuitous changes
                 * to things doesn't it?
                 */
                if ((tadire->d_reclen <= strlen(strhash)) ||
#else
                if ((tadire->d_namlen <= strlen(strhash)) ||
#endif
                    strncmp(tadire->d_name, strhash, strlen(strhash))) {
                    continue;
                }
                /*
                 * found one! Increment the suffix.
                 */
                p = strstr(tadire->d_name, ".");
                p++;
                num = atoi(p);
                num++;
            }
            sprintf(taentry, "%s/%s.%d", tadb, strhash, num);
            if ((bio = BIO_new_file(taentry, "w+")) != NULL) {
                PEM_write_bio_X509(bio, x509);
                BIO_free(bio);
            }
            (void)closedir(tadird);
            X509_free(x509);
        }
    }
    (void)closedir(cadird);
    return;
}

int 
main (int argc, char **argv)
{
    struct est_client client;
    int res, c, good = 0;

    memset(&client, 0, sizeof(struct est_client));
    strcpy(client.cafile, "notspec");         /* not specified */
    strcpy(client.capath, "notspec");
    client.port = 8443;
    client.verify_peer = 1;
    for (;;) {
        c = getopt(argc, argv, "ric:f:ou:h:l:kp:tsqvx:y:");
        if (c < 0) {
            break;
        }
        switch (c) {
            case 'i':
                client.verify_peer = 0;
                break;
            case 'c':
                snprintf(client.capath, sizeof(client.capath), "%s", optarg);
                break;
            case 'f':
                snprintf(client.cafile, sizeof(client.cafile), "%s", optarg);
                break;
            case 'k':
                client.svrkeygen = 1;
                break;
            case 'u':
                snprintf(client.username, sizeof(client.username), "%s", optarg);
                good |= 0x01;
                break;
            case 'h':
                snprintf(client.hostname, sizeof(client.hostname), "%s", optarg);
                good |= 0x02;
                break;
            case 'l':
                snprintf(client.arbitrary_label, sizeof(client.arbitrary_label), "/%s", optarg);
                break;
            case 'p':
                client.port = atoi(optarg);
                break;
#ifdef OPENSSL_HAS_TLS_PWD
            case 'r':   /* use TLS-pwd */
                client.tls_mask |= USE_TLS_PWD;
                break;
#endif  /* OPENSSL_HAS_TLS_PWD */
            case 't':
                client.tls_mask |= USE_TLSv1;
                break;
            case 'v':
                client.how_chatty |= SORT_OF_CHATTY;
                break;
            case 's':
                client.how_chatty |= REAL_CHATTY;
                break;
            case 'q':
                goto helpme;
                break;
            case 'x':
                snprintf(client.mykey, sizeof(client.mykey), "%s", optarg);
                client.key_cert |= CLIENT_KEY;
                break;
            case 'y':
                snprintf(client.mycert, sizeof(client.mycert), "%s", optarg);
                client.key_cert |= CLIENT_CERT;
                break;
            default:
                good = 0;
                break;
        }
    }
    
    if ((good != 0x03) ||
        (client.key_cert && (client.key_cert != (CLIENT_KEY|CLIENT_CERT)))) {
helpme:
#ifdef OPENSSL_HAS_TLS_PWD
        fprintf(stderr, "USAGE: %s -u username -h hostname [-p <port>] [-x <key.pem>] [-y <cert.pem>] [-c <capath>] [-f <cafile>] [-i] [-r] [-s] [-v] [-t] [-k]\n", 
                argv[0]);
        fprintf(stderr, "\t-i: do not verify the server's certificate\n"
                        "\t-r: use TLS-pwd for authentication\n"
#ifndef OPENSSL_VERSION_TLSV1
                        "\t-t: use TLSv1 (default TLS_v1_2)\n"
#endif  /* OPENSSL_VERSION_TLSV1 */
                        "\t-k: let the server generate the key\n"
                        "\t-v: be kind of chatty\n"
                        "\t-s: scream real loud!, be more chatty\n");
#else
        fprintf(stderr, "USAGE: %s -u username -h hostname [-p <port>] [-x <key.pem>] [-y <cert.pem>] [-c <capath>] [-f <cafile>] [-i] [-s] [-v] [-t] [-k]\n", 
                argv[0]);
        fprintf(stderr, "\t-i: do not verify the server's certificate\n"
#ifndef OPENSSL_VERSION_TLSV1
                        "\t-t: use TLSv1 (default TLS_v1_2)\n"
#endif  /* OPENSSL_VERSION_TLSV1 */
                        "\t-k: let the server generate the key\n"
                        "\t-v: be kind of chatty\n"
                        "\t-s: scream real loud!, be more chatty\n");
#endif  /* OPENSSL_HAS_TLS_PWD */
        exit(1);
    }
#ifdef OPENSSL_VERSION_TLSV1
    fprintf(stderr, "%s: EST requires TLSv1.2, this version is technically noncompliant\n", argv[0]);
#endif  /* OPENSSL_VERSION_TLSV1 */

    /*
     * fill in some random cruft, need to plumb the real info from
     * your device here
     */
    snprintf(client.macaddr, sizeof(client.macaddr), 
             "00:01:02:03:04:05");                      client.options_mask |= MAC_MASK;
    snprintf(client.imei, sizeof(client.imei), 
             "359721000000016");                        client.options_mask |= IMEI_MASK;
    snprintf(client.devid, sizeof(client.devid), 
             "none of your business");                  client.options_mask |= DEVID_MASK;
    snprintf(client.drink, sizeof(client.drink),
             "le vrai pastis de Marseille");            client.options_mask |= DRINK_MASK;
    srand(time(NULL));
    client.serialnum = rand() % 1000;                   client.options_mask |= SERIAL_MASK;

    if (!client.key_cert) {
        printf("password (for %s auth): ", (client.tls_mask & USE_TLS_PWD) ? "tls-pwd" : "basic or digest"); 
        fflush(stdout);
        (void)scanf("%s", client.password);
    }
    
    res = do_cest(&client);
    switch (res) {
        case EST_SUCCESS:
            printf("successfully enrolled with EST :-)\n");
            break;
        case EST_ADD_TADB:
            if (strcmp(client.capath, "notspec")) {
                add_certs_to_tadb(client.capath);
            } else {
                fprintf(stderr, "%s: To add CA cert(s) to TADB, rerun with the -c option\n",
                        argv[0]);
                fprintf(stderr, "\te.g.: ");
                for (c = 0; c < argc; c++) {
                    fprintf(stderr, "%s ", argv[c]);
                }
                fprintf(stderr, "-c <tadb>\n");
            }
            break;
        case EST_FAILURE:
            printf("unsuccessful enrollment with EST :-(\n");
            break;
    }

    exit(0);
}

