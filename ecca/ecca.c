/*
 * ecca - stand-alone CA serving up ECC certificates for EST server
 *
 * Copyright (c) Dan Harkins, 2014, 2021
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
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "service.h"

service_context srvctx;
int unique = 0;

static void
sign_req (int fd, void *unused)
{
    char thefile[80], cmd_buf[300], p7[3000];
    int i, num, ret;
    unsigned char *data, *asn1;
    int32_t msglen;
    BIO *bio = NULL;
    FILE *fp;
    struct stat blah;
    X509_REQ *req = NULL;
    EVP_ENCODE_CTX *ctx;
    
    if (recv(fd, (char *)&msglen, sizeof(int32_t), MSG_WAITALL) < sizeof(int32_t)) {
        return;
    }
    msglen = ntohl(msglen);
    if (msglen > 3000) {
        return;
    }
    if ((data = (unsigned char *)malloc(msglen)) == NULL) {
        return;
    }
    if ((asn1 = (unsigned char *)malloc(msglen)) == NULL) {
        free(data);
        return;
    }
    if (recv(fd, (char *)data, msglen, MSG_WAITALL) < msglen) {
        free(data);
        return;
    }

    if ((ctx = EVP_ENCODE_CTX_new()) == NULL) {
        return;
    }
    EVP_DecodeInit(ctx);
    EVP_DecodeUpdate(ctx, asn1, &i, data, msglen);
    num = i;
    EVP_DecodeFinal(ctx, &(asn1[i]), &i);
    num += i;
    EVP_ENCODE_CTX_free(ctx);
    free(data);

    if ((bio = BIO_new_mem_buf(asn1, num)) == NULL) {
        free(asn1);
        goto no_cert;
    }
    if ((req = d2i_X509_REQ_bio(bio, NULL)) == NULL) {
        free(asn1);
        goto no_cert;
    }
    free(asn1);
    BIO_free(bio); bio = NULL;
    
    unique++;
    memset(thefile, 0, sizeof(thefile));
    snprintf(thefile, sizeof(thefile), "%dreq.pem", unique);
    if ((fp = fopen(thefile, "w+")) == NULL) {
        goto no_cert;
    }
    if ((bio = BIO_new(BIO_s_file())) == NULL) {
        fprintf(stderr, "unable to create bio for CSR\n");
        goto no_cert;
    }
    BIO_set_fp(bio, fp, BIO_NOCLOSE);
    PEM_write_bio_X509_REQ(bio, req);
    (void)BIO_flush(bio);
    BIO_free(bio); bio = NULL;
    fclose(fp);

    snprintf(cmd_buf, sizeof(cmd_buf),
             "openssl ca "
             "-policy policy_anything -batch -notext "
             "-config ./conf/openssl.cnf "
             "-out %dcert.pem -in %dreq.pem", unique, unique);
    ret = system(cmd_buf);
    if (ret < 0) {
        fprintf(stderr, "ecca: error calling %s\n", cmd_buf);
    }
    unlink(thefile);

    snprintf(thefile, sizeof(thefile), "%dcert.pem", unique);
    if ((stat(thefile, &blah) < 0) || (blah.st_size < 1)) {
        goto no_cert;
    }

    snprintf(cmd_buf, sizeof(cmd_buf),
             "openssl crl2pkcs7 "
             "-certfile %dcert.pem -outform DER -out %dder.p7 -nocrl", unique, unique);
    ret = system(cmd_buf);
    if (ret < 0) {
        fprintf(stderr, "ecca: error calling %s\n", cmd_buf);
    }
    unlink(thefile); 

    snprintf(thefile, sizeof(thefile), "%dder.p7", unique);
    if (stat(thefile, &blah) < 0) {
        goto no_cert;
    }
    i = blah.st_size;
    printf("DER-encoded P7 is %d bytes\n", i);
    if ((data = (unsigned char *)malloc(blah.st_size*2)) == NULL) {
        goto no_cert;
    }
    
    if ((fp = fopen(thefile, "r")) == NULL) {
        free(data);
        goto no_cert;
    }
    if (fread(p7, 1, sizeof(p7), fp) < blah.st_size) {
        free(data);
        goto no_cert;
    }
    fclose(fp);
    unlink(thefile);

    i = 0;
    if ((ctx = EVP_ENCODE_CTX_new()) == NULL) {
        return;
    }
    EVP_EncodeInit(ctx);
    EVP_EncodeUpdate(ctx, data, &i, (unsigned char *)p7, blah.st_size);
    num = i;
    EVP_EncodeFinal(ctx, (unsigned char *)&(data[i]), &i);
    num += i;
    EVP_ENCODE_CTX_free(ctx);
    printf("PEM-encoded P7 is %d bytes\n", num);
    msglen = num;
    msglen = htonl(msglen);
    send(fd, (char *)&msglen, sizeof(int32_t), 0);
    send(fd, (char *)data, num, 0);
    free(data);

no_cert:
    BIO_free(bio);
    srv_rem_input(srvctx, fd);
    close(fd);
    
    return;
}

static void
new_req (int fd, void *data)
{
    int sd;
    struct sockaddr_in *serv = (struct sockaddr_in *)data;
    uint32_t clen;
    
    clen = sizeof(struct sockaddr_in);
    if ((sd = accept(fd, (struct sockaddr *)serv, &clen)) < 0) {
        return;
    }
    srv_add_input(srvctx, sd, NULL, sign_req);
    return;
}

static void
exceptor (int fd, void *unused)
{
    srv_rem_input(srvctx, fd);
}

int
main (int argc, char **argv)
{
    struct sockaddr_in serv;
    int opt, lsd;
    
    memset(&serv, 0, sizeof(struct sockaddr_in));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = INADDR_ANY;
    serv.sin_port = htons(8888);

    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    
    if ((lsd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	fprintf(stderr, "%s: unable to create enrollment socket!\n", argv[0]);
	exit(1);
    }
    opt = 1;
    if (setsockopt(lsd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)) < 0) {
	fprintf(stderr, "%s: cannot set reuseaddr on socket!\n", argv[0]);
    }

    if ((bind(lsd, (struct sockaddr *)&serv, sizeof(serv)) < 0) ||
	(listen(lsd, 5) < 0)) {
	fprintf(stderr, "%s: unable to bind and listen on enrolling socket!\n", argv[0]);
	exit(1);
    }

    if ((srvctx = srv_create_context()) == NULL) {
        fprintf(stderr, "%s: can't create service context\n", argv[0]);
        exit(1);
    }
    
    srv_add_input(srvctx, lsd, &serv, new_req);
    srv_add_exceptor(srvctx, exceptor);
    srv_main_loop(srvctx);
    exit(0);
}
