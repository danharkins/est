/*
 * cest - client side of EST
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
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <curl/curl.h>
#include "cest.h"

/*
 * an I/O buffer to talk to curl
 */
struct buffer {
    char *ptr;
    int left;
    int txrx;
};

/*
 * additional certificate attributes that might not be in your standard
 * OpenSSL distribution.
 */
static const unsigned char ma[] = { 0x2b, 0x06, 0x01, 0x01, 0x01, 0x01, 0x16 };
static const unsigned char im[] = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xbe, 0x68, 0x01, 0x01, 0x03 };
//static const unsigned char me[] = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xbe, 0x68, 0x01, 0x01, 0x04 };
static const unsigned char di[] = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xbe, 0x68, 0x01, 0x01, 0x05 };
static const unsigned char dr[] = { 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x05 };
static const unsigned char ra[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x1c };

#define KNOWN_OID_MAC_ADDR      0
#define KNOWN_OID_IMEI          1
#define KNOWN_OID_DEVID         2
#define KNOWN_OID_DRINK         3
#define KNOWN_OID_CMCRA         4
#define FIN_KNOWN_OID           5

/* unlikely that the 999x range will get used in openssl anytime soon */
#define imei_nid                9999
#define devid_nid               9998
#define cmcra_nid               9997
#define mac_nid                 9996

/*
 * I get so tired having to deal with objects that openssl just decides to make opaque!
 */
typedef struct asn1_object_st
{
    const char *sn,*ln;
    int nid;
    int length;
    const unsigned char *data; 
    int flags;
} ASN1OBJ;

ASN1_OBJECT *c2i_ASN1_OBJECT(ASN1_OBJECT **a, const unsigned char **pp,
                             long length);
int i2c_ASN1_BIT_STRING(ASN1_BIT_STRING *a, unsigned char **pp);
ASN1_BIT_STRING *c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,
                                     const unsigned char **pp, long length);
int i2c_ASN1_INTEGER(ASN1_INTEGER *a, unsigned char **pp);
ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **a, const unsigned char **pp,
                               long length);

/*
 * end of transparency efforts
 */


ASN1OBJ known_oids[FIN_KNOWN_OID] = {
    {      /* MAC address-- KNOWN_OID_MAC_ADDR */
        NULL, NULL, mac_nid, 7, ma, 0
    },
    {     /* WFA HS2.0 IMEI-- KNOWN_OID_IMEI */
        NULL, NULL, imei_nid, 11, im, 0
    },
    {     /* dev id-- KNOWN_OID_DEVID */
        NULL, NULL, devid_nid, 11, di, 0
    },
    {     /* drink-- KNOWN_OID_DRINK, included here for simplicity */
        NULL, NULL, NID_favouriteDrink, 10, dr, 0
    },
    {     /* RA-- KNOWN_OID_CMCRA */
        NULL, NULL, cmcra_nid, 8, ra, 0
    }
};

/*
 * a linked list of values extraced from an ASN.1 SET for a given attribute
 */
typedef struct setval_t {
    struct setval_t *next;
    enum {
        SETVAL_ERROR, SETVAL_NID, SETVAL_STR, SETVAL_INT,
        SETVAL_BOOL, SETVAL_OCTSTR, SETVAL_BITSTR
    } type;
    union {
        int nid;
        unsigned char *str;
        int integer;
        int boolean;
        unsigned char *octstr;
        unsigned char *bitstr;
    };
} setval;

/*
 * globals
 */
EVP_PKEY *key = NULL;
unsigned char *csrattrs;
int csrattrs_len = -1;
unsigned char tls_unique[24];
int tls_unique_len = 0;
struct buffer recv_buff, send_buff;
CURL *curl;
int idx = -1, be_chatty = 0;

static void
debug (const char *fmt, ...)
{
    va_list argptr;
    
    if (be_chatty) {
        va_start(argptr, fmt);
        vfprintf(stdout, fmt, argptr);
        va_end(argptr);
    }
}

/*
 * seek_cb()
 *   - callback to reset a stream that we've PUT. In this case it
 *     will be the send_buff.
 */
static int
seek_cb (void *instream, curl_off_t offset, int toseek)
{
    struct buffer *buff = (struct buffer *)instream;

    if (buff == NULL) {
        return -1;
    }
    switch (toseek) {
        case SEEK_SET:          /* rewind */
            buff->left = (buff->txrx - offset);
            buff->txrx = offset;
            debug("rewinding stream %d bytes back to %d\n", 
                  buff->left, buff->txrx);
            break;
        case SEEK_END:          /* EOF */
            buff->txrx += buff->left;
            debug("setting stream to EOF (%d) by adding %d bytes\n",
                  buff->txrx, buff->left);
            buff->left = 0;
            break;
        default:
        case SEEK_CUR:          /* do nothing */
            debug("seeking current location in stream");
            break;
    }
    return 0;   /* success! */
}

/*
 * read_cb()
 *   - callback to send data to server-- curl reads from us
 */
static size_t
read_cb (void *ptr, size_t size, size_t nmemb, void *foo)
{
    struct buffer *data = (struct buffer *)foo;
    char *src;
    int ret = 0;
    
    if (data == NULL) {
        return -1;
    }
    if (size != 1) {
        return 0;
    }
    if (data->left == 0) {
        return 0;
    }
    src = data->ptr + data->txrx;
    if (nmemb > data->left) {
        ret = data->left;
        memcpy(ptr, src, data->left);
        data->txrx += data->left;
        data->left = 0;
    } else {
        ret = nmemb;
        memcpy(ptr, src, nmemb);
        data->left -= nmemb;
        data->txrx += nmemb;
    }
    return ret;
}

/*
 * write_cb()
 *   - callback to obtain data from server-- curl writes to us
 */
static size_t
write_cb (void *ptr, size_t size, size_t nmemb, void *foo)
{
    struct buffer *data = (struct buffer *)foo;
    long n = size * nmemb;
    char *dst;

    if (data == NULL) {
        return -1;
    }
    if (n > data->left) {
        return 0;
    }

    dst = data->ptr + data->txrx;
    memcpy(dst, ptr, n);
    data->txrx += n;
    data->left -= n;
    return n;
}

/*
 * object_to_nid()
 *   - front end OpenSSL's OBJ_obj2nid() call. Check to see whether we're
 *     looking for our known OIDs (which will probably turn up NID_undef)
 *     first before trying obj2nid.
 */
static int
object_to_nid (ASN1_OBJECT *obj)
{
    int i, nid = NID_undef;

    if (obj == NULL) {
        return NID_undef;
    }
    for (i = 0; i < FIN_KNOWN_OID; i++) {
        if ((obj->length == known_oids[i].length) &&
            (memcmp(obj->data, known_oids[i].data, obj->length) == 0)) {
            nid = known_oids[i].nid;
            break;
        }
    }
    if (nid == NID_undef) {
        nid = OBJ_obj2nid(obj);
    }
    return nid;
}

/*
 * free_setval()
 *   - free up any memory allocated when parsing an attribute's SET
 */
void free_setval (setval *freeme)
{
    if (freeme == NULL) {
        return;
    }
    if (freeme->next != NULL) {
        free_setval(freeme->next);
    }
    if (freeme->type == SETVAL_STR) {
        free(freeme->str);
    }
    if (freeme->type == SETVAL_OCTSTR) {
        free(freeme->octstr);
    }
    if (freeme->type == SETVAL_BITSTR) {
        free(freeme->bitstr);
    }
    free(freeme);
    freeme = NULL;
    return;
}

/*
 * get_set()
 *   - parse an ASN.1 SET an extract all the values in it
 */
static setval*
get_set (unsigned char **p, int len)
{
    unsigned char *ptr, *op;
    unsigned char *tmp;
    int inf, tag, xclass, length, hl;
    long l;
    ASN1_OBJECT *ao = NULL;
    setval *ret = NULL, *next = NULL;
    ASN1_INTEGER *ai = NULL;
    ASN1_OCTET_STRING *os = NULL;
    ASN1_BIT_STRING *abit = NULL;

    ptr = *p;
    /*
     * this assumes we've already parsed past a V_ASN1_SET
     */
    length = len;
    while (length) {
        op = ptr;
        tmp = ptr;
        inf = ASN1_get_object((const unsigned char **)&tmp, &l, &tag, &xclass, length);
        if (inf & 0x80) {
            free_setval(ret);
            return NULL;
        }

        /*
         * it's a linked list of setvals...
         */
        if (ret == NULL) {
            if ((ret = (setval *)malloc(sizeof(setval))) == NULL) {
                return NULL;
            }
            ret->type = SETVAL_ERROR;
            ret->next = NULL;
            next = ret;
        } else {
            if ((next->next = (setval *)malloc(sizeof(setval))) == NULL) {
                free_setval(ret);
                return NULL;
            }
            next = next->next;
            next->type = SETVAL_ERROR;
            next->next = NULL;
        }
        /*
         * ...fill it in according to the tag
         */
        if (tag == V_ASN1_OBJECT) {
            d2i_ASN1_OBJECT(&ao, (const unsigned char **)&ptr, length);
            next->type = SETVAL_NID;
            next->nid = object_to_nid(ao);
            ASN1_OBJECT_free(ao);
            ao = NULL;
        } else if ((tag == V_ASN1_PRINTABLESTRING) ||
                   (tag == V_ASN1_T61STRING) ||
                   (tag == V_ASN1_IA5STRING) ||
                   (tag == V_ASN1_VISIBLESTRING) ||
                   (tag == V_ASN1_NUMERICSTRING) ||
                   (tag == V_ASN1_UTF8STRING) ||
                   (tag == V_ASN1_UTCTIME) ||
                   (tag == V_ASN1_GENERALIZEDTIME)) {
            next->type = SETVAL_STR;
            if ((next->str = (unsigned char *)malloc(length + 1)) == NULL) {
                free_setval(ret);
                return NULL;
            }
            memset(next->str, 0, length+1);
            memcpy(next->str, ptr, length);
            ptr += l;
        } else if (tag == V_ASN1_INTEGER) {
            d2i_ASN1_INTEGER(&ai, (const unsigned char **)&ptr, length);
            next->type = SETVAL_INT;
            next->integer = ASN1_INTEGER_get(ai);
            ASN1_INTEGER_free(ai);
            ai = NULL;
        } else if (tag == V_ASN1_OCTET_STRING) {
            os = d2i_ASN1_OCTET_STRING(NULL, (const unsigned char **)&op, length);
            if ((os != NULL) && (os->length > 0)) {
                next->type = SETVAL_OCTSTR;
                if ((next->octstr = (unsigned char *)malloc(os->length)) == NULL) {
                    free_setval(ret);
                    return NULL;
                }
                memset(next->octstr, 0, os->length);
                memcpy(next->octstr, os->data, os->length);
            }
            if (os != NULL) {
                ASN1_OCTET_STRING_free(os);
            }
            os = NULL;
//            ptr += l;
//        } else if (tag == V_ASN1_BOOLEAN) {
//            next->type = SETVAL_BOOL;
//            next->boolean = d2i_ASN1_BOOLEAN(NULL, (const unsigned char **)&ptr, l);
//            ptr += l;
        } else if (tag == V_ASN1_BIT_STRING) {
            d2i_ASN1_BIT_STRING(&abit, (const unsigned char **)&ptr, length);
            next->type = SETVAL_BITSTR;
            if ((next->bitstr = (unsigned char *)malloc(abit->length)) == NULL) {
                free_setval(ret);
                return NULL;
            }
            memset(next->bitstr, 0, abit->length);
            memcpy(next->bitstr, abit->data, abit->length);
            ASN1_BIT_STRING_free(abit);
            abit = NULL;
        }
        hl = (ptr - op);
        length -= hl;
    }
    if (ret->type == SETVAL_ERROR) {
        free_setval(ret);
        ret = NULL;
    }
    return ret;
}

/*
 * create_custom_extension: creates an X509v3 certificate extension 
 *      for the OIDs we know about.
 */
static X509_EXTENSION *
create_custom_extension (int oid, const unsigned char *str, int len)
{
    ASN1_IA5STRING *ia5 = NULL;
    ASN1_INTEGER *ai = NULL;
    ASN1_OCTET_STRING *octstr = NULL;
    unsigned char *der = NULL, *ptr;
    X509_EXTENSION *ex = NULL;
    int length;

    switch (oid) {
        case KNOWN_OID_MAC_ADDR:
        case KNOWN_OID_DEVID:
        case KNOWN_OID_DRINK:

            if ((ia5 = ASN1_STRING_type_new(V_ASN1_IA5STRING)) == NULL) {
                goto fin;
            }
            ASN1_STRING_set((ASN1_STRING *)ia5, 
                            (unsigned char *)str, len);
            if ((der = malloc(ia5->length + 2)) == NULL) {
                goto fin;
            }
            ptr = der;
            *ptr++ = ia5->type;
            *ptr++ = ia5->length;
            memcpy(ptr, ia5->data, ia5->length);
            length = ia5->length;
            break;
        case KNOWN_OID_IMEI:
            if ((ai = s2i_ASN1_INTEGER(NULL, (char *)str)) == NULL) {
                goto fin;
            }
            if ((der = malloc(ai->length + 2)) == NULL) {
                goto fin;
            }
            ptr = der;
            *ptr++ = ai->type;
            *ptr++ = ai->length;
            memcpy(ptr, ai->data, ai->length);
            length = ai->length;
            break;
        default:
            goto fin;
    }
    if ((octstr = ASN1_STRING_type_new(V_ASN1_OCTET_STRING)) == NULL) {
        goto fin;
    }
    octstr->data = der;
    octstr->length = length + 2;

    ex = X509_EXTENSION_create_by_OBJ(NULL,
                                      &known_oids[oid], 
                                      0, octstr);
fin:
    if (ia5 != NULL) {
        ASN1_STRING_free((ASN1_STRING *)ia5);
    }
    if (ai != NULL) {
        ASN1_INTEGER_free(ai);
    }
    if (der != NULL) {
        free(der);
    }
    return ex;
}

/*
 * generate_csr()
 *   - try and generate a CSR, place it in send_buff.ptr for 
 *     transmission to the server
 */
static int
generate_csr (struct est_client *client)
{
    int i, challp_len, pkey_id, tag, xclass, inf, asn1len, attrlen, length, hl;
    int nid, keylen = 2048, crypto_nid = NID_rsaEncryption;    /* default is 2048 bit RSA... */ 
    const EVP_MD *md = EVP_sha256();                           /* ...and sha256 */
    const unsigned char *tot, *op;
    unsigned char *challp, *p, *tp, *attrdata = NULL;
    char serialnum[10];
    BIO *bio = NULL, *b64 = NULL;
    ASN1_OBJECT *o = NULL;
    const EVP_PKEY_ASN1_METHOD *ameth;
    EVP_PKEY_CTX *pkeyctx = NULL;
    EVP_PKEY *tmp = NULL;
    EC_GROUP *group = NULL;
    EC_KEY *ec = NULL;
    X509_NAME *subj = NULL;
    X509_REQ *req = NULL;
    long len;
    EVP_ENCODE_CTX *ctx;
    setval *values = NULL, *value;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    STACK_OF(ASN1_OBJECT) *sk = NULL;
    X509_EXTENSION *ex = NULL;
    X509_ATTRIBUTE *attr = NULL;
    ASN1_INTEGER *aint = NULL;

    /*
     * famous last words: "it will never happen"
     */
    if (client == NULL) {
        return 0;
    }
    /*
     * if we haven't tried to get csrattrs, or we haven't been authenticated yet
     * then don't try to generate a CSR, there's no point at this time. This can
     * happen after we do a GET on /cacerts and before we do a GET on /csrattrs.
     */
    if ((csrattrs_len < 0) || (tls_unique_len == 0)) {
        return 0;
    }
    /*
     * start constructing the X509_REQ 
     */
    if (((req = X509_REQ_new()) == NULL) ||
        (!X509_REQ_set_version(req, 0L))) {
        debug("cannot create a CSR!\n");
        return -1;
    }
    subj = X509_REQ_get_subject_name(req);
    if (!X509_NAME_add_entry_by_txt(subj, "commonName", MBSTRING_ASC,
                                    (unsigned char *)client->username, -1, -1, 0)) {
        debug("cannot add common name %s\n", client->username);
        return -1;
    }

    /*
     * generate the challengePassword, add it to the CSR
     */
    if (((bio = BIO_new(BIO_s_mem())) == NULL) ||
        ((b64 = BIO_new((BIO_METHOD *)BIO_f_base64())) == NULL) ||
        ((bio = BIO_push(b64, bio)) == NULL)) {
        debug("can't create BIOs for encoding challenge password\n");
        return -1;
    }
    BIO_write(bio, tls_unique, tls_unique_len);
    (void)BIO_flush(bio);
    challp_len = BIO_get_mem_data(bio, &challp);
    challp_len--;   /* get rid of terminating character */
    if (be_chatty & REAL_CHATTY) {
        debug("tls_unique (hex): \n");
        for (i = 0; i < tls_unique_len; i++) {
            debug("%x", tls_unique[i]);
        }
        debug("\n");
        debug("tls_unique (base64 encoded): \n");
        for (i = 0; i < challp_len; i++) {
            debug("%c", challp[i]);
        }
        debug("\n");
    }
    X509_REQ_add1_attr_by_NID(req, NID_pkcs9_challengePassword, 
                              MBSTRING_UTF8, challp, challp_len);
    BIO_free(bio);          /* this frees up the pushed bio too */
    bio = NULL;

    /*
     * if we have csrattrs, run through all the objects in the SEQUENCE OF
     * and add stuff to the X509_REQ
     */
    if (csrattrs_len) {
        if (be_chatty & REAL_CHATTY) {
            debug("csrattrs (hex): \n");
            for (i = 0; i < csrattrs_len; i++) {
                debug("%02x ", csrattrs[i]);
            }
            debug("\n");
        }
        p = (unsigned char *)csrattrs;
        tot = p + csrattrs_len;
        /*
         * csr attrs are a SEQUENCE of attributes or objects
         */ 
        inf = ASN1_get_object((const unsigned char **)&p, &len, &tag, &xclass, csrattrs_len);
        if (inf & 0x80) {
            debug("ASN.1 is not well-formed!\n");
            /*
             * messed up csrattrs is no reason to not generate a CSR
             */
            goto gen_csr;
        }
        if (tag != V_ASN1_SEQUENCE) {
            debug("csrattrs are not a SEQUENCE OF...!\n");
            /*
             * ditto, ibid, what he said
             */
            goto gen_csr;
        }
        length = len;

        while (p < tot) {
            op = p;
            tp = p;
            /*
             * go through the SEQUENCE looking for objects and attributes...
             * get a sneak peak using tp instead of p
             */
            inf = ASN1_get_object((const unsigned char **)&tp, &len, &tag, &xclass, length);
            if (inf & 0x80) {
                debug("bad asn.1\n");
                break;
            }
            hl = (tp - op);
            length -= hl;
            /*
             * a SEQUENCE here indicates an attribute (and object and a set)
             */
            if (tag == V_ASN1_SEQUENCE) {
                debug("got a SEQUENCE...\n");
                /*
                 * get the SEQUENCE...
                 */
                inf = ASN1_get_object((const unsigned char **)&p, &len, &tag, &xclass, length);
                if (inf & 0x80) {
                    debug("bad asn.1\n");
                    break;
                }
                /*
                 * ...and then the SET...
                 */
                d2i_ASN1_OBJECT(&o, (const unsigned char **)&p, length);
                nid = object_to_nid(o);
                ASN1_OBJECT_free(o);
                o = NULL;
                
                inf = ASN1_get_object((const unsigned char **)&p, &len, &tag, &xclass, length);
                if (inf & 0x80) {
                    debug("bad asn.1 for SET in attribute\n");
                    goto parse_fail;
                }
                if (!(inf & V_ASN1_CONSTRUCTED) || (tag != V_ASN1_SET)) {
                    debug("it's not an attribute! Should be a SET here\n");
                    goto parse_fail;
                }
                /*
                 * ...and all the values in the SET
                 */
                if ((values = get_set(&p, len)) == NULL) {
                    debug("couldn't get values from set!\n");
                    goto parse_fail;
                }
                p += len;
                debug("got an attribute...");
                switch (nid) {
                    /*
                     * depending on the attribute's object (the nid), parse through
                     * whatever was in the set looking for something that makes sense
                     * for this attribute. We'll ignore stuff in the set that doesn't
                     * make sense instead of rejecting the attribute.
                     */
                    case NID_rsaEncryption:
                        /*
                         * for RSA, look for a key length
                         */
                        for (value = values; value != NULL; value = value->next) {
                            if (value->type == SETVAL_INT) {
                                crypto_nid = nid;
                                keylen = value->integer;
                                debug(" RSA encryption, key length: %d\n", keylen);
                                break;
                            }
                        }
                        break;
                    case NID_X9_62_id_ecPublicKey:
                        /*
                         * for EC, look for a supported curve
                         */
                        for (value = values; value != NULL; value = value->next) {
                            if ((value->type == SETVAL_NID) &&
                                ((value->nid == NID_secp384r1)  ||
                                 (value->nid == NID_secp521r1) ||
#ifdef OPENSSL_HAS_BRAINPOOL
                                 (value->nid == NID_brainpoolp256r1) ||
                                 (value->nid == NID_brainpoolp384r1) ||
                                 (value->nid == NID_brainpoolp512r1) ||
#endif  /* OPENSSL_HAS_BRAINPOOL */
                                 (value->nid == NID_X9_62_prime256v1) ||
                                 (value->nid == NID_secp256k1))) {
                                crypto_nid = value->nid;
                                debug(" an elliptic curve, nid = %d\n", crypto_nid);
                                break;
                            }
                        }
                        break;
                    case NID_pseudonym:
                    case NID_friendlyName:
                    case NID_pkcs9_unstructuredName:
                        for (value = values; value != NULL; value = value->next) {
                            if (value->type == SETVAL_STR) {
                                X509_REQ_add1_attr_by_NID(req, nid, MBSTRING_UTF8, 
                                                          value->str, strlen((char *)value->str));
                                debug(" a string for %s: %s\n", 
                                        nid == NID_pseudonym ? "pseudonym" : 
                                        nid == NID_friendlyName ? "friendly name" : "unstructuredName", 
                                        value->str);
                                break;
                            }
                        }
                        break;
                    case NID_ext_req:
                        if (exts == NULL) {
                            if ((exts = sk_X509_EXTENSION_new_null()) == NULL) {
                                break;
                            }
                        }
                        debug(" an extension request:\n");
                        for (value = values; value != NULL; value = value->next) {
                            if (value->type == SETVAL_NID) {
                                switch (value->nid) {
                                    /*
                                     * 4U2DO:
                                     *    plumb relevant info (MAC address, IMEI, etc.) from your
                                     *    particular device here
                                     */
                                    case mac_nid:
                                        debug("\tfor mac address\n");
                                        if (client->options_mask & MAC_MASK) {
                                            if ((ex = create_custom_extension(KNOWN_OID_MAC_ADDR,
                                                                              (unsigned char *)client->macaddr,
                                                                              strlen(client->macaddr))) != NULL) {
                                                sk_X509_EXTENSION_push(exts, ex);
                                            }
                                        }
                                        break;
                                    case imei_nid: 
                                        debug("\tfor IMEI\n");
                                        if (client->options_mask & IMEI_MASK) {
                                            if ((ex = create_custom_extension(KNOWN_OID_IMEI,
                                                                              (unsigned char *)client->imei,
                                                                              strlen(client->imei))) != NULL) {
                                                sk_X509_EXTENSION_push(exts, ex);
                                            }
                                        }
                                        break;
                                    case devid_nid:
                                        debug("\tfor device ID\n");
                                        if (client->options_mask & DEVID_MASK) {
                                            if ((ex = create_custom_extension(KNOWN_OID_DEVID, 
                                                                              (unsigned char *)client->devid,
                                                                              strlen(client->devid))) != NULL) {
                                                sk_X509_EXTENSION_push(exts, ex);
                                            }
                                        }
                                        break;
                                    case NID_favouriteDrink:
                                        debug("\tfor favorite drink\n");
                                        if (client->options_mask & DRINK_MASK) {
                                            if ((ex = create_custom_extension(KNOWN_OID_DRINK,
                                                                              (unsigned char *)client->drink,
                                                                              strlen(client->drink))) != NULL) {
                                                sk_X509_EXTENSION_push(exts, ex);
                                            }
                                        }
                                        break;
                                }
                            }
                        }
                        break;
                    case NID_ext_key_usage:
                        debug(" an extended key usage request:\n");
                        if (exts == NULL) {
                            if ((exts = sk_X509_EXTENSION_new_null()) == NULL) {
                                break;
                            }
                        }
                        if ((sk = sk_ASN1_OBJECT_new_null()) == NULL) {
                            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
                            break;
                        }
                        /*
                         * go through the SET OF and see if there's anything
                         * we understand. If so, add it to the extensions
                         */
                        for (value = values; value != NULL; value = value->next) {
                            if (value->type == SETVAL_NID) {
                                switch (value->nid) {
                                    case NID_server_auth:
                                    case NID_client_auth:
                                    case NID_ipsecTunnel:
                                        if ((o = OBJ_nid2obj(value->nid)) != NULL) {
                                            sk_ASN1_OBJECT_push(sk, o);
                                        }
                                        break;
                                    case cmcra_nid:
                                        sk_ASN1_OBJECT_push(sk, &known_oids[KNOWN_OID_CMCRA]);
                                        break;
                                    default:
                                        break;
                                }
                            }
                        }
                        /*
                         * don't make these critical
                         */
                        if ((ex = X509V3_EXT_i2d(NID_ext_key_usage, 0, sk)) != NULL) {
                            sk_X509_EXTENSION_push(exts, ex);
                        }
                        break;
                    /*
                     * add cases here for more NIDs that we understand
                     */
                    default:
                        debug("unknown attribute...skipping\n");
                        goto parse_fail;
                }
                free_setval(values);
                values = NULL;
parse_fail:
                /*
                 * end of attribute...next!
                 */
                continue;
            }
            /*
             * not an attribute, it's just another object in the SEQUENCE
             *
             * Try to make the most sense out of these.
             */
            if (tag == V_ASN1_OBJECT) {
                debug("got an object!\n");
                d2i_ASN1_OBJECT(&o, (const unsigned char **)&p, length);
                nid = object_to_nid(o);
                ASN1_OBJECT_free(o);
                o = NULL;
                switch (nid) {
                    case mac_nid:
                        debug("a nid for mac-address\n");
                        if (client->options_mask & MAC_MASK) {
                            X509_REQ_add1_attr_by_NID(req, nid, MBSTRING_UTF8,
                                                      (unsigned char *)client->macaddr, -1);
                        }
                        break;
                    case imei_nid:
                        debug("a nid for IMEI\n");
                        if (client->options_mask & IMEI_MASK) {
                            if ((aint = s2i_ASN1_INTEGER(NULL, client->imei)) != NULL) {
                                attrlen = i2d_ASN1_INTEGER(aint, &attrdata);
                                if ((attr = X509_ATTRIBUTE_create_by_NID(NULL, nid, V_ASN1_OCTET_STRING,
                                                                         attrdata, attrlen)) != NULL) {
                                    X509_REQ_add1_attr(req, attr);
                                }
                                ASN1_INTEGER_free(aint);
                            }
                        }
                        break;
                    case NID_serialNumber:
                        /*
                         * the serial number is a printable string!
                         */
                        debug("a nid for serial number\n");
                        if (client->options_mask & SERIAL_MASK) {
                            snprintf(serialnum, sizeof(serialnum), "%d", client->serialnum);
                            if (!X509_NAME_add_entry_by_txt(subj, "serialNumber", MBSTRING_ASC,
                                                            (unsigned char *)serialnum, -1, -1, 0)) {
                                debug("can't add serial number :-(\n");
                            }
                        }
                        break;
                    case NID_pkcs9_challengePassword:   /* we always send this */
                        debug("a nid for challengePassword\n");
                        break;
                    case NID_sha256WithRSAEncryption:
                        crypto_nid = NID_rsaEncryption;
                        debug("a nid for sha256withRSAEncryption\n");
                        md = EVP_sha256();
                        break;
                    case NID_sha384WithRSAEncryption:
                        crypto_nid = NID_rsaEncryption;
                        debug("a nid for sha384withRSAEncryption\n");
                        md = EVP_sha384();
                        break;
                    case NID_sha512WithRSAEncryption:
                        crypto_nid = NID_rsaEncryption;
                        debug("a nid for sha512withRSAEncryption\n");
                        md = EVP_sha512();
                        break;
                    case NID_ecdsa_with_SHA256:
                        /*
                         * if we get a ecdsa_with_SHAXYZ then set the curve
                         * to be something appropriate for the hash if it
                         * hasn't been set already.
                         */
                        debug("a nid for ecdsa with sha256\n");
                        if (crypto_nid == NID_rsaEncryption) {
                            crypto_nid = NID_X9_62_prime256v1;
                        }
                        md = EVP_sha256();
                        break;
                    case NID_ecdsa_with_SHA384:
                        debug("a nid for ecdsa with sha384\n");
                        if (crypto_nid == NID_rsaEncryption) {
                            crypto_nid = NID_secp384r1;
                        }
                        md = EVP_sha384();
                        break;
                    case NID_ecdsa_with_SHA512:
                        debug("a nid for ecdsa with sha512\n");
                        if (crypto_nid == NID_rsaEncryption) {
                            crypto_nid = NID_secp521r1;
                        }
                        md = EVP_sha512();
                        break;
                    case NID_secp384r1:
                    case NID_secp521r1:
                    case NID_secp256k1:
                    case NID_X9_62_prime256v1:
                        debug("a nid for an elliptic curve\n");
                        crypto_nid = nid;
                        break;
                    case NID_sha256:
                        debug("a nid for sha256\n");
                        md = EVP_sha256();
                        break;
                    case NID_sha384:
                        debug("a nid for sha384\n");
                        md = EVP_sha384();
                        break;
                    case NID_sha512:
                        debug("a nid for sha512\n");
                        md = EVP_sha512();
                        break;
                }
            } else {
                debug("not a SEQUENCE OF objects and attributes\n");
                p += len;
            }
        }
    }
gen_csr:
    /*
     * if we got extensions above, add them to the REQ
     */
    if (exts != NULL) {
        X509_REQ_add_extensions(req, exts);
        if (sk != NULL) {
            sk_ASN1_OBJECT_pop_free(sk, ASN1_OBJECT_free);
        }
        /*
         * the following frees "exts" too
         */
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        exts = NULL;
    }

    /*
     * create a PKEY context for the particular crypto system 
     * our key will be in
     */
    if (crypto_nid == NID_rsaEncryption) {
        ameth = EVP_PKEY_asn1_find_str(NULL, "rsa", -1);
        EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL, ameth);
        pkeyctx = EVP_PKEY_CTX_new_id(pkey_id, NULL);
        if (EVP_PKEY_keygen_init(pkeyctx) < 1) {
            debug("can't initialize key generation for RSA\n");
            return -1;
        }
        EVP_PKEY_CTX_set_rsa_keygen_bits(pkeyctx, keylen);
    } else {
        /*
         * generate an EC keypair for the specified group
         */
        if ((group = EC_GROUP_new_by_curve_name(crypto_nid)) == NULL) {
            debug("unable to create curve group!\n");
            return -1;
        }
        EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
        EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_UNCOMPRESSED);
        if ((ec = EC_KEY_new()) == NULL) {
            debug("unable to create an EC_KEY!\n");
            return -1;
        }
        if (EC_KEY_set_group(ec, group) == 0) {
            debug("unable to set group to  PKEY!\n");
            return -1;
        }
        if (!EC_KEY_generate_key(ec)) {
            debug("unable to generate PKEY!\n");
            return -1;
        }
        /*
         * assign EC keypair to an EVP_PKEY and then use that to make
         * an EVP_PKEY_CTX
         */
        if ((tmp = EVP_PKEY_new()) == NULL) {
            debug("unable to create PKEY!\n");
            return -1;
        }
        EVP_PKEY_assign(tmp, EVP_PKEY_EC, ec);
        pkeyctx = EVP_PKEY_CTX_new(tmp, NULL);
        EVP_PKEY_free(tmp);
        EC_GROUP_free(group);
    }
    
    /*
     * we have an EVP_PKEY_CTX now for our desired public key type, generate!
     */
    if (EVP_PKEY_keygen_init(pkeyctx) < 1) {
        debug("unable to initiate keygen procedure!\n");
        goto csr_fail;
    }
    if (EVP_PKEY_keygen(pkeyctx, &key) < 1) {
        debug("unable to generate keypair!\n");
        goto csr_fail;
    }
    EVP_PKEY_CTX_free(pkeyctx); /* will free ec too, if used */
    if ((bio = BIO_new_file("mykey.pem", "w")) != NULL) {
        PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    } else {
        debug("can't save my key!\n");
    }
    BIO_free(bio);
    bio = NULL;
    /*
     * put the key in the request and sign the request
     */
    X509_REQ_set_pubkey(req, key);
    if (!X509_REQ_sign(req, key, md)) {
        debug("can't sign CSR!\n");
        goto csr_fail;
    }

    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        debug("unable to create another bio!\n");
        goto csr_fail;
    }

    /*
     * this routine can be called more than once depending on
     * server behavior that we cannot predict. So if we've been
     * through here before, clean up the remnants of our past
     * visit before we proceed
     */
    if (send_buff.left) {
        free(send_buff.ptr);
    }
    i2d_X509_REQ_bio(bio, req);
    asn1len = BIO_get_mem_data(bio, &p);

    if ((send_buff.ptr = malloc(2*asn1len)) == NULL) {
        goto csr_fail;
    }

    if ((ctx = EVP_ENCODE_CTX_new()) == NULL) {
        goto csr_fail;
    }
    /*
     * base64 encode the request
     */
    EVP_EncodeInit(ctx);
    EVP_EncodeUpdate(ctx, (unsigned char *)send_buff.ptr, &i, p, asn1len);
    send_buff.left = i;
    EVP_EncodeFinal(ctx, (unsigned char *)&(send_buff.ptr[i]), &i);
    send_buff.left += i;
    EVP_ENCODE_CTX_free(ctx);
        
    send_buff.txrx = 0;
    /*
     * we finally know how big this POST will be
     */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, send_buff.left);
    if (be_chatty & REAL_CHATTY) {
        debug("the CSR\n%s", send_buff.ptr, send_buff.left);
    }

csr_fail:
    X509_REQ_free(req);
    if (bio != NULL) {
        BIO_free(bio);
    }
    return 1;
}

/*
 * called as part of SSL handshake. When handshake is done, generate
 * tls-unique and try creating a CSR.
 *
 * Since the server can close the socket, this can actually end up
 * getting called multiple times. We create a CSR each time so that
 * the tls-unique we're proving possession of is the one for the
 * current TLS session.
 */
static void
ssl_info_callback (const SSL *ssl, int type, int val)
{
    struct est_client *client;
    SSL_CTX *sctx;
    
    if (type & SSL_CB_HANDSHAKE_DONE) {
        /*
         * Grab the TLS-unique for this SSL connection. RFC 5929 says
         * it's the "first" finished message which, for the client,
         * is her's...unless there's session resumption going on,
         * in which case it's the server's.
         */
        if (SSL_session_reused((SSL *)ssl)) {
            tls_unique_len = SSL_get_peer_finished(ssl, tls_unique, sizeof(tls_unique));
        } else {
            tls_unique_len = SSL_get_finished(ssl, tls_unique, sizeof(tls_unique));
        }
        /*
         * get the client structure out of the SSL_CTX and try to
         * generate a CSR with this new tls_unique value
         */
        sctx = SSL_get_SSL_CTX(ssl);
        if ((client = (struct est_client *)SSL_CTX_get_ex_data(sctx, idx)) != NULL) {
            if (generate_csr(client) < 1) {
                /*
                 * so we failed, hope to try again later-- not fatal!
                 */
                debug("unable to generate a CSR!\n");
            }
            
        }
    }
    return;
}

#ifdef OPENSSL_HAS_TLS_PWD
/*
 * the bowels of TLS-pwd will try to free whatever is
 * returned from this callback so malloc something
 */
static char *
get_client_pwd_callback (SSL *ssl, void *unused)
{
    struct est_client *client;
    char *pass;

    if ((client = (struct est_client *)SSL_CTX_get_ex_data(ssl->ctx, idx)) == NULL) {
        return NULL;
    }
    if ((pass = malloc(strlen(client->password))) == NULL) {
        return NULL;
    }
    strcpy(pass, client->password);
    
    return pass;
}
#endif  /* OPENSSL_HAS_TLS_PWD */

/*
 * curl calls this when an SSL_CTX has been created.
 * Set the info callback so we know when handshaking is done
 * and if we're doing tls-pwd set the SSL_CTX appropriately.
 */
static CURLcode ssl_ctx_callback (CURL *curl, void *sslctx, void *parm)
{
    SSL_CTX *ctx = (SSL_CTX *)sslctx;
    struct est_client *client = (struct est_client *)parm;

    /*
     * register a callback so we know when negotiation has finished
     * and store the client structure in the SSL_CTX for retrieval
     * when the connection is complete and we need to generate a CSR.
     */
    SSL_CTX_set_info_callback(ctx, ssl_info_callback);
    idx = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    SSL_CTX_set_ex_data(ctx, idx, client);
        
#ifdef OPENSSL_HAS_TLS_PWD
    if (client->tls_mask & USE_TLS_PWD) {
        /*
         * if we're doing TLS-pwd we need set set the acceptable cipher
         * and add a callback to get the user's password
         */
        SSL_CTX_set_pwd_username(ctx, client->username);
        SSL_CTX_set_pwd_password_callback(ctx, get_client_pwd_callback);
        if (client->tls_mask & USE_TLSv1) {
            SSL_CTX_set_cipher_list(ctx, "PWD-ECC-AES-128-CBC-SHA-PRIV");
        } else {
//            SSL_CTX_set_cipher_list(ctx, "PWD-ECC-AES-128-GCM-SHA256-PRIV,PWD-ECC-AES-256-GCM-SHA384-PRIV");
            SSL_CTX_set_cipher_list(ctx, "PWD-ECC-AES-128-GCM-SHA256-PRIV");
        }
        
    }
#endif  /* OPENSSL_HAS_TLS_PWD */
    return CURLE_OK;
}

static PKCS7 *
get_p7_from_resp (char *ptr, int len)
{
    int i, asn1len;
    PKCS7 *p7 = NULL;
    unsigned char *asn1;
    EVP_ENCODE_CTX *ctx;
    BIO *bio = NULL;

    if (ptr == NULL) {
        return NULL;
    }
    /*
     * decoded, it'll be less than len bytes long
     */
    if ((asn1 = (unsigned char *)malloc(len)) == NULL) {
        return NULL;
    }
    if ((ctx = EVP_ENCODE_CTX_new()) == NULL) {
        free(asn1);
        return NULL;
    }
    i = len;
    EVP_DecodeInit(ctx);
    (void)EVP_DecodeUpdate(ctx, asn1, &i, (unsigned char *)ptr, len);
    asn1len = i;
    (void)EVP_DecodeFinal(ctx, &(asn1[i]), &i);
    asn1len += i;
    EVP_ENCODE_CTX_free(ctx);
    /*
     * convert the DER-encoded blob into a PKCS7 structure
     */
    if ((bio = BIO_new_mem_buf(asn1, asn1len)) == NULL) {
        debug("can't convert DER into P7!\n");
        free(asn1);
        return NULL;
    }
    if ((p7 = d2i_PKCS7_bio(bio, NULL)) == NULL) {
        debug("can't read PKCS7 from server\n");
    }
    free(asn1);
    BIO_free(bio);
    return p7;
}

/*
 * get_certs_from_p7()
 *      - given a P7, return the certs in the bag
 */
static STACK_OF(X509) *
get_certs_from_p7(PKCS7 *p7)
{
    int nid;
    STACK_OF(X509) *certs = NULL;

    if (p7 == NULL) {
        return NULL;
    }
    nid = object_to_nid(p7->type);
    /*
     * location in the bag depends on the type of P7
     */
    switch (nid) {
        case NID_pkcs7_signed:
            certs = p7->d.sign->cert;
            break;
        case NID_pkcs7_signedAndEnveloped:
            certs = p7->d.signed_and_enveloped->cert;
            break;
        default:
            debug("unknown type of PKCS7 (nid = %d)\n", nid);
            certs = NULL;
            break;
    }
    return certs;
}

/*
 * certificate_verify_callback()
 *      - explain why a X509 verification failed, we don't overrule the
 *        result, just report the problem.
 */
static int
certificate_verify_callback (int pre_verify_ok, X509_STORE_CTX *ctx)
{
    X509 *x509;
    char buf[80];
    
    if (!pre_verify_ok) {
        if ((x509 = X509_STORE_CTX_get_current_cert(ctx)) == NULL) {
            debug("certificate store verify error %s\n",
                    X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
        } else {
            debug("error '%s' with certificate issued to ", 
                    X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
            X509_NAME_oneline(X509_get_subject_name(x509), buf, sizeof(buf));
            debug("%s, issued by ", buf);
            X509_NAME_oneline(X509_get_issuer_name(x509), buf, sizeof(buf));
            debug("%s\n", buf);
        }
    } else if (be_chatty & REAL_CHATTY) {
        if ((x509 = X509_STORE_CTX_get_current_cert(ctx)) != NULL) {
            debug("successful validation ('%s') of certificate issued to ", 
                    X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
            X509_NAME_oneline(X509_get_subject_name(x509), buf, sizeof(buf));
            debug("%s, issued by ", buf);
            X509_NAME_oneline(X509_get_issuer_name(x509), buf, sizeof(buf));
            debug("%s\n", buf);
        }
    }
    
    return pre_verify_ok;
}

/*
 * create_trusted_store()
 *   - extract the self-signed certificate from a PKCS#7 and
 *      instantiate a trusted certificate store.
 */
static X509_STORE *
create_trusted_store (char *ptr, int len)
{
    X509_STORE *store = NULL;
    PKCS7 *p7 = NULL;
    STACK_OF(X509) *certs = NULL;
    int i;
    
    /*
     * get a P7 out of the DER blob...
     */
    if ((p7 = get_p7_from_resp(ptr, len)) == NULL) {
        return NULL;
    }
    /*
     * ...and the certs out of the P7
     */
    certs = get_certs_from_p7(p7);

    if ((certs != NULL) && (store = X509_STORE_new()) != NULL) {
        for (i = 0; i < sk_X509_num(certs); i++) {
            /*
             * ...and when we find a self-signed cert, add it to the store
             * and stick ourselves into the process to report verification errors.
             */
            if (X509_check_issued(sk_X509_value(certs, i), 
                                  sk_X509_value(certs, i)) == X509_V_OK) {
                X509_STORE_add_cert(store, sk_X509_value(certs,i));
                X509_STORE_set_verify_cb(store, certificate_verify_callback);
                PKCS7_free(p7);
                return store;
            }
        }
        X509_STORE_free(store);
    }
    PKCS7_free(p7);
    return NULL;
}

/*
 * save_certs_from_p7()
 *   - validate and save certs in a PKCS#7
 */
static int
validate_and_save_certs (X509_STORE *store, char *str, char *ptr, int len)
{
    char fname[20];
    STACK_OF(X509) *certs = NULL;
    X509 *x509 = NULL;
    X509_STORE_CTX *ctx;
    BIO *bio = NULL;
    int i, ret = 1;
    PKCS7 *p7;

    /*
     * get a P7 out of the DER blob...
     */
    if ((p7 = get_p7_from_resp(ptr, len)) == NULL) {
        return -1;
    }
    /*
     * ...and the certs out of the P7
     */
    certs = get_certs_from_p7(p7);

    if ((certs != NULL) && ((ctx = X509_STORE_CTX_new()) != NULL)) {
        /*
         * go through all the certs...
         */
        for (i = 0; i < sk_X509_num(certs); i++) {
            if (!X509_STORE_CTX_init(ctx, store, NULL, certs)) {
                break;
            }
            /*
             * ...and if they can be verified, save them!
             */
            x509 = sk_X509_value(certs, i);
            X509_STORE_CTX_set_cert(ctx, x509);
            if (X509_verify_cert(ctx) > 0) {
                if (sk_X509_num(certs) == 1) {
                    snprintf(fname, sizeof(fname), "%s.pem", str);
                } else {
                    snprintf(fname, sizeof(fname), "%s%d.pem", str, i);
                }
                if ((bio = BIO_new_file(fname, "w+")) == NULL) {
                    debug("unable to save %s\n", fname);
                    break;
                }
                PEM_write_bio_X509(bio, x509);
                BIO_free(bio);
            } else {
                /*
                 * But! If there's a problem with any of them
                 * then return a failure
                 */
                ret = -1;
            }
        }
        X509_STORE_CTX_free(ctx);
    }
    PKCS7_free(p7);
    return ret;
}

static int
parse_multi_part (X509_STORE *store, char *parts, int totallen)
{
    char *delimiter, *p8start = NULL, *p8end = NULL, *p7start = NULL, *p7end = NULL, *line, *p;
    unsigned char *buf;
    int i, asn1len, curmime = 0;
    PKCS8_PRIV_KEY_INFO *p8info = NULL;
    BIO *bio = NULL;
    EVP_ENCODE_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    
    if ((parts == NULL) || (totallen < 1)) {
        return -1;
    }
    p = parts;
    while (1) {
        delimiter = strtok(p, "\n");
        p += (strlen(delimiter) + 1);
        if (p > (parts + totallen)) {
            return -1;
        }
        if ((delimiter[0] == '-') && (delimiter[1] == '-')) {
            break;
        }
    }
    while (1) {
        /*
         * have I mentioned lately how much I hate parsing strings in C?
         */
        if (*p == '\n') {
            p++;
            if (curmime == 1) {
                p8start = p;
            } else if (curmime == 2) {
                p7start = p;
            }
        }
        line = strtok(p, "\n");
        if (strstr(line, "pkcs8") != NULL) {
            curmime = 1;
        } else if (strstr(line, "pkcs7") != NULL) {
            curmime = 2;
        } else if (strncmp(line, delimiter, strlen(delimiter)-1) == 0) {
            if (curmime == 1) {
                p8end = p;
            } else if (curmime == 2) {
                p7end = p;
            }
            curmime = 0;
        }
        if (((p7end != NULL) && (p8end != NULL)) ||
            (p > (parts + totallen))) {
            break;
        }
        p += (strlen(line) + 1);
        line[strlen(line)] = '\n';
    }
    /*
     * decode asn1
     */
    if ((buf = (unsigned char *)malloc(p8end - p8start)) == NULL) {
        debug("unable to alloc space for p8\n");
        return -1;
    }
    if ((ctx = EVP_ENCODE_CTX_new()) == NULL) {
        debug("can't create encode context!\n");
        return -1;
    }
    EVP_DecodeInit(ctx);
    EVP_DecodeUpdate(ctx, buf, &i, (unsigned char *)p8start, (p8end - p8start));
    asn1len = i;
    EVP_DecodeFinal(ctx, &(buf[i]), &i);
    asn1len += i;
    EVP_ENCODE_CTX_free(ctx);
    
    /*
     * create a p8 out of asn1
     */
    if ((bio = BIO_new_mem_buf(buf, asn1len)) == NULL) {
        debug("can't create bio for p8\n");
        free(buf);
        return -1;
    }
    if ((p8info = d2i_PKCS8_PRIV_KEY_INFO_bio(bio, NULL)) == NULL) {
        debug("can't create p8 from ASN1\n");
        BIO_free(bio);
        free(buf);
        return -1;
    } 
    BIO_free(bio);
    free(buf);

    /*
     * extract the private key...
     */
    if ((pkey = EVP_PKCS82PKEY(p8info)) == NULL) {
        debug("can't extract private key from p8\n");
        return -1;
    }

    if ((bio = BIO_new_file("mykey.pem", "w")) == NULL) {
        debug("can't create bio to save private key\n");
        return -1;
    }
    /*
     * ...validate our certificate from the p7, if it's successful
     * then save our private key as well.
     */
    if (validate_and_save_certs(store, "mycert", p7start, (p7end - p7start)) > 0) {
        PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    }
    BIO_free(bio);

    return 1;
}

/*
 * open_socket() and close_socket()
 *   - Need to keep track of whether the socket is open or not because we have
 *     no control over whether the server closes the socket each time and how
 *     and when we generate the csr depends on knowing the state of the socket.
 */
static curl_socket_t 
open_socket (void *data, curlsocktype purpose, struct curl_sockaddr *addr)
{
    int *sopen = (int *)data;
    curl_socket_t s;

    s = socket(addr->family, addr->socktype, addr->protocol);
    if (s > 0) {
        *sopen = 1;
        debug("SOCKET IS OPEN!!!\n");
    }
    return s;
}

static int 
close_socket (void *data, curl_socket_t s)
{
    int *sopen = (int *)data;

    close(s);
    *sopen = 0;
    debug("SOCKET IS CLOSED!!!\n");
    return 1;
}

int 
do_cest (struct est_client *client)
{
    CURLcode res;
    struct curl_slist *slist = NULL;
    char cmd[250], resp[10000];
    int socket_open = 0, i;
    long rcode;
    X509_STORE *cert_store = NULL;
    EVP_ENCODE_CTX *ctx;
    int ret = EST_FAILURE;

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    be_chatty = client->how_chatty;
    if ((curl = curl_easy_init()) == 0) {
        debug("can't init curl\n");
        return ret;
    }

    /*
     * EST requires TLSv1.1 or later but interop shows that not everyone
     * does that, so allow for plain ol'TLSv1.
     */
#ifndef OPENSSL_VERSION_TLSV1
    if (client->tls_mask & USE_TLSv1) {
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
    } else {
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    }
#else
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
#endif
    /*
     * reuse the socket if at all possible but...
     */
    curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 0L);
    /*
     * ...keep track of whether the server closes the socket or 
     * not to minimize the number of CSRs we end up generating.
     */
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, open_socket);
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &socket_open);
    curl_easy_setopt(curl, CURLOPT_CLOSESOCKETFUNCTION, close_socket);
    curl_easy_setopt(curl, CURLOPT_CLOSESOCKETDATA, &socket_open);

    curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, client);
    if (curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, ssl_ctx_callback) != CURLE_OK) {
        debug("can't set ssl_ctx callback for curl\n");
        return ret;
    }

    /*
     * allow up to 2 redirects, maintain the request method, and follow
     * the RFCs (i.e. don't convert POST requests to GET requests-- default
     * behavior is not RFC-compliant!)
     */
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 2L);
    curl_easy_setopt(curl, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);
    
    /*
     * if we're doing username/password authentication then set them...
     */
    if (!client->key_cert) {
        /*
         * HTTP auth needs this, if we're doing TLS-pwd it's handled
         * via callback above when we have an SSL_CTX.
         */
        if ((client->tls_mask & USE_TLS_PWD) == 0) {
            curl_easy_setopt(curl, CURLOPT_USERNAME, client->username);
            curl_easy_setopt(curl, CURLOPT_PASSWORD, client->password);
            curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC|CURLAUTH_DIGEST);
        }
    } else {
        /*
         * otherwise, set up the key and cert for client authentication
         */
        debug("using %s as a client certificate\n", client->mycert);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, client->mykey);
        curl_easy_setopt(curl, CURLOPT_SSLCERT, client->mycert);

        curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);
        /*
         * let the presence of a cert and key override the potential
         * inclusion of "-r" on the command line-- i.e. don't try and 
         * do TLS-pwd if we have a key and cert to use
         */
        client->tls_mask &= ~USE_TLS_PWD;
    }

    /*
     * stupid curl wants to verify the server cert even when there isn't one--
     * i.e. when doing tls-pwd, so if we're doing tls-pwd don't verify peer.
     */
    if ((client->tls_mask & USE_TLS_PWD) || (client->verify_peer == 0)) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    } else {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        if (strcmp(client->cafile, "notspec")) {
            debug("using %s for CA\n", client->cafile);
            curl_easy_setopt(curl, CURLOPT_CAINFO, client->cafile);
        }
        if (strcmp(client->capath, "notspec")) {
            debug("using %s for TADB\n", client->capath);
            curl_easy_setopt(curl, CURLOPT_CAPATH, client->capath);
        }
    }

    /*
     * set up send/recv buffers
     */
    memset(resp, 0, sizeof(resp));
    recv_buff.ptr = resp;
    recv_buff.left = sizeof(resp);
    recv_buff.txrx = 0;

    send_buff.ptr = NULL;
    send_buff.left = 0;
    send_buff.txrx = 0;

    /*
     * first get the CA's cert
     */
    sprintf(cmd, "https://%s:%d/.well-known/est%s/cacerts", 
            client->hostname, client->port, client->arbitrary_label);
    curl_easy_setopt(curl, CURLOPT_URL, cmd);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &recv_buff);

    if (be_chatty) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }
    
    if ((res = curl_easy_perform(curl)) != CURLE_OK) {
        if (res == CURLE_SSL_CACERT) {
            debug("EST server cannot be authenticated.\n");
            if (strcmp(client->capath, "notspec")) {
                /*
                 * if a TADB was specified, see if it's acceptable to
                 * add the CA certificate
                 */
                curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                if (((res = curl_easy_perform(curl)) == CURLE_OK) &&
                    ((cert_store = create_trusted_store(recv_buff.ptr, recv_buff.txrx)) != NULL)) {
                    if (validate_and_save_certs(cert_store, "cacerts", recv_buff.ptr, recv_buff.txrx) > 0) {
                        ret = EST_ADD_TADB;
                    }
                } else {
                    ret = EST_FAILURE;
                }
            } else {
                ret = EST_ADD_TADB;
            }
        } else {
            ret = EST_FAILURE;
        }
        goto fin;
    }
    debug("Response from /cacerts:\n%s\n", resp);

    if ((cert_store = create_trusted_store(recv_buff.ptr, recv_buff.txrx)) == NULL) {
        debug("unable to create trusted certificate store from /cacerts!\n");
        goto fin;
    }
    
    if (validate_and_save_certs(cert_store, "cacerts", recv_buff.ptr, recv_buff.txrx) < 0) {
        debug("unable to verify response from /cacerts!\n");
        goto fin;
    }
    
    if (client->svrkeygen) {
        /*
         * we still have to generate a PKCS10, so imply that we
         * tried to get /csrattrs to allow the CSR to be generated
         */
        csrattrs_len = 0;
    } else {
        /*
         * next, get list of attributes that should be in our CSR
         */
        memset(resp, 0, sizeof(resp));
        recv_buff.ptr = resp;
        recv_buff.left = sizeof(resp);
        recv_buff.txrx = 0;

        sprintf(cmd, "https://%s:%d/.well-known/est%s/csrattrs", 
                client->hostname, client->port, client->arbitrary_label);
        curl_easy_setopt(curl, CURLOPT_URL, cmd);
        if ((res = curl_easy_perform(curl)) != CURLE_OK) {
            debug("can't perform /csrattrs command\n%s\n", curl_easy_strerror(res));
            goto fin;
        }
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &rcode);
        if (rcode != 200) {
            debug("server does not support /csrattrs :-(\n");
            csrattrs_len = 0;       /* indicate that we tried though */
        } else {
            debug("Response from /csrattrs:\n%s\n", resp);
            if ((csrattrs = (unsigned char *)malloc(strlen(resp))) == NULL) {
                csrattrs_len = 0;
            } else {
                i = strlen(resp);
                memset(csrattrs, 0, i);
                if ((ctx = EVP_ENCODE_CTX_new()) == NULL) {
                    csrattrs_len = 0;
                } else {
                    EVP_DecodeInit(ctx);
                    (void)EVP_DecodeUpdate(ctx, csrattrs, &i, (unsigned char *)resp, strlen(resp));
                    csrattrs_len = i;
                    (void)EVP_DecodeFinal(ctx, &(csrattrs[i]), &i);
                    csrattrs_len += i;
                    EVP_ENCODE_CTX_free(ctx);
                }
            }
        }
    }
    /*
     * set up to send CSR to CA and get a PKCS7 package back
     */
    memset(resp, 0, sizeof(resp));
    recv_buff.ptr = resp;
    recv_buff.left = sizeof(resp);
    recv_buff.txrx = 0;

    if (client->svrkeygen) {
        sprintf(cmd, "https://%s:%d/.well-known/est%s/serverkeygen", 
                client->hostname, client->port, client->arbitrary_label);
    } else {
        sprintf(cmd, "https://%s:%d/.well-known/est%s/simpleenroll", 
                client->hostname, client->port, client->arbitrary_label);
    }

    curl_easy_setopt(curl, CURLOPT_URL, cmd);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_cb);
    curl_easy_setopt(curl, CURLOPT_READDATA, &send_buff);
    /*
     * if there's a problem, we can "rewind" the sending stream
     */
    curl_easy_setopt(curl, CURLOPT_SEEKFUNCTION, seek_cb);
    curl_easy_setopt(curl, CURLOPT_SEEKDATA, &send_buff);

    /*
     * if the socket is still open then the server isn't closing the
     * connection on each transaction. Which means we might not get
     * ssl_info_callback() invoked anymore so generate the CSR now.
     */
    if (socket_open) {
        if (generate_csr(client) < 1) {
            fprintf(stderr, "can't generate CSR yet...hopefully next\n");
        }
    }
    slist = curl_slist_append(slist, "Content-Type: application/pkcs10");
    slist = curl_slist_append(slist, "Content-Transfer-Encoding: base64");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
    
    if ((res = curl_easy_perform(curl)) != CURLE_OK) {
        if (res != CURLE_SEND_FAIL_REWIND) {
            debug("failed to send PKCS#10 and/or get PKCS#7! %s\n", 
                  curl_easy_strerror(res));
            goto fin;
        }
        /*
         * deal with Max's weird server which produces this:
         *    "no chunk, no close, no size. Assume close to signal end"
         * and
         *    "Send failed since rewinding of the data stream failed"
         * Just try again, it's really a 401 Unauthorized
         */
        res = curl_easy_perform(curl);
    } 
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &rcode);
    /*
     * if we're authenticating with a certificate, the server may still
     * ask for a password. Try it....
     */
    if ((rcode == 401) && client->key_cert) {
        printf("Still not authorized! Try using a password too\n"); 
        curl_easy_setopt(curl, CURLOPT_USERNAME, client->username);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, client->password);
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC|CURLAUTH_DIGEST);
        send_buff.txrx = 0;
        curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &rcode);
    }
    curl_slist_free_all(slist);
    if (rcode != 200) {
        debug("can't enroll with EST :-(\n");
    } else {
        debug("Response to %s:\n%s\n", client->svrkeygen ? "/serverkeygen" : "/simpleenroll", resp);
        if (client->svrkeygen) {
            if (parse_multi_part(cert_store, recv_buff.ptr, recv_buff.txrx) > 0) {
                ret = EST_SUCCESS;
            }
        } else {
            if (validate_and_save_certs(cert_store, "mycert", recv_buff.ptr, recv_buff.txrx) > 0) {
                ret = EST_SUCCESS;
            }
        }
    }
fin:
    if (csrattrs_len) {
        free(csrattrs);
    }
    if (cert_store != NULL) {
        X509_STORE_free(cert_store);
    }
    if (send_buff.left) {
        free(send_buff.ptr);
    }
    curl_easy_cleanup(curl);

    return ret;
}

