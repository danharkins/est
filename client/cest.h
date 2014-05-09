/*
 * cest.h - include file to communicate with cest
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

/*
 * some useful defines for sizes of cruft below
 */
#define MAC_STR_LEN     18
#define IMEI_LEN        17
#define DEVID_LEN       30
#define DRINK_LEN       40

/*
 * client-specific cruft to pass into the cest module
 */
struct est_client {
    /*
     * cruft necessary to do EST
     */
    char username[40];
    char password[40];
    char hostname[80];
    char cafile[80];
    char capath[80];
    char mykey[40];
    char mycert[40];
    int svrkeygen;
    int port;
    char arbitrary_label[80];
    /*
     * cruft to influence how EST is spoken
     */
#define CLIENT_CERT     0x01
#define CLIENT_KEY      0x02
    int key_cert;
    int verify_peer;
#define SORT_OF_CHATTY  0x01
#define REAL_CHATTY     0x02
    int how_chatty;
#define USE_TLSv1       0x01
#define USE_TLS_PWD     0x02
    int tls_mask;
    /*
     * client-specific cruft to put in a CSR
     */
    char options_mask;                  /* which cruft is here? */
#define SERIAL_MASK     0x01
#define MAC_MASK        0x02
#define IMEI_MASK       0x04
#define DEVID_MASK      0x08
#define DRINK_MASK      0x10
    int serialnum;
    char macaddr[MAC_STR_LEN];
    char imei[IMEI_LEN];
    char devid[DEVID_LEN];
    char drink[DRINK_LEN];
};

/*
 * the work-horse, the speaker of EST...do_est()
 */
int do_cest(struct est_client *);

/*
 * return values for do_est()
 */
#define EST_SUCCESS     1
#define EST_ADD_TADB    0
#define EST_FAILURE     -1
