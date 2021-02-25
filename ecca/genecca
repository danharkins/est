#!/bin/sh
#
SEDCMD='s:FIXME:'`pwd`':'
#
cat conf/dummy.cnf | sed -e ${SEDCMD} > conf/openssl.cnf
#
CATOP=`pwd`
#
rm -rf ${CATOP}/certs
rm -rf ${CATOP}/crl
rm -rf ${CATOP}/newcerts
rm -rf ${CATOP}/private
rm ${CATOP}/serial*
rm ${CATOP}/index*
#
mkdir ${CATOP}/certs
mkdir ${CATOP}/crl
mkdir ${CATOP}/newcerts
mkdir ${CATOP}/private
echo "01" > ${CATOP}/serial
touch ${CATOP}/index.txt
#
echo "Generating a new EC CA..."
#
openssl ecparam -name ${1} -out ${CATOP}/curveparam.pem
#
openssl req -config ${CATOP}/conf/openssl.cnf $SSLEAY_CONFIG \
    -newkey ec:${CATOP}/curveparam.pem -x509 \
    -nodes -sha512 -keyout ${CATOP}/private/estcakey.pem \
    -out ${CATOP}/estcacert.pem -days 3650
#
# make a der-encoded p7 of the CA's cert for the server to
# send in response to /CACerts requests
#
openssl crl2pkcs7 -certfile ${CATOP}/estcacert.pem -outform DER \
    -out ../server/eccacert_der.p7 -nocrl
#
# make a PEM-encoded version available to enable SSL authentication
#
cp ${CATOP}/estcacert.pem ${CATOP}/../server/eccacert.pem
#
echo "...finished!"
