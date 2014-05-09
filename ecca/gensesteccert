#!/bin/sh
#
CATOP=`pwd`
#
echo "Generating a CSR..."
#
openssl req -config ${CATOP}/conf/openssl.cnf $SSLEAY_CONFIG \
	-newkey ec:${CATOP}/curveparam.pem -nodes \
	-keyout key.pem -out req.pem
#
echo "...signing CSR..."
#
openssl ca -config ${CATOP}/conf/openssl.cnf $SSLEAY_CONFIG \
	-policy policy_anything -batch -notext \
	-out cert.pem -infiles req.pem
#
cat key.pem cert.pem > ../server/sesteccert.pem
rm key.pem req.pem cert.pem
#
echo "...finished!"

