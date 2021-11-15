#!/bin/bash

#cd $dir

set -e
key_bits=2048
expire_days=3650
subj=/C="CA"/ST="California"/L="Sunnyvale"/O="TBQUIC"/OU="TBQUIC"/CN="tbquic"
dir=demoCA
mkdir -p $dir/{private,newcerts}
if [ ! -f $dir/index.txti ]; then
	touch $dir/index.txt
fi
if [ ! -f $dir/serial ]; then
	echo 00 > $dir/serial
fi

config=./openssl.cnf
ca_name=ca-root
root_cacer=$ca_name.cer
root_cakey=$ca_name.key
#Root CA
openssl genrsa -out $root_cakey $key_bits
openssl req -config $config -x509 -new -key $root_cakey -out $root_cacer -days $expire_days -subj $subj
cd $dir
ln -sf ../$root_cacer cacert.pem
cd private
ln -sf ../../$root_cakey cakey.pem
#openssl ca -config $config -keyfile $root_cakey -out $root_cacer -infiles $root_csr -selfsign
echo "===================Gen Root CA OK===================="
