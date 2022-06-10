#!/bin/bash

dir=test
#cd $dir

set -e
cacer=$dir/cert/ca-root.cer
cer=$dir/cert/rsa.pem
key=$dir/cert/rsa.pem
ca_chain=$dir/cert/ca-chain.cer
cat $cacer $cer | tee $ca_chain 1>/dev/null

openssl verify -CAfile $ca_chain $cer
rm -f $ca_chain
sudo ./$dir/quic_test -c $cer -k $key -a $cacer -d
