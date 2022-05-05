#!/bin/bash

dir=test
#cd $dir

set -e
cacer=$dir/cert/ca-root.cer
cer=$dir/cert/rsa.pem
key=$dir/cert/rsa.pem

openssl verify -CAfile $cacer $cer
sudo ./$dir/quic_test -c $cer -k $key -a $cacer
