#!/bin/bash

#
# Generates CA / Certificates and replace CA-Bundle in deployment
#

set -e
set -o errexit
set -o nounset
set -o pipefail

CERTDIR=certs

# CREATE THE PRIVATE KEY FOR OUR CUSTOM CA
openssl genrsa -out $CERTDIR/ca.key 2048

# GENERATE A CA CERT WITH THE PRIVATE KEY
openssl req -new -x509 -key $CERTDIR/ca.key -out $CERTDIR/ca.crt -config $CERTDIR/ca-config.txt

# CREATE THE PRIVATE KEY FOR OUR fluentd SERVER
openssl genrsa -out $CERTDIR/tailer.key 2048

# CREATE A CSR FROM THE CONFIGURATION FILE AND OUR PRIVATE KEY
openssl req -new -key $CERTDIR/tailer.key -subj "/CN=kubernetes-audit-tailer" -out $CERTDIR/tailer.csr -config $CERTDIR/ca-config.txt

# CREATE THE CERT SIGNING THE CSR WITH THE CA CREATED BEFORE
openssl x509 -req -in $CERTDIR/tailer.csr -CA $CERTDIR/ca.crt -CAkey $CERTDIR/ca.key -CAcreateserial -out $CERTDIR/tailer.crt

# CREATE THE PRIVATE KEY FOR OUR forwarder
openssl genrsa -out $CERTDIR/forwarder.key 2048

# CREATE A CSR FROM THE CONFIGURATION FILE AND OUR PRIVATE KEY
openssl req -new -key $CERTDIR/forwarder.key -subj "/CN=kubernetes-audit-forwarder" -out $CERTDIR/forwarder.csr -config $CERTDIR/ca-config.txt

# CREATE THE CERT SIGNING THE CSR WITH THE CA CREATED BEFORE
openssl x509 -req -in $CERTDIR/forwarder.csr -CA $CERTDIR/ca.crt -CAkey $CERTDIR/ca.key -CAcreateserial -out $CERTDIR/forwarder.crt

# Create certificate secret manifests for tailer. In the kind cluster, the forwarder needs them copied into the file system because accessing secrets does not work at apiserver creation time.
CA_KEY=$(cat $CERTDIR/ca.key | base64 | tr -d '\n')
CA_BUNDLE=$(cat $CERTDIR/ca.crt | base64 | tr -d '\n')
TAILER_KEY=$(cat $CERTDIR/tailer.key | base64 | tr -d '\n')
TAILER_CERT=$(cat $CERTDIR/tailer.crt | base64 | tr -d '\n')
FORWARDER_KEY=$(cat $CERTDIR/forwarder.key | base64 | tr -d '\n')
FORWARDER_CERT=$(cat $CERTDIR/forwarder.crt | base64 | tr -d '\n')

cat <<EOF >$CERTDIR/tailer-certs.yaml
---
apiVersion: v1
data:
  ca.crt: $CA_BUNDLE
  audittailer-server.key: $TAILER_KEY
  audittailer-server.crt: $TAILER_CERT
kind: Secret
metadata:
  name: audittailer-server
  namespace: kube-system
type: Opaque
---
apiVersion: v1
data:
  ca.crt: $CA_BUNDLE
  audittailer-client.key: $TAILER_KEY
  audittailer-client.crt: $TAILER_CERT
kind: Secret
metadata:
  name: audittailer-client
  namespace: kube-system
type: Opaque
EOF
