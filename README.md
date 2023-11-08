# Audit-forwarder

This is a small piece of software that is intended to run as sidecar in an out-of-cluster kube-apiserver (for example: [gardener](https://github.com/gardener/gardener) clusters) and forward the audit log data back into the cluster where it can be picked up by cluster monitoring / logging software.

## Current scope for the implementation

- The audit-forwarder has to run as sidecar container of the kube-apiserver
- The audit data needs to be logged to file in a shared volume
- There has to be a corresponding `kubernetes-audit-tailer` service and pod in the cluster that receives the audit data and makes it available to a cluster logging solution, e.g. by writing it to its stdout so that it appears as container log
- We use fluent-bit with the `forward` out plugin as forwarding agent because it is built for the task of reliably forwarding log data. There needs to be a corresponding fluent-bit or fluentd running in the `kubernetes-audit-tailer` pod to receive the data

### Use with proxy (mTLS proxy with http-connect)

In some scenarios it is necessary to use a proxy to communicate from the control plane to the cluster:

- When a [konnectivity proxy](https://github.com/kubernetes-sigs/apiserver-network-proxy) is used to connect from the control plane to the cluster. Konnectivity comes in two flavours:
  - Using a UDS proxy
  - Using a mTLS proxy with http-connect
- When the Gardener reversed-vpn feature is used

Auditforwarder can use either UDS or mTLS proxy; konnectivity or Gardener reversed-vpn look the same from a user perspective (only the proxy hostname is different) so they get treated the same.

FIXME describe this better

- A UDS proxy using the http connect method, running in another sidecar of the apiserver. Details on how this gets invoked are within the konnectivity test case (see next section).
- A mTLS proxy using http connect, running in a seperate pod from the kube-apiserver. The method to use this is much the same as with the UDS proxy; there are seperate command options to specify the proxy host and port.

## Testing locally

Test cases for local testing in a [kind](https://github.com/kubernetes-sigs/kind) cluster can be found in the [kind](kind) subdirectory.
