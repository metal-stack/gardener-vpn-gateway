# Gardener VPN Gateway

This is a small piece of software that is intended to run in the shoot controlplane of a [Gardener](https://github.com/gardener/gardener) shoot cluster. It watches for a service in the shoot for incoming connections and listens for incoming connections, which it will forward through the VPN between seed and shoot to the service in the cluster.

The point of this is that the VPN gateway will take care of talking to the VPN proxy, while for the client in the controlplane it looks like a transparent connection.

## Current scope for the implementation

- Only one service per running VPN gateway instance

### Use with proxy (mTLS proxy with http-connect)


## Testing locally

TODO this is not updated for the new vpn gateway role; will need to evaluate if local testing still makes sense and if so how to do this.

<!-- Test cases for local testing in a [kind](https://github.com/kubernetes-sigs/kind) cluster can be found in the [kind](kind) subdirectory. -->
