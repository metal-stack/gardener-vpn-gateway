# Local testing of auditforwarder with kind

Here are test cases how to test auditforwarder in a local [kind](https://github.com/kubernetes-sigs/kind) cluster.

## Test setup

### Prerequisites

You'll need a linux system with the usual tools installed; and also kubectl, [kind](https://github.com/kubernetes-sigs/kind), and [kustomize](https://kustomize.io/) installed as standalone binary. Stern is also useful to monitor your pod logs.

### Subdirectories

* `audit` contains config files related to auditing: The audit policy, and (optional) additional fluent-bit config. These get copied into the cluster itself during the course of the test setup.
* `auditlog` gets mounted into the cluster and contains the audit log files written by the apiserver. In longer test runs, the log files can build up so you may want to clear them out every once in a while; in a production cluster you should limit the nunber of audit log files kept!
* `kind-etc-kubernetes` contains the /etc/kubernetes directory of the test cluster's master node, so that we can manipulate and examine the cluster's innards more easily. It needs to be empty when you create a new test cluster.

### Preparing the environment

Create the necessary certificates with `./gencerts.sh`. (If you did your test setup a long time ago, the test will fail if the certificates have expired. Keep this in mind and re-generate the certificates if needed.)

## Basic scenario

### Setting up the kind cluster

Create the kind cluster with `./make-kind-cluster`.
This creates a three-node kind cluster with the `/etc/kubernetes` directory exposed in the `kind-etc-kubernetes` subdirectory on the host, so that we can manipulate the internals of the cluster to continue the test setup, and examine what happens under the hood. To make this usable, the script tells you to chown the files to your current user and make them readable to you. Since this needs root privileges this is not done automatically but needs to done manually by you.

To create the audit tailer pod(, deployment) and service, execute `kubectl apply -f kubernetes-audit-tailer-tls.yaml`.

### Turning on auditforwarder and verifying the results

Turn on kubernetes auditing and the audit-forwarder sidecar by executing `./make-audit-forwarder`. This will copy the audit policy in place and patch the `kube-apiserver` manifest to turn on auditing and deploy the audit-forwarder sidecar.

You should see a new `kube-apiserver-kind-control-plane` pod getting created, with an `audit-forwarder` sidecar container; the audit logs will appear in the `auditlog` directory, and also in the log of the `kubernetes-audit-tailer` pod in the `kube-system` namespace. Check the logs in the `audit-forwarder` sidecar container to make sure everything is working fine.

You can also wait with the deployment of the audit tailer and start it after the audit-forwarder. You'll see some complaints, but it should pick up the service and start forwarding eventually.

Start and stop the audit tailer service and/or pod, and see what happens.

You can modify the [kube-apiserver patch](kind/kustomize-auditforwarder/kube-apiserver_patch.yaml) file to experiment with audit-forwarder settings; you need to run `./make-audit-forwarder` again to activate them. This is also the right place to specify a specific audit-forwarder version. (Watch a new `kube-apiserver-kind-control-plane` pod being made. Kubernetes is magic!)

When done, delete the cluster with `kind delete cluster`.

## Additional fluent-bit config for additional log destination (example: Splunk)

In addition to the in-cluster audit-tailer, audit-forwarder can also send the log files to another destination. To achieve this, it will pick up any fluent-bit config files mounted into the `/fluent-bit/etc/add/` directory.

There is a test case included for splunk as additional destination; the sample config file is [kind/audit/add/splunk.conf](kind/audit/add/splunk.conf). You'll need to supply your own splunk HEC endpoint and token.

Execute `./make-audit-forwarder-splunk` to activate the configuration.

You can implement your own destination by using the right output plugin; you can also do your own filtering. Just make sure you leave the `rewrite-tag` filter in place so that the audit data still gets passed on to the audit-tailer.

(If you do not need the audit tailer in the cluster, just directly implement a fluent-bit sidecar because then you don't need the kubernetes magic to detect the in-cluster audit tailer around it.)

## Using auditforwarder with a konnectivity tunnel

Gardener offers the option to use a [konnectivity](https://github.com/kubernetes-sigs/apiserver-network-proxy) tunnel for the connectivity between apiserver and cluster. The way Gardener uses it (unless the apiserver SNI featureGate is active as well), a Unix Domain Socket file acts as proxy endpoint for the kube-apiserver.

audit-forwarder can use this proxy; you need to mount the UDS socket file into the container and specify it with the `konnectivity-uds-socket` command line option (or corresponding environment variable). The audit-forwarder will open a local port for fluent-bit to use, connect to the audit-tailer service the the konnectivity tunnel and then just forward the data throuth the tunnel.

Creating the kind cluster with konnectivity enabled in a manner similar to what Gardener is doing is a two step process: First execute `./make-kind-cluster_konnectivity` to create the cluster, and make the `kind-etc-kubernetes` subdirectory your own as instructed; then patch the kube-apiserver to use konnectivity with `./make-konnectivity`.

Once you have the cluster, you can activate the audit-forwarder with `./make-audit-forwarder-konnectivity`. And don't forget the audit tailer.

There is no seperate test case for the mTLS proxy; konnectivity has already been removed from current gardener versions so this is very short-lived and not worth the effort to implement.

## Testing memory limits

audit-forwarder comes with a default mem_buf_limit configuration of 200 Mbyte to prevent it from using up all the memory if it can not write the log data to the audit tailer for a long time. The limit can also be configured through command line option / environment variable.

To test this, you probably want to enable a metrics server so that `kubectl top pod` works. `./make-metrics-server` downloads and patches the metrics server for kind, according to thes instructions: <https://gist.github.com/sanketsudake/a089e691286bf2189bfedf295222bd43>

You can install an intentionally broken audit tailer service with `kubectl apply -f kubernetes-audit-tailer-broken.yaml`, and see the memory usage of audit-forwarder grow until it hits the memory limit. Note the overhead, in addition to the memory buffer itself. It is greater when the events get duplicated for sending to splunk also!

With `kubectl top pod --containers` you can see the `audit-forwarder` container itself, not just the `kube-apiserver` pod as a whole.
