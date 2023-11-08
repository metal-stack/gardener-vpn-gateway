# Notes


To start the cluster:
`./make-kind-cluster`


Made a audit tailer deployment with fluent-bit. Start with:
`kubectl apply -f kubernetes-audit-tailer.yaml`

## TODO
* Apply the audit-forwarder-controller to the apiserver manifest; make all the right volumes / volume-mounts

* It works!
* Sequence to do it:
  * Start cluster and tailer, see above
  * make-kind-cluster exports the kubeconfig as ./kube.config, but with the exposed port on the host. We need the (internal) address from the manifest, which is at kind-etc-kubernetes/manifests/kube-apiserver.yaml
    * Wrong: `    server: https://127.0.0.1:41757`
    * From manifest: `    kubeadm.kubernetes.io/kube-apiserver.advertise-address.endpoint: 172.18.0.3:6443`
    * Right: `    server: https://172.18.0.3:6443`
  * We need to put this kubeconfig in: kind-etc-kubernetes/audit/kube.config BEFORE we start the audit-forwarder
  * Next we copy the kube-apiserver manifest (as root) to . and edit it:
```
# Add the sidecar container:
  - image: mreiger/audit-forwarder
    imagePullPolicy: IfNotPresent
    name: audit-forwarder
    env:
    - name: AUDIT_KUBECFG
      value: "/kube.config"
    volumeMounts:
    - mountPath: /audit
      name: auditlog
    - mountPath: /kube.config
      name: kubeconfig
# Add the kubeconfig volume:
  - hostPath:
      path: /etc/kubernetes/audit/kube.config
      type: File
    name: kubeconfig
```
  * Copy the manifest back to kind-etc-kubernetes/manifests and the audit-forwarder will start and ship the logs to the tailer.
  * It is important to have the right kubeconfig in place, because the audit-forwarder does not re-read it if it changes on disk - and also does not get killed when one tries to delete the kube-apiserver pod(!) A dirty trick to kill the container so it will get restarted with the right kubeconfig:
```
k exec -n kube-system kube-apiserver-kind-control-plane --container=audit-forwarder -ti -- sh
/ #
/ # ps -ef
PID   USER     TIME  COMMAND
    1 root      0:00 /fluent-bit/bin/audit-forwarder
   27 root      0:00 sh
   33 root      0:00 ps -ef
/ # kill 1
/ # command terminated with exit code 137
```

Now try to automate this...
And: Make audit-forwarder handle kubeconfig file changes gracefully.
* Idea: Simply exit when watching for pods does not work. Let K8s restart - It's what it is good at.

## To automate it:

Multi step process:
* Prepare subdirectory (Make kind-etc-kubernetes and make sure it is empty)
* Script to create cluster and export Kubeconfig
* Chown -R it to the user
* chmod a+r it
* Script that patches Kubeconfig and kube-apiserver manifest and puts them in place
-> kind-cluster with audit forwarder should be in place.
  * Looks like kubeconfig needs to be in place first.



## Further exercises

Install splunk connect:
```
kubectl create namespace splunk
helm install -n splunk my-splunk-connect -f values.yaml splunk/splunk-connect-for-kubernetes
```

Debug pod:
`k run debug -n kube-system --image=alpine -ti`


To get the logs from inside the kind cluster:
`kind export logs kind-logs` (`kind export logs <destination directory>`)


