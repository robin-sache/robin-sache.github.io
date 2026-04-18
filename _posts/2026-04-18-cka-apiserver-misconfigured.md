---
title:  "Killercoda Apiserver Misconfigured"
date:   2026-04-18
categories: Cloud-Computing CKA
---
![CKA-LOGO](/assets/images/cka/logo.png)
I am planning to take the CKA exam in the near future. I work with Kubernetes daily at my job, but am mostly self taught, so it is probably realistic to say that I have some knowledge gaps. This blog is part of my preparation, where I go through all the scenarios on Killercoda.

# Apiserver Misconfigured
https://killercoda.com/killer-shell-cka/scenario/apiserver-misconfigured
> Fix a misconfigured kube-apiserver

## Finding the misconfigurations

> The kube-apiserver is not running. The static Pod manifest at /etc/kubernetes/manifests/kube-apiserver.yaml has been misconfigured in 3 places. Find and fix all 3 errors so the kube-apiserver starts successfully.

Using `kubectl` we see that the API is not available:

```
$ k get pods
E0418 12:51:36.924523    5115 memcache.go:265] "Unhandled Error" err="couldn't get current server API group list: Get \"https://172.30.1.2:6443/api?timeout=32s\": dial tcp 172.30.1.2:6443: connect: connection refused"
```

Checking the running containers on the control plane with `crictl ps` shows that no kube-apiserver is ever started.

```
Every 2.0s: crictl ps                                                                                                                                                               controlplane: Sat Apr 18 12:52:45 2026

CONTAINER           IMAGE               CREATED              STATE               NAME                      ATTEMPT             POD ID              POD                                       NAMESPACE
5c61e2d129b45       f1b5c176c6ee8       About a minute ago   Running             cilium-operator           5                   f690602605e2a       cilium-operator-5d8ddcb8d8-t446j          kube-system
71dfc3281221f       5f2a969bc7a43       3 minutes ago        Running             kube-scheduler            2                   c45e7a671cfb2       kube-scheduler-controlplane               kube-system
0d9eccc3a4dde       8d7002962c484       3 minutes ago        Running             kube-controller-manager   2                   5fb48f7cb0ca8       kube-controller-manager-controlplane      kube-system
cd07ef401388f       30074b38b9778       39 minutes ago       Running             local-path-provisioner    1                   97edcd0c4d61c       local-path-provisioner-644f8b49d7-qtk79   local-path-storage
3a40a4cdfcdf7       aa5e3ebc0dfed       39 minutes ago       Running             coredns                   1                   8b807e05deb41       coredns-5f68d5bd7f-mbzlm                  kube-system
ba3b421f28b04       aa5e3ebc0dfed       39 minutes ago       Running             coredns                   1                   f17da33133371       coredns-5f68d5bd7f-b4n4t                  kube-system
9be6e38b9e61e       886c30c731c2b       39 minutes ago       Running             cilium-agent              1                   350c01d36fcfe       cilium-kn99v                              kube-system
d0e404434823b       140688c2240f5       40 minutes ago       Running             cilium-envoy              1                   ca46aeaa59572       cilium-envoy-6hzbm                        kube-system
e574c999b06f4       0a108f7189562       40 minutes ago       Running             etcd                      1                   21dbd15523f65       etcd-controlplane                         kube-system
```

My first intuition is to check the kubelet logs using `journalctl`. Here we can see, that the `kube-apiserver.yaml` manifest could not be parsed, with an error on line 4:

```
$ journalctl | grep apiserver
Apr 18 12:54:45 controlplane kubelet[1533]: E0418 12:54:45.660923    1533 file.go:187] "Could not process manifest file" err="/etc/kubernetes/manifests/kube-apiserver.yaml: couldn't parse as pod(yaml: line 4: could not find expected ':'), please check config file" path="/etc/kubernetes/manifests/kube-apiserver.yaml"
```

Looking at the manifest I immediatly noticed, that on line 3 a semicolon is used instead of a regular colon for the metadata key (`metadata;` instead of `metadata:`). Never blindely trust the exact line numbers in an error message!
```
$ cat /etc/kubernetes/manifests/kube-apiserver.yaml 
apiVersion: v1
kind: Pod
metadata;
  annotations:
    kubeadm.kubernetes.io/kube-apiserver.advertise-address.endpoint: 172.30.1.2:6443
  labels:
    component: kube-apiserver
    tier: control-plane
  name: kube-apiserver
  namespace: kube-system
```

After fixing the mistake and checking `watch crictl ps` again, we see that the kube-apiserver container is still not starting. We now have a new error in the journal:

```
Apr 18 12:57:13 controlplane kubelet[1533]: E0418 12:57:13.093217    1533 pod_workers.go:1324] "Error syncing pod, skipping" err="failed to \"StartContainer\" for \"kube-apiserver\" with CrashLoopBackOff: \"back-off 20s restarting failed container=kube-apiserver pod=kube-apiserver-controlplane_kube-system(d14f29a1aabee5555f4951a0fb77a3ca)\"" pod="kube-system/kube-apiserver-controlplane" podUID="d14f29a1aabee5555f4951a0fb77a3ca"
```
The pod is stuck in the `CrashLoopBackOff` state, which means it tried to start the container in the pod but failed. This however means, that we should now have a logfile in `/var/log/pods`. Since kubelet is creating a pod. Checking the log, gives us the next error message:

```
$ cat /var/log/pods/kube-system_kube-apiserver-controlplane_d14f29a1aabee5555f4951a0fb77a3ca/kube-apiserver/4.log 
2026-04-18T12:58:10.934211951Z stderr F Error: unknown flag: --authorization-mode-wrong
```

The kube-apiserver binary received a wrong parameter. Checking the documentation I found the `--authorization-mode` argument, which seems to be the one, we need ([see here][apiman]):

> --authorization-mode strings <br>
Ordered list of plug-ins to do authorization on secure port. Defaults to AlwaysAllow if --authorization-config is not used. Comma-delimited list of: AlwaysAllow,AlwaysDeny,ABAC,Webhook,RBAC,Node.


Going into the manifest again we see the faulty argument. We change it from `--authorization-mode-wrong` to `authorization-mode`. The defined options `Node,RBAC` seem to check out. So we leave them as is. 
```
 - command:
    - kube-apiserver
    - --advertise-address=172.30.1.2
    - --allow-privileged=true
    - --authorization-mode-wrong=Node,RBAC
```

The container is still not starting. Checking the pod log again, we have another new error:
```
$ cat /var/log/pods/kube-system_kube-apiserver-controlplane_31b5450c49a061d4686f95e92e0aa2b6/kube-apiserver/2.log 
2026-04-18T13:02:38.036036573Z stderr F E0418 13:02:38.035967       1 run.go:72] "command failed" err="open /etc/kubernetes/pki/apiserver-wrong.crt: no such file or directory"
```

Apparently we are searching for a certificate `/etc/kubernetes/pki/apiserver-wrong.crt` which can't be found. Looking into the directory specified, we see the following:

```
$ ls -al /etc/kubernetes/pki/
total 68
drwxr-xr-x 3 root root 4096 Apr  1 08:51 .
drwxrwxr-x 4 root root 4096 Apr  1 08:51 ..
-rw-r--r-- 1 root root 1123 Apr  1 08:51 apiserver-etcd-client.crt
-rw------- 1 root root 1679 Apr  1 08:51 apiserver-etcd-client.key
-rw-r--r-- 1 root root 1176 Apr  1 08:51 apiserver-kubelet-client.crt
-rw------- 1 root root 1675 Apr  1 08:51 apiserver-kubelet-client.key
-rw-r--r-- 1 root root 1289 Apr  1 08:51 apiserver.crt
-rw------- 1 root root 1679 Apr  1 08:51 apiserver.key
-rw-r--r-- 1 root root 1107 Apr  1 08:51 ca.crt
-rw------- 1 root root 1679 Apr  1 08:51 ca.key
drwxr-xr-x 2 root root 4096 Apr  1 08:51 etcd
-rw-r--r-- 1 root root 1123 Apr  1 08:51 front-proxy-ca.crt
-rw------- 1 root root 1671 Apr  1 08:51 front-proxy-ca.key
-rw-r--r-- 1 root root 1119 Apr  1 08:51 front-proxy-client.crt
-rw------- 1 root root 1675 Apr  1 08:51 front-proxy-client.key
-rw------- 1 root root 1675 Apr  1 08:51 sa.key
-rw------- 1 root root  451 Apr  1 08:51 sa.pub
```

Going into the manifest for a last time we again see the misconfiguration a little furhter down. 

```
  - command:
    - kube-apiserver
    - ...
    - --tls-cert-file=/etc/kubernetes/pki/apiserver-wrong.crt
```

In the documentation ([see here][apiman]) we learn, that this certificate is used, so that the API is reachable using HTTPS:
> --tls-cert-file string <br> File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert). If HTTPS serving is enabled, and --tls-cert-file and --tls-private-key-file are not provided, a self-signed certificate and key are generated for the public address and saved to the directory specified by --cert-dir.

I assume the correct certificate file is `/etc/kubernetes/pki/apiserver.crt` and change the path in the manifest. (`--tls-cert-file=/etc/kubernetes/pki/apiserver-wrong.crt` to `--tls-cert-file=/etc/kubernetes/pki/apiserver.crt`).

Checking `crictl ps` we now see a running kube-apiserver container! With `kubectl` we can then check if the API is reachable again:

```
$ crictl ps | grep api
3b36df7167ff5       6f9eeb0cff981       About a minute ago   Running             kube-apiserver            0                   8dcc16fba2024       kube-apiserver-controlplane               kube-system
```
```
$ k get pods
No resources found in default namespace.
```
## Learnings
- If the static pod manifest files do not have the correct syntax, no container or pod log is created, since no pod is ever created.
- Even if no container starts, we maybe still have a pod log. (For example if the pod is in the `CrashLoopBackOff` state)


[apiman]: https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/