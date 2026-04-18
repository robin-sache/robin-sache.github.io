---
title:  "CKA - Killercoda Apiserver Crash"
date:   2026-04-12
categories: Cloud-Computing CKA
---
![CKA-LOGO](/assets/images/cka/logo.png)
I am planning to take the CKA exam in the near future. I work with Kubernetes daily at my job, but am mostly self taught, so it is probably realistic to say that I have some knowledge gaps. This blog is part of my preparation, where I go through all the scenarios on Killercoda.

# Apiserver Crash
https://killercoda.com/killer-shell-cka/scenario/apiserver-crash
> The idea here is to misconfigure the Apiserver in different ways, then check possible log locations for errors.
<br> You should be very comfortable with situations where the Apiserver is not coming back up.


## Wrong kube-apiserver argument
> Configure the Apiserver manifest with a new argument --this-is-very-wrong

Kubelet checks the path `/etc/kubernetes/manifests/` for constant pod manifests including the kube-apiserver pod definition ([see here][constman]).

We make a backup of the manifest:
```
cp /etc/kubernetes/manifests/kube-apiserver.yaml ~/kube-apiserver.yaml.bak
```

Then we add the wrong parameter:
```
$ vim /etc/kubernetes/manifests/kube-apiserver.yaml
...
containers:
  - command:
    - kube-apiserver
    - --this-is-very-wrong
    - --advertise-address=172.30.1.2
    - --allow-privileged=true
    - --authorization-mode=Node,RBAC
...
```

> Check if the Pod comes back up and what logs this causes.

After a short while, we see using `crictl ps` that the kube-apiserver pod is restarting constantly and the api is no longer reachable:
```
$ k get pods
E0412 12:06:35.233287    5254 memcache.go:265] "Unhandled Error" err="couldn't get current server API group list: Get \"https://172.30.1.2:6443/api?timeout=32s\": dial tcp 172.30.1.2:6443: connect: connection refused"
```

Checking the default pod log location `/var/logs/pods` ([see here][logloc]) we see the following:
```
$ cat /var/log/pods/kube-system_kube-apiserver-controlplane_c130c47187dfe5e4eeeeff210327ba6e/kube-apiserver/6.log 
2026-04-12T12:53:39.25835163Z stderr F Error: unknown flag: --this-is-very-wrong
```
(`/var/log/containers` symlinks to `/var/log/pods` for backwards compatibility)
> Fix the Apiserver again.

Copying the backup back into the original location leads to the apiserver pod coming up and the API being reachable again:

```
$ cp ~/kube-apiserver.yaml.bak /etc/kubernetes/manifests/kube-apiserver.yaml

$ crictl ps | grep kube-apiserver
bd17fa0227181       6f9eeb0cff981       56 seconds ago      Running             kube-apiserver            0                   f220692e2bb0a       kube-apiserver-controlplane               kube-system

$ k get pods 
No resources found in default namespace.
```

## Wrong etcd-servers address
> Change the existing Apiserver manifest argument to: --etcd-servers=this-is-very-wrong 

> Check what the logs say, without using anything in /var .

Again changing the manifest `/etc/kubernetes/manifests/kube-apiserver.yaml`:

```
 - command:
    - kube-apiserver
    - ...
    - --etcd-servers=this-is-very-wrong
```

This again leads to the kube-apiserver continuously crashing and the API not being available. Since we aren't allowed to check the logs in `/var` we instead use the `crictl` tool to look at the logs:

```
$ crictl ps 
CONTAINER           IMAGE               CREATED             STATE               NAME                      ATTEMPT             POD ID              POD                                       NAMESPACE
a4fa45ca3a8be       6f9eeb0cff981       13 seconds ago      Running             kube-apiserver            3                   26cd6c368c031       kube-apiserver-controlplane               kube-system
```

```
$ crictl logs a4fa45ca3a8be
> Error while dialing dial tcp: address this-is-very-wrong: missing port in address. Reconnecting...
```

The kube-apiserver is unable to reach the etcd service, as it does not have a valid address configuration. Since K8s needs the etcd key/value store for storing pretty much the complete cluster state, nothing works. ([see here][etcdbasics])

Now to fix it again we just need to insert the correct etcd address again. However I forgot to create a backup of the kube-apiserver manifest before breaking it and I did not remember the original value of the changed argument...ups.

Since the etcd-controlplane is still running, we can just inspect its configuration and hopefully find the defined listening address:
```
$ crictl ps
CONTAINER           IMAGE               CREATED             STATE               NAME                      ATTEMPT             POD ID              POD                                       NAMESPACE                       kube-system
c30cbfb5f9deb       0a108f7189562       About an hour ago   Running             etcd                      1                   98bb84dd04f5b       etcd-controlplane                         kube-system
```

```
$ crictl inspect c30cbfb5f9deb
{
  "info": {
    "config": {
      "annotations": {
        ...
      },
      "command": [
        "etcd",
        "--advertise-client-urls=https://172.30.1.2:2379",
        "--cert-file=/etc/kubernetes/pki/etcd/server.crt",
        "--client-cert-auth=true",
        "--data-dir=/var/lib/etcd",
        "--feature-gates=InitialCorruptCheck=true",
        "--initial-advertise-peer-urls=https://172.30.1.2:2380",
        "--initial-cluster=controlplane=https://172.30.1.2:2380",
        "--key-file=/etc/kubernetes/pki/etcd/server.key",
        "--listen-client-urls=https://127.0.0.1:2379,https://172.30.1.2:2379",
        "--listen-metrics-urls=http://127.0.0.1:2381",
        "--listen-peer-urls=https://172.30.1.2:2380",
        ...
      ],
```

Looking at the etcd commandline argument documentation ([see here][etcdparams]). The `--listen-client-urls` seems to be the information we searched for.

> --listen-client-http-urls <br>
    List of URLs to listen on for HTTP-only client traffic. This flag tells the etcd to accept incoming requests from clients on the specified http://IP:port combinations. Enabling this flag removes HTTP services from --listen-client-urls. Use this flag when you want to segregate HTTP traffic from other protocols. If 0.0.0.0 is specified as the IP, etcd listens to the given port on all interfaces. If an IP address is given as well as a port, etcd will listen on the given port and interface. Multiple URLs may be used to specify a number of addresses and ports to listen on. The etcd will respond to requests from any of the listed addresses and ports.


So inserting `https://172.30.1.2:2379` into the kube-apiserver configuration should fix our problem:

```
$ cat kube-apiserver.yaml 
...
  - command:
    - kube-apiserver
    - ...
    - --etcd-servers=https://172.30.1.2:2379
```

Which lead to the pod coming up again!

## Invalid Apiserver Manifest YAML
> Change the Apiserver manifest and add invalid YAML, something like this:
```
  apiVersionTHIS IS VERY ::::: WRONG v1
  kind: Pod
  metadata:
```

We do exactly that in the `/etc/kubernetes/manifests/kube-apiserver.yaml` ( after creating a backup :) ).

Checking the output of `crictl ps` now shows, that the kube-apiserver pod is completely gone. There are also no logs found in `/var/logs/pods` that could help us:

```
$ ls -l /var/log/pods       
total 36
drwxr-xr-x 3 root root 4096 Apr  1 08:51 kube-system_cilium-envoy-6hzbm_b52605f1-62c7-4516-aed5-ee935604b542
drwxr-xr-x 9 root root 4096 Apr  1 08:51 kube-system_cilium-kn99v_22ad9313-9a1f-4464-8d18-995696a4070a
drwxr-xr-x 3 root root 4096 Apr  1 08:51 kube-system_cilium-operator-5d8ddcb8d8-t446j_10256c36-1536-4fc0-92e9-43656e9373bb
drwxr-xr-x 3 root root 4096 Apr  1 08:52 kube-system_coredns-5f68d5bd7f-b4n4t_6fbef201-ad55-42ea-9216-8f7797a7529b
drwxr-xr-x 3 root root 4096 Apr  1 08:52 kube-system_coredns-5f68d5bd7f-mbzlm_e92989b5-7e11-401d-b007-44936c19ec02
drwxr-xr-x 3 root root 4096 Apr  1 08:53 kube-system_etcd-controlplane_e9372758075579e63217f5b050ad88f3
drwxr-xr-x 3 root root 4096 Apr  1 08:53 kube-system_kube-controller-manager-controlplane_9558a8794fd8531b32223b3190c0423c
drwxr-xr-x 3 root root 4096 Apr  1 08:53 kube-system_kube-scheduler-controlplane_99f727e1f9eff311e4b8b8637ae53fda
drwxr-xr-x 3 root root 4096 Apr  1 08:54 local-path-storage_local-path-provisioner-644f8b49d7-qtk79_12ad84ce-5bca-42b1-aead-b745f0aff679
```

Looking at the systemd journal helps us however:
```
$ journalctl | grep apiserver
pr 18 12:20:34 controlplane kubelet[1560]: E0418 12:20:34.886578    1560 file.go:187] "Could not process manifest file" err="/etc/kubernetes/manifests/kube-apiserver.yaml: couldn't parse as pod(Object 'apiVersion' is missing in '{\"apiVersionTHIS IS VERY ::::\":\"WRONG v1\",\"kind\":\"Pod\",\"metadata\":..., please check config file" path="/etc/kubernetes/manifests/kube-apiserver.yaml"
```
Since we screwed up the manifest format, kubelet was not able to read it and start a pod. So lets revert the change again. This time by copying the backup manifest. After a short while the kube-apiserver pod starts up and the API is reachable again:

```
cp /etc/kubernetes/manifests/kube-apiserver.yaml ~/kube-apiserver.yaml.bak
```

```
$ k get pods
No resources found in default namespace.
```

## Learnings

- Helpful log locations and commands on a control plane are: `/var/log/pods`, `journalctl -eu kubelet`, `crictl logs <container_id>`
- Static manifests are found in `/etc/kubernetes/manifests`
- Make backups before you fuck around with stuff

[constman]: https://kubernetes.io/docs/reference/setup-tools/kubeadm/implementation-details/#constants-and-well-known-values-and-paths
[logloc]: https://kubernetes.io/docs/concepts/cluster-administration/logging/#log-location-node
[etcdbasics]: https://kubernetes.io/docs/tasks/administer-cluster/configure-upgrade-etcd/
[etcdparams]: https://etcd.io/docs/v3.4/op-guide/configuration/#--listen-client-urls