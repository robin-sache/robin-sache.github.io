---
title:  "CKA - Killercoda Apiserver Crash"
date:   2026-04-12
categories: Cloud-Computing CKA
---
![CKA-LOGO](/assets/images/cka/logo.png)
I am planning to take the CKA exam in the near future. This blog is part of my preparation, where I go through all the scenarios on Killercoda.

[constman]: https://kubernetes.io/docs/reference/setup-tools/kubeadm/implementation-details/#constants-and-well-known-values-and-paths
[logloc]: https://kubernetes.io/docs/concepts/cluster-administration/logging/#log-location-node

## Scenarion Definition
> The idea here is to misconfigure the Apiserver in different ways, then check possible log locations for errors.
<br> You should be very comfortable with situations where the Apiserver is not coming back up.


## Wrong kube-apiserver argument
> Configure the Apiserver manifest with a new argument --this-is-very-wrong

Kubelet checks the path `/etc/kubernetes/manifests/` for constant pod manifests including the kubeapi pod definition ([see here][constman]).

We make a backup of the manifest:
```
cp /etc/kubernetes/manifests/kube-apiserver.yaml ~/kube-apiserver.yaml.bak
```

Then we add the wrong parameter
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

After a short while, we see using `crictl ps` that the kube-apiserver pod is no longer running and the api is no longer reachable
```
$ crictl ps | grep kube-apiserver
$

$ k get pods
E0412 12:06:35.233287    5254 memcache.go:265] "Unhandled Error" err="couldn't get current server API group list: Get \"https://172.30.1.2:6443/api?timeout=32s\": dial tcp 172.30.1.2:6443: connect: connection refused"
```

Checking the default pod log location defined by kubelet `/var/logs/pods` ([see here][logloc]) we see the following:
(`/var/log/containers` symlinks to `/var/log/pods` for backwards compatibility)
```
$ cat /var/log/pods/kube-system_kube-apiserver-controlplane_c130c47187dfe5e4eeeeff210327ba6e/kube-apiserver/6.log 
2026-04-12T12:53:39.25835163Z stderr F Error: unknown flag: --this-is-very-wrong
```

> Fix the Apiserver again.

Copying the backup back into the original location fixes the problem and leads to the apiserver pod coming up again and the api being reachable again:

```
$ cp ~/kube-apiserver.yaml.bak /etc/kubernetes/manifests/kube-apiserver.yaml

$ crictl ps | grep kube-apiserver
bd17fa0227181       6f9eeb0cff981       56 seconds ago      Running             kube-apiserver            0                   f220692e2bb0a       kube-apiserver-controlplane               kube-system

$ k get pods 
No resources found in default namespace.
```

## Wrong etcd-servers address
> Change the existing Apiserver manifest argument to: --etcd-servers=this-is-very-wrong 

