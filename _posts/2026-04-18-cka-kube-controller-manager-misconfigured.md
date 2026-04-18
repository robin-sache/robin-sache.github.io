---
title:  "Killercoda Kube Controller Manager Misconfigured"
date:   2026-04-12
categories: Cloud-Computing CKA
---
![CKA-LOGO](/assets/images/cka/logo.png)
I am planning to take the CKA exam in the near future. I work with Kubernetes daily at my job, but am mostly self taught, so it is probably realistic to say that I have some knowledge gaps. This blog is part of my preparation, where I go through all the scenarios on Killercoda.

# Kube Controller Manager Misconfigured
https://killercoda.com/killer-shell-cka/scenario/kube-controller-manager-misconfigured
> It is crashing, fix it

## Custom Kube Controller Image
> A custom Kube Controller Manager container image was running in this cluster for testing. It has been reverted back to the default one, but it's not coming back up. Fix it.

The controller manager is responsible for managing different controllers, which in turn are responsible for pushing the cluster into the desired state. So for example the Replication Controller is responsible for ensuring, that the desired number of pod replicas are running. ([see here][ckmman])

Let's start by checking what pods are running in the `kube-system` namespace. Here we see, that the kube-controller-manager-controlplane pod is crashing:
```
$ k get pods -n kube-system
NAME                                   READY   STATUS             RESTARTS       AGE
cilium-envoy-6hzbm                     1/1     Running            1 (49m ago)    17d
cilium-kn99v                           1/1     Running            1 (49m ago)    17d
cilium-operator-5d8ddcb8d8-t446j       1/1     Running            2 (49m ago)    17d
coredns-5f68d5bd7f-b4n4t               1/1     Running            1 (49m ago)    17d
coredns-5f68d5bd7f-mbzlm               1/1     Running            1 (49m ago)    17d
etcd-controlplane                      1/1     Running            1 (49m ago)    17d
kube-apiserver-controlplane            1/1     Running            1 (49m ago)    17d
kube-controller-manager-controlplane   0/1     CrashLoopBackOff   6 (4m2s ago)   9m30s
kube-scheduler-controlplane            1/1     Running            1 (49m ago)    17d
```

Describing the pod and looking at the events we don't see anything specific. It tries to start the container and fails:

```
$ k describe pod -n kube-system kube-controller-manager-controlplane
...
Events:
  Type     Reason   Age                  From     Message
  ----     ------   ----                 ----     -------
  Normal   Pulled   4m51s (x7 over 10m)  kubelet  spec.containers{kube-controller-manager}: Container image "registry.k8s.io/kube-controller-manager:v1.35.1" already present on machine and can be accessed by the pod
  Normal   Created  4m51s (x7 over 10m)  kubelet  spec.containers{kube-controller-manager}: Container created
  Normal   Started  4m51s (x7 over 10m)  kubelet  spec.containers{kube-controller-manager}: Container started
  Warning  BackOff  49s (x25 over 10m)   kubelet  spec.containers{kube-controller-manager}: Back-off restarting failed container kube-controller-manager in pod kube-controller-manager-controlplane_kube-system(3a55b705a84a6fefa87bc94071f8cc92)
```

Looking at the pod logs, we get the error message that an unknown flag was used. On the kube-controller-manager manpage we see that this flag does not seem to exist ([see here][ckmman]).
```
$ k logs -n kube-system kube-controller-manager-controlplane
...
Error: unknown flag: --project-sidecar-insertion
```

In the static manifest file `/etc/kubernetes/manifests/kube-controller-manager.yaml` we see the faulty flag:
```
...
containers:
  - command:
    - kube-controller-manager
    - ...
    - --project-sidecar-insertion
```

Since I am unsure if this is the correct course of action I made a backup before removing the flag:
```
$ cp kube-controller-manager.yaml ~/backup.yaml
```

After removing it and checking the pods in the `kube-system` namespace again, we can see that the pod is up now.

```
$ k get pods -n kube-system | grep controller
kube-controller-manager-controlplane   1/1     Running   0             19s
```

Looking at the pod logs everything seems clean now.
```
$ k logs -n kube-system kube-controller-manager-controlplane
I0418 13:56:44.001105       1 shared_informer.go:377] "Caches are synced"
I0418 13:56:44.002269       1 shared_informer.go:377] "Caches are synced"
I0418 13:56:44.004508       1 shared_informer.go:377] "Caches are synced"
I0418 13:56:44.010623       1 shared_informer.go:377] "Caches are synced"
I0418 13:56:44.011051       1 shared_informer.go:377] "Caches are synced"
I0418 13:56:44.011185       1 shared_informer.go:377] "Caches are synced"
I0418 13:56:44.023478       1 shared_informer.go:377] "Caches are synced"
I0418 13:56:44.023724       1 shared_informer.go:377] "Caches are synced"
I0418 13:56:44.040319       1 shared_informer.go:370] "Waiting for caches to sync"
I0418 13:56:44.141680       1 shared_informer.go:377] "Caches are synced"
I0418 13:56:44.229202       1 shared_informer.go:377] "Caches are synced"
I0418 13:56:44.229228       1 garbagecollector.go:166] "Garbage collector: all resource monitors have synced"
I0418 13:56:44.229237       1 garbagecollector.go:169] "Proceeding to collect garbage"
```

## Learnings
- The controller manager is responsible for managing controllers. If it is not running the cluster state will drift from the desired state.

[ckmman]: https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/