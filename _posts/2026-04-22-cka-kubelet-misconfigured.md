---
title:  "Killercoda Kubelet Misconfigured"
date:   2026-04-22
categories: Cloud-Computing CKA
---
![CKA-LOGO](/assets/images/cka/logo.png)
I am planning to take the CKA exam in the near future. I work with Kubernetes daily at my job, but am mostly self taught, so it is probably realistic to say that I have some knowledge gaps. This blog is part of my preparation, where I go through all the scenarios on Killercoda.

# Kubelet Misconfigured
https://killercoda.com/killer-shell-cka/scenario/kubelet-misconfigured
> Someone tried to improve the Kubelet on Node node01 , but broke it instead. Fix it.

Currently we are on the controlplane, so let's check if we can see other nodes using `k get nodes`:
```
$ k get nodes
NAME           STATUS     ROLES           AGE   VERSION
controlplane   Ready      control-plane   21d   v1.35.1
node01         NotReady   <none>          21d   v1.35.1
```

We do! We also see, that `node01` has the `NotReady` state. By describing it we see that the kubelet has stopped responding:
```
$ k describe node node01
Conditions:
  Type                 Status    LastHeartbeatTime                 LastTransitionTime                Reason              Message
  ----                 ------    -----------------                 ------------------                ------              -------
  NetworkUnavailable   False     Wed, 01 Apr 2026 09:19:30 +0000   Wed, 01 Apr 2026 09:19:30 +0000   CiliumIsUp          Cilium is running on this node
  MemoryPressure       Unknown   Wed, 22 Apr 2026 14:55:41 +0000   Wed, 22 Apr 2026 14:59:30 +0000   NodeStatusUnknown   Kubelet stopped posting node status.
  DiskPressure         Unknown   Wed, 22 Apr 2026 14:55:41 +0000   Wed, 22 Apr 2026 14:59:30 +0000   NodeStatusUnknown   Kubelet stopped posting node status.
  PIDPressure          Unknown   Wed, 22 Apr 2026 14:55:41 +0000   Wed, 22 Apr 2026 14:59:30 +0000   NodeStatusUnknown   Kubelet stopped posting node status.
  Ready                Unknown   Wed, 22 Apr 2026 14:55:41 +0000   Wed, 22 Apr 2026 14:59:30 +0000   NodeStatusUnknown   Kubelet stopped posting node status.
```

Let's log into the node and check the state of the kubelet service:
```
$ ssh node01
Last login: Mon Feb 10 22:06:42 2025 from 10.244.0.131
```

```
root@node01:~$ systemctl status kubelet
● kubelet.service - kubelet: The Kubernetes Node Agent
     Loaded: loaded (/usr/lib/systemd/system/kubelet.service; enabled; preset: enabled)
    Drop-In: /usr/lib/systemd/system/kubelet.service.d
             └─10-kubeadm.conf
     Active: activating (auto-restart) (Result: exit-code) since Wed 2026-04-22 15:08:49 UTC; 1s ago
       Docs: https://kubernetes.io/docs/
    Process: 2827 ExecStart=/usr/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS $KUBELET_EXTRA_ARGS (code=exited, status=1/FAILURE)
   Main PID: 2827 (code=exited, status=1/FAILURE)
        CPU: 54ms
```

The service has failed with exit code 1. In the service logs the error message `failed to parse kubelet flag: unknown flag: --improve-speed` is shown.
```
root@node01:~$ journalctl -eu kubelet
Apr 22 15:09:30 node01 systemd[1]: Started kubelet.service - kubelet: The Kubernetes Node Agent.
Apr 22 15:09:30 node01 kubelet[2887]: E0422 15:09:30.285957    2887 run.go:72] "command failed" err="failed to parse kubelet flag: unknown flag: --improve-speed"
Apr 22 15:09:30 node01 systemd[1]: kubelet.service: Main process exited, code=exited, status=1/FAILURE
Apr 22 15:09:30 node01 systemd[1]: kubelet.service: Failed with result 'exit-code'.
```

Kubelet has received an unknown argument. Based on the documentation ([see here][kubeletman]) the flag `--improve-speed` does not exist. To check where the flag is configured, we can look at the systemd unit file:
```
root@node01:~$ systemctl cat kubelet
# /usr/lib/systemd/system/kubelet.service
[Unit]
...

# /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf
# Note: This dropin only works with kubeadm and kubelet v1.11+
[Service]
Environment="KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf"
Environment="KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml"
# This is a file that "kubeadm init" and "kubeadm join" generates at runtime, populating the KUBELET_KUBEADM_ARGS variable dynamically
EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env
# This is a file that the user can use for overrides of the kubelet args as a last resort. Preferably, the user should use
# the .NodeRegistration.KubeletExtraArgs object in the configuration files instead. KUBELET_EXTRA_ARGS should be sourced from this file.
EnvironmentFile=-/etc/default/kubelet
ExecStart=
ExecStart=/usr/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS $KUBELET_EXTRA_ARGS
```

The unit file has a dropin configured under `/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf`. Here we can see the section `EnvironmentFile=-/var/lib/kubelet/kubeadm-flags.env`. Inside of the environment file the unknown argument can be found:

```
root@node01:~$ cat /var/lib/kubelet/kubeadm-flags.env
KUBELET_KUBEADM_ARGS=" --improve-speed"
```

After removing and restarting the kubelet service, everything seems to run as expected:
```
root@node01:~$ systemctl restart kubelet
root@node01:~$ systemctl status kubelet
● kubelet.service - kubelet: The Kubernetes Node Agent
     Loaded: loaded (/usr/lib/systemd/system/kubelet.service; enabled; preset: enabled)
    Drop-In: /usr/lib/systemd/system/kubelet.service.d
             └─10-kubeadm.conf
     Active: active (running) since Wed 2026-04-22 15:21:47 UTC; 8s ago
       Docs: https://kubernetes.io/docs/
   Main PID: 3546 (kubelet)
      Tasks: 8 (limit: 2237)
     Memory: 21.7M (peak: 22.0M)
        CPU: 245ms
     CGroup: /system.slice/kubelet.service
             └─3546 /usr/bin/kubelet --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf --config=/var/lib/kubelet/config.yaml --container-runtime-endpoint unix:///run/containerd/containe>
```

Checking the nodes on the controlplane, we can see now that `node-1` is shown as `Ready`:
```
$ k get nodes
NAME           STATUS   ROLES           AGE   VERSION
controlplane   Ready    control-plane   21d   v1.35.1
node01         Ready    <none>          21d   v1.35.1
```

[kubeletman]: https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/