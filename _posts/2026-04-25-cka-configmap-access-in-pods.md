---
title:  "Killercoda ConfigMap Access in Pods"
date:   2026-04-25
categories: Cloud-Computing CKA
---
![CKA-LOGO](/assets/images/cka/logo.png)
I am planning to take the CKA exam in the near future. I work with Kubernetes daily at my job, but am mostly self taught, so it is probably realistic to say that I have some knowledge gaps. This blog is part of my preparation, where I go through all the scenarios on Killercoda.

# ConfigMap Access in Pods
https://killercoda.com/killer-shell-cka/scenario/configmap-pod-access

## Create ConfigMaps
> Create two ConfigMaps:

> 1. Create a ConfigMap named trauerweide with content tree=trauerweide <br>
> 2. Create the ConfigMap stored in existing file /root/cm.yaml


In the documentation for creating configMaps we see an example for creating one with a literal ([see here][configmapman]):

```
# Create a new config map named my-config with key1=config1 and key2=config2
  kubectl create configmap my-config --from-literal=key1=config1 --from-literal=key2=config2
```

With the `--from-literal` argument we execute the first task:
```
$  kubectl create configmap trauerweide --from-literal=tree=trauerweide
configmap/trauerweide created
```

```
$ k get cm trauerweide -oyaml
apiVersion: v1
data:
  tree: trauerweide
kind: ConfigMap
metadata:
  creationTimestamp: "2026-04-25T14:14:51Z"
  name: trauerweide
  namespace: default
  resourceVersion: "11074"
  uid: d6e07cf0-cfd4-4e45-85a9-d2972a1cb2ac
```

For the second task we already have a configMap manifest prepared for us. This we can just apply as is:

```
$ cat /root/cm.yaml 
apiVersion: v1
data:
  tree: birke
  level: "3"
  department: park
kind: ConfigMap
metadata:
  name: birke
```
```
$ k apply -f /root/cm.yaml 
configmap/birke created
```


## Access ConfigMaps in Pod
> 1. Create a Pod named pod1 of image nginx:alpine
> 2. Make key tree of ConfigMap trauerweide available as environment variable TREE1
> 3. Mount all keys of ConfigMap birke as volume. The files should be available under /etc/birke/*
> 4. Test env+volume access in the running Pod

I rarely write manifests from scratch. Let's try with the help of the documentations for pods ([see here][podman]) and the explicit guide how to make configMaps available to pods ([see here][podconfigmap]). After some trial and error I landed on the following manifest, which creates a pod with one container and an attached volume. The volume is referencing the `birke` configmap and is mounted into the container at the path `/etc/birke`. The container also receives the value of the key `tree` from the configmap `trauerweide` as the environment variable `TREE1`.

```
$ vim pod.yml
apiVersion: v1
kind: Pod
metadata:
  name: pod1
spec:
  containers:
  - name: nginx
    image: nginx:alpine
    env:
    - name: TREE1
      valueFrom:
        configMapKeyRef:
          name: trauerweide
          key: tree
    volumeMounts:
    - name: birke
      mountPath: /etc/birke
  volumes:
  - name: birke
    configMap: 
      name: birke
```

We can now apply this manifest:
```
$ k apply -f pod.yml 
pod/pod1 created
```

To check the configuration we exec into the the pod interactively using the `-it` parameter and run `sh`. Here we see the environment variable and the mounted configMap in the filesystem:
```
$ k exec -it pod1 -- sh
# env | grep TREE1
TREE1=trauerweide
# ls -al /etc/birke/
total 16
drwxrwxrwx    3 root     root          4096 Apr 25 14:27 .
drwxr-xr-x    1 root     root          4096 Apr 25 14:28 ..
drwxr-xr-x    2 root     root          4096 Apr 25 14:27 ..2026_04_25_14_27_59.2433766962
lrwxrwxrwx    1 root     root            32 Apr 25 14:27 ..data -> ..2026_04_25_14_27_59.2433766962
lrwxrwxrwx    1 root     root            17 Apr 25 14:27 department -> ..data/department
lrwxrwxrwx    1 root     root            12 Apr 25 14:27 level -> ..data/level
lrwxrwxrwx    1 root     root            11 Apr 25 14:27 tree -> ..data/tree
```


[configmapman]: https://kubernetes.io/docs/reference/kubectl/generated/kubectl_create/kubectl_create_configmap/
[podman]: https://kubernetes.io/docs/concepts/workloads/pods/
[podconfigmap]: https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/