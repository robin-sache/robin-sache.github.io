---
title:  "Killercoda Application Misconfigured"
date:   2026-04-25
categories: Cloud-Computing CKA
---
![CKA-LOGO](/assets/images/cka/logo.png)
I am planning to take the CKA exam in the near future. I work with Kubernetes daily at my job, but am mostly self taught, so it is probably realistic to say that I have some knowledge gaps. This blog is part of my preparation, where I go through all the scenarios on Killercoda.

# Application Misconfigured 1
https://killercoda.com/killer-shell-cka/scenario/application-misconfigured-1
> There is a Deployment in Namespace application1 which seems to have issues and is not getting ready. Fix it by only editing the Deployment itself and no other resources.

Let's check the existing deployments in the `application1` namespace and if there are any interesting events:
```
$ k -n application1 get deployments   
NAME   READY   UP-TO-DATE   AVAILABLE   AGE
api    0/3     3            0           2m31s
```

```
$ k -n application1 describe deployment api
...
Events:
  Type    Reason             Age    From                   Message
  ----    ------             ----   ----                   -------
  Normal  ScalingReplicaSet  2m45s  deployment-controller  Scaled up replica set api-76b9797db4 from 0 to 3
```

The deployment got scaled up to 3 replicas, but none of them ended up in the `READY` state. If we check the pods, we can see why:

```
$ k -n application1 get pods               
NAME                   READY   STATUS                       RESTARTS   AGE
api-76b9797db4-8j79h   0/1     CreateContainerConfigError   0          3m12s
api-76b9797db4-vnjnj   0/1     CreateContainerConfigError   0          3m12s
api-76b9797db4-xhfx8   0/1     CreateContainerConfigError   0          3m12s
```
```
$ k -n application1 describe pod api-76b9797db4-8j79h
...
Events:
  Type     Reason     Age                   From               Message
  ----     ------     ----                  ----               -------
  Normal   Scheduled  3m26s                 default-scheduler  Successfully assigned application1/api-76b9797db4-8j79h to controlplane
  Normal   Pulling    3m24s                 kubelet            spec.containers{httpd}: Pulling image "httpd:2.4.52-alpine"
  Normal   Pulled     3m20s                 kubelet            spec.containers{httpd}: Successfully pulled image "httpd:2.4.52-alpine" in 4.2s (4.2s including waiting). Image size: 18209719 bytes.
  Warning  Failed     15s (x16 over 3m20s)  kubelet            spec.containers{httpd}: Error: configmap "category" not found
  Normal   Pulled     15s (x15 over 3m20s)  kubelet            spec.containers{httpd}: Container image "httpd:2.4.52-alpine" already present on machine and can be accessed by the pod
```

The pods are looking for a configmap `category` which does not exist. If we check the configmaps, we see a similar sounding one: `configmap-category`.
```
$ k -n application1 get cm                           
NAME                 DATA   AGE
configmap-category   1      3m55s
kube-root-ca.crt     1      3m55s
```

If we compare the expected key from the deployment and the content of the configmap (in both cases the `category` key), we can assume, that this configmap is actually the one we want:
```
$ k -n application1 get deployment api -oyaml
...
containers:
      - env:
        - name: CATEGORY
          valueFrom:
            configMapKeyRef:
              key: category
              name: category
...
```

```
$ k -n application1 get cm configmap-category -oyaml
apiVersion: v1
data:
  category: abc
kind: ConfigMap
metadata:
  creationTimestamp: "2026-04-25T12:30:52Z"
  name: configmap-category
  namespace: application1
  resourceVersion: "9812"
  uid: be24d191-0270-4007-84a7-fd343eb2f732
```

Using the `edit` keyword we update the configuration:

```
$ k -n application1 edit deployment api
containers:
      - env:
        - name: CATEGORY
          valueFrom:
            configMapKeyRef:
              key: category
              name: configmap-category
```

Now the pods start!
```
$ k -n application1 get pods
NAME                   READY   STATUS    RESTARTS   AGE
api-7d68cbdd7f-bhntw   1/1     Running   0          14s
api-7d68cbdd7f-fkz2p   1/1     Running   0          12s
api-7d68cbdd7f-hmjnx   1/1     Running   0          16s
```

# Application Misconfigured 2
https://killercoda.com/killer-shell-cka/scenario/application-misconfigured-2
> A Deployment has been imported from another Kubernetes cluster. But it seems like the Pods are not running. Fix the Deployment so that it would work in any Kubernetes cluster.

We have no information in which namespace the deployment resides, so lets use the `-A` parameter to see deployments in all namespaces:
```
$ k get deployments -A
NAMESPACE            NAME                     READY   UP-TO-DATE   AVAILABLE   AGE
default              management-frontend      0/5     5            0           34s
kube-system          cilium-operator          1/1     1            1           15h
kube-system          coredns                  2/2     2            2           15h
local-path-storage   local-path-provisioner   1/1     1            1           15h
```

The `management-frontend` seems to be our suspect. Lets check out the events:
```
$ k describe deployment management-frontend
...
Events:
  Type    Reason             Age   From                   Message
  ----    ------             ----  ----                   -------
  Normal  ScalingReplicaSet  72s   deployment-controller  Scaled up replica set management-frontend-89d7d4879 from 0 to 5
```

Like in the previous task the pods got created, but they did not end up in a running state. If we look at the pods, we can see that they are stuck in `Pending`:
```
$ k get pods
NAME                                  READY   STATUS    RESTARTS   AGE
management-frontend-89d7d4879-5dc8z   0/1     Pending   0          7s
management-frontend-89d7d4879-gfm88   0/1     Pending   0          7s
management-frontend-89d7d4879-lxjwl   0/1     Pending   0          7s
management-frontend-89d7d4879-xbn6m   0/1     Pending   0          7s
management-frontend-89d7d4879-xf6sx   0/1     Pending   0          7s
```

The `Pending` state persists if a pod can't be scheduled on a node. This could be because of resource limitations or other scheduling restrictions ([see here][pendingdebugging]). Lets analyse the deployment:

```
$ k get -oyaml deployment management-frontend
apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
    deployment.kubernetes.io/revision: "1"
  creationTimestamp: "2026-04-25T12:39:13Z"
  generation: 1
  name: management-frontend
  namespace: default
  ...
spec:
  progressDeadlineSeconds: 600
  replicas: 5
  revisionHistoryLimit: 10
  selector:
    matchLabels:
      app: management-frontend
  strategy:
    rollingUpdate:
      maxSurge: 25%
      maxUnavailable: 25%
    type: RollingUpdate
  template:
    metadata:
      labels:
        app: management-frontend
    spec:
      containers:
      - image: nginx:alpine
        imagePullPolicy: IfNotPresent
        name: nginx
        resources: {}
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
      dnsPolicy: ClusterFirst
      nodeName: staging-node1
      restartPolicy: Always
      schedulerName: default-scheduler
      securityContext: {}
      terminationGracePeriodSeconds: 30
```

I noticed the `nodeName` key. Based on the documentation it allows you to restrict the scheduling of pods to only the named node. If the node does not exist, the pods stay in the `Pending` state. ([see here][nodeNameman]).

If we check out what nodes exist, we see that there is only the `controlplane`:

```
$ k get nodes
NAME           STATUS   ROLES           AGE   VERSION
controlplane   Ready    control-plane   15h   v1.35.1
```

The solution is to remove the `nodeName` from the deployment, which allows the pods to be scheduled normally. However there could be a small twist. On a cluster deployed by the `kubeadm` tool a default taint `node-role.kubernetes.io/control-plane:NoSchedule` is added to all controlplane nodes. This restricts what can be scheduled on them ([see here][controlplaneTaint]). If the taint exists, we either have to remove it using:
```
kubectl taint nodes controlplane node-role.kubernetes.io/control-plane:NoSchedule-
```
Or add a toleration to the deployment ([see here][toleration]):
```
tolerations:
- key: "node-role.kubernetes.io/control-plane"
  operator: "Exists"
  effect: "NoSchedule"
```

Thankfully we don't have any taints so we can just remove the `nodeName` key from the deployment:
```
$ k get node controlplane -oyaml | grep taint
```

Which makes the pods schedulable:
```
$ k get pods
NAME                                  READY   STATUS    RESTARTS   AGE
management-frontend-6b4fb8fbb-6nxf6   1/1     Running   0          10s
management-frontend-6b4fb8fbb-bzx4h   1/1     Running   0          10s
management-frontend-6b4fb8fbb-kk852   1/1     Running   0          17s
management-frontend-6b4fb8fbb-rpx6k   1/1     Running   0          17s
management-frontend-6b4fb8fbb-x2lcq   1/1     Running   0          17s
```

[pendingdebugging]: https://kubernetes.io/docs/tasks/debug/debug-application/debug-pods/#debugging-pods
[nodeNameman]: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/
[controlplaneTaint]: https://kubernetes.io/docs/reference/labels-annotations-taints/#node-role-kubernetes-io-control-plane-taint
[toleration]: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/