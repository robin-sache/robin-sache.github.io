---
title:  "Killercoda Deployment Scaling Issue"
date:   2026-05-16
categories: Cloud-Computing CKA
---
![CKA-LOGO](/assets/images/cka/logo.png)
I am planning to take the CKA exam in the near future. I work with Kubernetes daily at my job, but am mostly self taught, so it is probably realistic to say that I have some knowledge gaps. This blog is part of my preparation, where I go through all the scenarios on Killercoda.

# Deployment Scaling Issue
https://killercoda.com/course-cka/scenario/domain4-deployment-scaling

## Create HPA for Deployment
> A Deployment api-gateway is running in Namespace team-api with 3 replicas.
Create an HPA named api-gateway for this Deployment that scales between 10 and 20 replicas based on 60% average CPU utilisation.

First let's again check that we have the specified deployment:

```
$ k get deployments api-gateway -n team-api
NAME          READY   UP-TO-DATE   AVAILABLE   AGE
api-gateway   3/3     3            3           3m26s
```

In the documentation for the HorizontalPodAutoscaler (HPA) we learn, that they can be used to automatically update a workload resource based on demand. In this case horizontal means, that we create more pods to better spread out demand. In constrast a VerticalPodAutoscaler (VPA) would assign more resources to existing pods to handle load ([see here][hpaman] & [see here][vpaman]). In the HPA Documentation we also learn, that there is a specific `kubectl autoscale` command to simplify creation of HPAs. Using this command ([see here][autoscale]) we can specify that the deployment `api-gateway` should scale between minimum 10 and maximum 20 pods (`--min 10` & `--max 20`) to stay within the average cpu utilization of 60% (`--cpu 60%`):

```
$ k autoscale  -n team-api deployment api-gateway --min=10 --max=20 --cpu=60%
```

This now creates a new HPA, which looks as following:
```
$ k get hpa -n team-api
NAME          REFERENCE                TARGETS              MINPODS   MAXPODS   REPLICAS   AGE
api-gateway   Deployment/api-gateway   cpu: <unknown>/60%   10        20        3          17s


$ k get hpa -n team-api api-gateway -oyaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-gateway
  namespace: team-api
spec:
  maxReplicas: 20
  metrics:
  - resource:
      name: cpu
      target:
        averageUtilization: 60
        type: Utilization
    type: Resource
  minReplicas: 10
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api-gateway
```

And if we look at the deployment, we can see that the number of desired replicas shot up to 10:

```
$ k get deployments api-gateway -n team-api
NAME          READY   UP-TO-DATE   AVAILABLE   AGE
api-gateway   5/10    5            5           11m
```

## Fix the Scaling Issue

> The HPA should have scaled the Deployment to at least 10 replicas, but not all Pods are running.
Investigate why the Deployment cannot reach the desired replica count.
Fix the issue so that the Namespace can run up to the HPA's maximum of 20 Pods.

When looking at the deployment we see, that never more that 5 pods end up in the ready state:
```
$ k get deployments api-gateway -n team-api
NAME          READY   UP-TO-DATE   AVAILABLE   AGE
api-gateway   5/10    5            5           11m
```
Neither the Deployments nor the HPAs events give us any indication why this could be the case:
```
k describe deployments api-gateway -n team-api
...
Events:
  Type    Reason             Age   From                   Message
  ----    ------             ----  ----                   -------
  Normal  ScalingReplicaSet  11m   deployment-controller  Scaled up replica set api-gateway-bdb7449d9 from 0 to 3
  Normal  ScalingReplicaSet  76s   deployment-controller  Scaled up replica set api-gateway-bdb7449d9 from 3 to 10
```

```
$ k describe hpa api-gateway -n team-api
...
Events:
  Type    Reason             Age   From                       Message
  ----    ------             ----  ----                       -------
  Normal  SuccessfulRescale  4m    horizontal-pod-autoscaler  New size: 10; reason: Current number of replicas below Spec.MinReplicas
```

However if we look at the ReplicaSets event which is attached to the Deployment, we can see an error `Error creating: pods "[...]" is forbidden: exceeded quota: ns-quota`:
```
$ k get rs -n team-api
NAME                    DESIRED   CURRENT   READY   AGE
api-gateway-bdb7449d9   10        5         5       17m

$ k describe rs  api-gateway-bdb7449d9 -n team-api
...
Events:
  Type     Reason            Age                   From                   Message
  ----     ------            ----                  ----                   -------
  Normal   SuccessfulCreate  18m                   replicaset-controller  Created pod: api-gateway-bdb7449d9-dpk44
  Normal   SuccessfulCreate  18m                   replicaset-controller  Created pod: api-gateway-bdb7449d9-4zp5h
  Normal   SuccessfulCreate  18m                   replicaset-controller  Created pod: api-gateway-bdb7449d9-729f8
  Normal   SuccessfulCreate  8m                    replicaset-controller  Created pod: api-gateway-bdb7449d9-kzd9v
  Warning  FailedCreate      8m                    replicaset-controller  Error creating: pods "api-gateway-bdb7449d9-dkvbh" is forbidden: exceeded quota: ns-quota, requested: pods=1, used: pods=5, limited: pods=5
  Normal   SuccessfulCreate  8m                    replicaset-controller  Created pod: api-gateway-bdb7449d9-ffqw9
  Warning  FailedCreate      8m                    replicaset-controller  Error creating: pods "api-gateway-bdb7449d9-lc4lw" is forbidden: exceeded quota: ns-quota, requested: pods=1, used: pods=5, limited: pods=5
  Warning  FailedCreate      8m                    replicaset-controller  Error creating: pods "api-gateway-bdb7449d9-hkdnm" is forbidden: exceeded quota: ns-quota, requested: pods=1, used: pods=5, limited: pods=5
  Warning  FailedCreate      8m                    replicaset-controller  Error creating: pods "api-gateway-bdb7449d9-ln8cb" is forbidden: exceeded quota: ns-quota, requested: pods=1, used: pods=5, limited: pods=5
  Warning  FailedCreate      8m                    replicaset-controller  Error creating: pods "api-gateway-bdb7449d9-6qmft" is forbidden: exceeded quota: ns-quota, requested: pods=1, used: pods=5, limited: pods=5
  Warning  FailedCreate      8m                    replicaset-controller  Error creating: pods "api-gateway-bdb7449d9-bbqk8" is forbidden: exceeded quota: ns-quota, requested: pods=1, used: pods=5, limited: pods=5
  Warning  FailedCreate      8m                    replicaset-controller  Error creating: pods "api-gateway-bdb7449d9-wg9nd" is forbidden: exceeded quota: ns-quota, requested: pods=1, used: pods=5, limited: pods=5
  Warning  FailedCreate      7m59s                 replicaset-controller  Error creating: pods "api-gateway-bdb7449d9-v4ccw" is forbidden: exceeded quota: ns-quota, requested: pods=1, used: pods=5, limited: pods=5
  Warning  FailedCreate      7m58s                 replicaset-controller  Error creating: pods "api-gateway-bdb7449d9-r9cwg" is forbidden: exceeded quota: ns-quota, requested: pods=1, used: pods=5, limited: pods=5
  Warning  FailedCreate      3m8s (x8 over 7m57s)  replicaset-controller  (combined from similar events): Error creating: pods "api-gateway-bdb7449d9-wl8l6" is forbidden: exceeded quota: ns-quota, requested: pods=1, used: pods=5, limited: pods=5
```

Reading up on the documentation again we can find ResourceQuotas, which define hard resource limits on a namespace level. This could be CPU or memory resources or also hard limits of how many pods are allowed to be started ([see here][quotaref] & [see here][quotaman]). Checking if we have a ResourceQuota we find one named `ns-quota` which limits the number of pods to 5:
```
$ k get resourcequota -A
NAMESPACE   NAME       REQUEST     LIMIT                 AGE
team-api    ns-quota   pods: 5/5   limits.cpu: 250m/10   22m

$ k get resourcequota -n team-api ns-quota -oyaml
apiVersion: v1
kind: ResourceQuota
metadata:
  creationTimestamp: "2026-05-16T09:52:32Z"
  name: ns-quota
  namespace: team-api
  resourceVersion: "6701"
  uid: 45220fd6-3aad-4ba7-af3e-9e93c2f8a3ef
spec:
  hard:
    limits.cpu: "10"
    pods: "5"
status:
  hard:
    limits.cpu: "10"
    pods: "5"
  used:
    limits.cpu: 250m
    pods: "5"
```

To fix this we can just increase the limit to 20:
```
k edit resourcequota -n team-api ns-quota -oyaml
apiVersion: v1
kind: ResourceQuota
metadata:
  creationTimestamp: "2026-05-16T09:52:32Z"
  name: ns-quota
  namespace: team-api
  resourceVersion: "8700"
  uid: 45220fd6-3aad-4ba7-af3e-9e93c2f8a3ef
spec:
  hard:
    limits.cpu: "10"
    pods: "20"
status:
  hard:
    limits.cpu: "10"
    pods: "20"
  used:
    limits.cpu: 250m
    pods: "5"
```

After recreating the ReplicaSet we can now see, that the expected 10 replicas are started:

```
$ k delete rs  api-gateway-bdb7449d9 -n team-api
replicaset.apps "api-gateway-bdb7449d9" deleted from team-api namespace
root@controlplane:~$ k get rs -n team-api
NAME                    DESIRED   CURRENT   READY   AGE
api-gateway-bdb7449d9   10        10        0       8s
root@controlplane:~$ k get rs -n team-api
NAME                    DESIRED   CURRENT   READY   AGE
api-gateway-bdb7449d9   10        10        6       11s
root@controlplane:~$ k get rs -n team-api
NAME                    DESIRED   CURRENT   READY   AGE
api-gateway-bdb7449d9   10        10        10      12s
```


## Trigger HPA Scale Up

> Cause enough CPU load on the Pods so that the HPA scales the Deployment up by at least one replica. 
The Pods run image polinux/stress which means you can run stress --cpu 1 in them to cause CPU load.

We can do this by executing the stress binary in a few of the containers in the background. If we then check the resource consumption of the pods using `kubectl top` we can see, that they hit their cpu limit of 50m and new pods are already being started: 

```
$(k exec -n team-api api-gateway-bdb7449d9-dgj2n -- stress --cpu 1) &
$(k exec -n team-api api-gateway-bdb7449d9-bqtms -- stress --cpu 1) &
$(k exec -n team-api api-gateway-bdb7449d9-dgj2n -- stress --cpu 1) &
$(k exec -n team-api api-gateway-bdb7449d9-j78fk -- stress --cpu 1) &

$ k top pod -n team-api
NAME                          CPU(cores)   MEMORY(bytes)   
api-gateway-bdb7449d9-8qcjj   51m          0Mi             
api-gateway-bdb7449d9-bqtms   50m          0Mi             
api-gateway-bdb7449d9-dgj2n   46m          0Mi             
api-gateway-bdb7449d9-j78fk   21m          0Mi             
api-gateway-bdb7449d9-k85nc   0m           0Mi             
api-gateway-bdb7449d9-mgww4   0m           0Mi             
api-gateway-bdb7449d9-pwt5j   0m           0Mi             
api-gateway-bdb7449d9-qqrlt   0m           0Mi             
api-gateway-bdb7449d9-rmbkj   0m           0Mi             
api-gateway-bdb7449d9-s5txg   2m           0Mi             
api-gateway-bdb7449d9-w8f2m   0m           0Mi             
api-gateway-bdb7449d9-z9qnp   0m           0Mi             
api-gateway-bdb7449d9-zxgqv   0m           0Mi   
```

In the events of the HPA we can also see the Rescale event:
```
$ k describe hpa api-gateway -n team-api
...
 Normal   SuccessfulRescale             104s   horizontal-pod-autoscaler  New size: 13; reason: cpu resource utilization (percentage of request) above target
 Normal   SuccessfulRescale             89s    horizontal-pod-autoscaler  New size: 20; reason: cpu resource utilization (percentage of request) above target
```

[autoscale]: https://kubernetes.io/docs/reference/kubectl/generated/kubectl_autoscale/
[hpaman]: https://kubernetes.io/docs/concepts/workloads/autoscaling/horizontal-pod-autoscale/
[vpaman]: https://kubernetes.io/docs/concepts/workloads/autoscaling/vertical-pod-autoscale/
[quotaman]: https://kubernetes.io/docs/concepts/policy/resource-quotas/
[quotaref]: https://kubernetes.io/docs/reference/kubernetes-api/policy-resources/resource-quota-v1/