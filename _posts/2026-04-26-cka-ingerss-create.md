---
title:  "Killercoda Ingress Create"
date:   2026-04-25
categories: Cloud-Computing CKA
---
![CKA-LOGO](/assets/images/cka/logo.png)

_Killercoda changed their subscription model while I was working on the courses. This specific task no longer exists and was replaced with the a Gateway API Exercise_


I am planning to take the CKA exam in the near future. I work with Kubernetes daily at my job, but am mostly self taught, so it is probably realistic to say that I have some knowledge gaps. This blog is part of my preparation, where I go through all the scenarios on Killercoda.

# Ingress Create
https://killercoda.com/killer-shell-cka/scenario/ingress-create

## Creating services

> There are two existing Deployments in Namespace world which should be made accessible via an Ingress.

> First: create ClusterIP Services for both Deployments for port 80 . The Services should have the same name as the Deployments.

Lets check the existing deployments in the specified `world` namespace for deployments:

```
$ k get deploy -n world
NAME     READY   UP-TO-DATE   AVAILABLE   AGE
asia     2/2     2            2           5m38s
europe   2/2     2            2           5m38s
```

Since we attach a service to a Pod using a `LabelSelector` we need to figure out what labels are added to the pods:
```
$ k get deploy asia -oyaml -n world
...
  labels:
    app: asia
...
$ k get deploy europe -oyaml -n world
...
  labels:
    app: europe
...
```


Now based on the Service documentation we can write new services for both Deployments. ([see here][serviceman]) & ([see here][serviceapi]). `port` is the port that the service exposes, `targetPort` is the port on the pod to attach to, which defaults to be the same as `port` if not specified and `protocol` defaults to `TCP`. The `type` ClusterIP specifies that a cluster internal IP address should be allocated.
```
apiVersion: v1
kind: Service
metadata:
  name: asia
  namespace: world
spec:
  selector:
    app: asia
  # type: ClusterIP # default behaviour
  ports:
    - port: 80
      # targetPort: 80 # default behaviour
      # protocol: TCP # default behaviour
---
apiVersion: v1
kind: Service
metadata:
  name: europe
  namespace: world
spec:
  selector:
    app: europe
  ports:
    - port: 80
```

## Create Ingress for existing Services
> The Nginx Ingress Controller has been installed. <br>
Create a new Ingress resource called world for domain name world.universe.mine . The domain points to the K8s Node IP via /etc/hosts. <br>
The Ingress resource should have two routes pointing to the existing Services: <br><br>
http://world.universe.mine:30080/europe/ <br>
and <br>
http://world.universe.mine:30080/asia/ 

_Important to note is, that it is recommended to switch to Gateway API and that Ingress Nginx is deprecated as of March 2026._

Let's check if we have an ingress class and the ingress-nginx controller is running:
```
$ k get ingressclass
NAME    CONTROLLER             PARAMETERS   AGE
nginx   k8s.io/ingress-nginx   <none>       14m
```

```
$ k get svc -n ingress-nginx
NAME                                 TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)                      AGE
ingress-nginx-controller             NodePort    10.105.210.46   <none>        80:30080/TCP,443:30443/TCP   17m
ingress-nginx-controller-admission   ClusterIP   10.102.85.132   <none>        443/TCP                      17m
```

Let's also validate the claim, that the domains are configured in the `/etc/hosts` file:

```
$ cat /etc/hosts
127.0.0.1 localhost
...
127.0.0.1 host01
127.0.0.1 controlplane
172.30.1.2 world.universe.mine
```

We can now write an Ingress manifest based on the documentation ([see here][ingressman]) & ([see here][ingressapi]). 

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: 
  name: world
  namespace: world
spec:
  ingressClassName: nginx
  rules:
  - host: "world.universe.mine"
    http:
      paths:
      - pathType: Prefix
        path: "/europe"
        backend:
          service:
            name: europe
            port:
              number: 80
      - pathType: Prefix
        path: "/asia"
        backend:
          service:
            name: asia
            port:
              number: 80
```

Lets curl the domain name with the patchPrefix to see if we get a reply from the correct pods:

```
$ curl http://world.universe.mine:30080/europe/
hello, you reached EUROPE
root@controlplane:~$ curl http://world.universe.mine:30080/asia/
hello, you reached ASIA
```


[serviceman]: https://kubernetes.io/docs/concepts/services-networking/service/
[serviceapi]: https://kubernetes.io/docs/reference/kubernetes-api/service-resources/service-v1/
[ingressman]: https://kubernetes.io/docs/concepts/services-networking/ingress/
[ingressapi]: https://kubernetes.io/docs/reference/kubernetes-api/service-resources/ingress-v1/

