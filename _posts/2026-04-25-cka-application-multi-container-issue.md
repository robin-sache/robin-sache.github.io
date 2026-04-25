---
title:  "Killercoda Application Multi Container Issue"
date:   2026-04-25
categories: Cloud-Computing CKA
---
![CKA-LOGO](/assets/images/cka/logo.png)
I am planning to take the CKA exam in the near future. I work with Kubernetes daily at my job, but am mostly self taught, so it is probably realistic to say that I have some knowledge gaps. This blog is part of my preparation, where I go through all the scenarios on Killercoda.

# Application Multi Container Issue
https://killercoda.com/killer-shell-cka/scenario/application-multi-container-issue
> There is a multi-container Deployment in Namespace management which seems to have issues and is not getting ready.

## Gather Logs
> Write the logs of all containers to /root/logs.log . <br> Can you see the reason for failure?

Lets check the deployment and see if we can get any useful information first from the events of one of the pods:

```
$ k -n management get deployments
NAME           READY   UP-TO-DATE   AVAILABLE   AGE
collect-data   0/2     2            0           2m39s
```

```
$ k -n management describe pod collect-data-fb68849c-pnrzd
...
Events:
  Type     Reason     Age                  From               Message
  ----     ------     ----                 ----               -------
  Normal   Scheduled  4m34s                default-scheduler  Successfully assigned management/collect-data-fb68849c-pnrzd to controlplane
  Normal   Pulling    4m32s                kubelet            spec.containers{nginx}: Pulling image "nginx:1.21.6-alpine"
  Normal   Pulled     4m29s                kubelet            spec.containers{nginx}: Successfully pulled image "nginx:1.21.6-alpine" in 3.426s (3.426s including waiting). Image size: 10170636 bytes.
  Normal   Created    4m29s                kubelet            spec.containers{nginx}: Container created
  Normal   Started    4m29s                kubelet            spec.containers{nginx}: Container started
  Normal   Pulling    4m29s                kubelet            spec.containers{httpd}: Pulling image "httpd:2.4.52-alpine"
  Normal   Pulled     4m25s                kubelet            spec.containers{httpd}: Successfully pulled image "httpd:2.4.52-alpine" in 3.656s (3.688s including waiting). Image size: 18209719 bytes.
  Normal   Created    78s (x6 over 4m25s)  kubelet            spec.containers{httpd}: Container created
  Normal   Started    78s (x6 over 4m25s)  kubelet            spec.containers{httpd}: Container started
  Normal   Pulled     78s (x5 over 4m23s)  kubelet            spec.containers{httpd}: Container image "httpd:2.4.52-alpine" already present on machine and can be accessed by the pod
  Warning  BackOff    15s (x8 over 4m22s)  kubelet            spec.containers{httpd}: Back-off restarting failed container httpd in pod collect-data-fb68849c-pnrzd_management(ae544489-d7c8-4af4-8793-afe8b2c03007)
```

We see that both the `httpd` and `nginx` container start running, but then the `httpd` container fails. Lets look at the logs to see if we can gather any useful information:

```
$ k -n management logs collect-data-fb68849c-pnrzd
/docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform configuration
/docker-entrypoint.sh: Looking for shell scripts in /docker-entrypoint.d/
/docker-entrypoint.sh: Launching /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh
10-listen-on-ipv6-by-default.sh: info: Getting the checksum of /etc/nginx/conf.d/default.conf
10-listen-on-ipv6-by-default.sh: info: Enabled listen on IPv6 in /etc/nginx/conf.d/default.conf
/docker-entrypoint.sh: Launching /docker-entrypoint.d/20-envsubst-on-templates.sh
/docker-entrypoint.sh: Launching /docker-entrypoint.d/30-tune-worker-processes.sh
/docker-entrypoint.sh: Configuration complete; ready for start up
2026/04/25 13:24:41 [notice] 1#1: using the "epoll" event method
2026/04/25 13:24:41 [notice] 1#1: nginx/1.21.6
2026/04/25 13:24:41 [notice] 1#1: built by gcc 10.3.1 20211027 (Alpine 10.3.1_git20211027) 
2026/04/25 13:24:41 [notice] 1#1: OS: Linux 6.8.0-110-generic
2026/04/25 13:24:41 [notice] 1#1: getrlimit(RLIMIT_NOFILE): 1024:524288
2026/04/25 13:24:41 [notice] 1#1: start worker processes
2026/04/25 13:24:41 [notice] 1#1: start worker process 31
```
Using the above method we only see the logs of the running `nginx` container. Lets look at the help page of the `logs` command to see how we can get to the `httpd` logs. The most interesting arguments are `--all-containers` and `--all-pods`:

```
$ k logs -h
...
Examples:
...
  # Return snapshot logs from all pods in the deployment nginx
  kubectl logs deployment/nginx --all-pods=true
...
Options:
    --all-containers=false:
        Get all containers' logs in the pod(s).

    --all-pods=false:
        Get logs from all pod(s). Sets prefix to true.
    
    --prefix=false:
        Prefix each log line with the log source (pod name and container name)
...
```

I have difficulties seeing what the difference is, but after testing them I understand now. `--all-pods` gives us the logs of all running containers of all pods of a deployment:


```
$ k -n management logs deployments/collect-data --all-pods
[pod/collect-data-fb68849c-pnrzd/nginx] /docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform configuration
[pod/collect-data-fb68849c-pnrzd/nginx] /docker-entrypoint.sh: Looking for shell scripts in /docker-entrypoint.d/
[pod/collect-data-fb68849c-pnrzd/nginx] /docker-entrypoint.sh: Launching /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh
[pod/collect-data-fb68849c-pnrzd/nginx] 10-listen-on-ipv6-by-default.sh: info: Getting the checksum of /etc/nginx/conf.d/default.conf
[pod/collect-data-fb68849c-pnrzd/nginx] 10-listen-on-ipv6-by-default.sh: info: Enabled listen on IPv6 in /etc/nginx/conf.d/default.conf
[pod/collect-data-fb68849c-pnrzd/nginx] /docker-entrypoint.sh: Launching /docker-entrypoint.d/20-envsubst-on-templates.sh
[pod/collect-data-fb68849c-pnrzd/nginx] /docker-entrypoint.sh: Launching /docker-entrypoint.d/30-tune-worker-processes.sh
[pod/collect-data-fb68849c-pnrzd/nginx] /docker-entrypoint.sh: Configuration complete; ready for start up
[pod/collect-data-fb68849c-pnrzd/nginx] 2026/04/25 13:24:41 [notice] 1#1: using the "epoll" event method
[pod/collect-data-fb68849c-pnrzd/nginx] 2026/04/25 13:24:41 [notice] 1#1: nginx/1.21.6
[pod/collect-data-fb68849c-pnrzd/nginx] 2026/04/25 13:24:41 [notice] 1#1: built by gcc 10.3.1 20211027 (Alpine 10.3.1_git20211027) 
[pod/collect-data-fb68849c-pnrzd/nginx] 2026/04/25 13:24:41 [notice] 1#1: OS: Linux 6.8.0-110-generic
[pod/collect-data-fb68849c-pnrzd/nginx] 2026/04/25 13:24:41 [notice] 1#1: getrlimit(RLIMIT_NOFILE): 1024:524288
[pod/collect-data-fb68849c-pnrzd/nginx] 2026/04/25 13:24:41 [notice] 1#1: start worker processes
[pod/collect-data-fb68849c-pnrzd/nginx] 2026/04/25 13:24:41 [notice] 1#1: start worker process 31
[pod/collect-data-fb68849c-xm978/nginx] /docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform configuration
[pod/collect-data-fb68849c-xm978/nginx] /docker-entrypoint.sh: Looking for shell scripts in /docker-entrypoint.d/
[pod/collect-data-fb68849c-xm978/nginx] /docker-entrypoint.sh: Launching /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh
[pod/collect-data-fb68849c-xm978/nginx] 10-listen-on-ipv6-by-default.sh: info: Getting the checksum of /etc/nginx/conf.d/default.conf
[pod/collect-data-fb68849c-xm978/nginx] 10-listen-on-ipv6-by-default.sh: info: Enabled listen on IPv6 in /etc/nginx/conf.d/default.conf
[pod/collect-data-fb68849c-xm978/nginx] /docker-entrypoint.sh: Launching /docker-entrypoint.d/20-envsubst-on-templates.sh
[pod/collect-data-fb68849c-xm978/nginx] /docker-entrypoint.sh: Launching /docker-entrypoint.d/30-tune-worker-processes.sh
[pod/collect-data-fb68849c-xm978/nginx] /docker-entrypoint.sh: Configuration complete; ready for start up
[pod/collect-data-fb68849c-xm978/nginx] 2026/04/25 13:24:41 [notice] 1#1: using the "epoll" event method
[pod/collect-data-fb68849c-xm978/nginx] 2026/04/25 13:24:41 [notice] 1#1: nginx/1.21.6
[pod/collect-data-fb68849c-xm978/nginx] 2026/04/25 13:24:41 [notice] 1#1: built by gcc 10.3.1 20211027 (Alpine 10.3.1_git20211027) 
[pod/collect-data-fb68849c-xm978/nginx] 2026/04/25 13:24:41 [notice] 1#1: OS: Linux 6.8.0-110-generic
[pod/collect-data-fb68849c-xm978/nginx] 2026/04/25 13:24:41 [notice] 1#1: getrlimit(RLIMIT_NOFILE): 1024:524288
[pod/collect-data-fb68849c-xm978/nginx] 2026/04/25 13:24:41 [notice] 1#1: start worker processes
[pod/collect-data-fb68849c-xm978/nginx] 2026/04/25 13:24:41 [notice] 1#1: start worker process 32
```

`--all-containers` gives us the logs of all containers inside one specific pod:
```
$  k -n management logs deployments/collect-data --all-containers
Found 2 pods, using pod/collect-data-fb68849c-bzngk
AH00558: httpd: Could not reliably determine the server's fully qualified domain name, using 192.168.0.110. Set the 'ServerName' directive globally to suppress this message
(98)Address in use: AH00072: make_sock: could not bind to address [::]:80
(98)Address in use: AH00072: make_sock: could not bind to address 0.0.0.0:80
no listening sockets available, shutting down
AH00015: Unable to open logs
/docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform configuration
/docker-entrypoint.sh: Looking for shell scripts in /docker-entrypoint.d/
/docker-entrypoint.sh: Launching /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh
10-listen-on-ipv6-by-default.sh: info: Getting the checksum of /etc/nginx/conf.d/default.conf
10-listen-on-ipv6-by-default.sh: info: Enabled listen on IPv6 in /etc/nginx/conf.d/default.conf
/docker-entrypoint.sh: Launching /docker-entrypoint.d/20-envsubst-on-templates.sh
/docker-entrypoint.sh: Launching /docker-entrypoint.d/30-tune-worker-processes.sh
/docker-entrypoint.sh: Configuration complete; ready for start up
2026/04/25 13:52:06 [notice] 1#1: using the "epoll" event method
2026/04/25 13:52:06 [notice] 1#1: nginx/1.21.6
2026/04/25 13:52:06 [notice] 1#1: built by gcc 10.3.1 20211027 (Alpine 10.3.1_git20211027) 
2026/04/25 13:52:06 [notice] 1#1: OS: Linux 6.8.0-110-generic
2026/04/25 13:52:06 [notice] 1#1: getrlimit(RLIMIT_NOFILE): 1024:524288
2026/04/25 13:52:06 [notice] 1#1: start worker processes
2026/04/25 13:52:06 [notice] 1#1: start worker process 33
```

So the second option is what we want. We redirect the logs into the `/root/logs.log` file using `>`:

```
$ k -n management logs deployments/collect-data --all-containers > /root/logs.log
```

When analyzing the log files we see the following error messages from the `httpd` container:

```
(98)Address in use: AH00072: make_sock: could not bind to address [::]:80
(98)Address in use: AH00072: make_sock: could not bind to address 0.0.0.0:80
no listening sockets available, shutting down
```

Both the `httpd` and `nginx` container try to bind to port 80. Since they are in the same pod and share a network stack only one of the can actually use the port. The `nginx` container binds it faster which leaves the `httpd` container failing.

## Fix the Deployment

> Fix the Deployment in Namespace management where both containers try to listen on port 80. <br> Remove one container.

We do that by commenting one of the containers. If both containers were needed a different solution would be to reconfigure one of them to bind to a different port.
```
$ k -n management edit deployment collect-data
      containers:
#      - image: nginx:1.21.6-alpine
#        imagePullPolicy: IfNotPresent
#        name: nginx
#        resources: {}
#        terminationMessagePath: /dev/termination-log
#        terminationMessagePolicy: File
      - image: httpd:2.4.52-alpine
        imagePullPolicy: IfNotPresent
        name: httpd
        resources: {}
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
```

After the change the pod is now in the state `Running`:
```
$ k -n management get pods  
NAME                            READY   STATUS    RESTARTS   AGE
collect-data-6c49c8f977-f7rrr   1/1     Running   0          11s
collect-data-6c49c8f977-zxrnt   1/1     Running   0          9s
```