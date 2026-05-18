---
title:  "Killercoda StorageClass and Dynamic Provisioning"
date:   2026-05-17
categories: Cloud-Computing CKA
---
![CKA-LOGO](/assets/images/cka/logo.png)
I am planning to take the CKA exam in the near future. I work with Kubernetes daily at my job, but am mostly self taught, so it is probably realistic to say that I have some knowledge gaps. This blog is part of my preparation, where I go through all the scenarios on Killercoda.

# StorageClass and Dynamic Provisioning
https://killercoda.com/course-cka/scenario/domain1-storageclass-dynamic-provisioning

> Create StorageClasses and understand reclaim policies

## Create StorageClass

> There is an existing default StorageClass using the rancher.io/local-path provisioner.
Create a new StorageClass named retain-storage using the same provisioner but with reclaimPolicy: Retain and volumeBindingMode: WaitForFirstConsumer .

StorageClasses describe the different types of storage that can be used and how they are provisioned ([see here][storageclassman]). The existing class uses the `rancher.io/local-path` provisioner, which uses the local nodes disk to provision volumes ([see here][rancher]):
```
$ k get storageclass
NAME                   PROVISIONER             RECLAIMPOLICY   VOLUMEBINDINGMODE      ALLOWVOLUMEEXPANSION   AGE
local-path (default)   rancher.io/local-path   Delete          WaitForFirstConsumer   false                  15h
```

Based on the documentation ([see here][storageclassref]) we can create a new StorageClass. The `reclaimPolicy: Retain` describes that if the PVC is deleted the PV provisioned stays in the `Released` state and has to be deleted manually. `volumeBindingMode: WaitForFirstConsumer` describes that the PV should only be provisioned as soon as a Pod is started which utilizes it.
```
cat <<EOF | kubectl apply -f -
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
    name: retain-storage
provisioner: rancher.io/local-path
reclaimPolicy: Retain
volumeBindingMode: WaitForFirstConsumer
EOF
```

## Create PVC and Pod
> In Namespace storage : Create a PVC named data-pvc requesting 1Gi with access mode ReadWriteOnce using the retain-storage StorageClass.
Create a Pod named writer that mounts the PVC at /data .
Exec into the Pod and create file /data/test.txt on the volume.

We create a PVC based on the docs ([see here][pvcref]). The access mode `ReadWriteOnce` describes that the PVC can only be mounted for RW access by one node at a time. Alternatives would be `ReadWriteMany` or `ReadOnlyMany` which need to be supported by the used priovisioner.

```
$ cat << EOF | kubectl apply -f -
apiVersion: v1 
kind: PersistentVolumeClaim
metadata: 
    name: data-pvc
    namespace: storage
spec:
    accessModes:
    - ReadWriteOnce
    resources:
        requests: 
            storage: 1Gi
    storageClassName: retain-storage
EOF
```

A pod with the volume mounted can be created by using `spec.volumes` and `spec.containers[].volumeMounts`:

```
$ cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
    name: writer
    namespace: storage
spec:
    containers:
    - name: writer
      image: nginx
      volumeMounts:
      - name: data
        mountPath: "/data"
    volumes:
    - name: data
      persistentVolumeClaim:
        claimName: data-pvc
EOF
```

To create the file we can just exec into the created Pod:
```
$ k exec -n storage writer -- touch /data/test.txt
```


## Verify Data Persistence
> Delete the Pod writer and the PVC data-pvc in Namespace storage .
Then confirm that the PV still exists with status Released and the file test.txt is still on disk.


We delete the Pod and the PVC. If we then look at the PVs, we can see that the associated PV `pvc-313e5161-749e-4d3c-a5ae-42c932cd8594` has the state `Released`:
```
$ k delete pod -n storage writer
pod "writer" deleted from storage namespace
$ k delete pvc data-pvc -n storage
persistentvolumeclaim "data-pvc" deleted from storage namespace
$ k get pv   
NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS     CLAIM              STORAGECLASS     VOLUMEATTRIBUTESCLASS   REASON   AGE
pvc-313e5161-749e-4d3c-a5ae-42c932cd8594   1Gi        RWO            Retain           Released   storage/data-pvc   retain-storage   <unset>                          8m20s
```

Since the used provisioner uses local paths to provision the storage we can describe the PV to figure out where on the disk the volume is located:
```
$ k describe pv pvc-313e5161-749e-4d3c-a5ae-42c932cd8594
Name:              pvc-313e5161-749e-4d3c-a5ae-42c932cd8594
Labels:            <none>
Annotations:       local.path.provisioner/selected-node: controlplane
                   pv.kubernetes.io/provisioned-by: rancher.io/local-path
Finalizers:        [kubernetes.io/pv-protection]
StorageClass:      retain-storage
Status:            Released
Claim:             storage/data-pvc
Reclaim Policy:    Retain
Access Modes:      RWO
VolumeMode:        Filesystem
Capacity:          1Gi
Node Affinity:     
  Required Terms:  
    Term 0:        kubernetes.io/hostname in [controlplane]
Message:           
Source:
    Type:          HostPath (bare host directory volume)
    Path:          /opt/local-path-provisioner/pvc-313e5161-749e-4d3c-a5ae-42c932cd8594_storage_data-pvc
    HostPathType:  DirectoryOrCreate
Events:            <none>
```

Now we can check the path `/opt/local-path-provisioner/pvc-313e5161-749e-4d3c-a5ae-42c932cd8594_storage_data-pvc` to see if our file still exists: 
```
$ ls -al /opt/local-path-provisioner/pvc-313e5161-749e-4d3c-a5ae-42c932cd8594_storage_data-pvc
total 8
drwxrwxrwx 2 root root 4096 May 17 12:31 .
drwxr-xr-x 4 root root 4096 May 17 12:29 ..
-rw-r--r-- 1 root root    0 May 17 12:31 test.txt
```

[rancher]: https://github.com/rancher/local-path-provisioner
[storageclassref]: https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/storage-class-v1/
[storageclassman]: https://kubernetes.io/docs/concepts/storage/storage-classes/
[pvcref]: https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/persistent-volume-claim-v1/