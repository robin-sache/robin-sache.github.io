---
title:  "Kubernetes Setup with Bitwarden, Cryptpad and Monitoring"
date:   2023-12-08
categories: Cloud-Computing Schoolwork
---

During my exchange semester I took the course "Cloud Infrastructure", which focused on giving an introduction to Kubernetes and applying the aquired knowledge in practice.

During the final project of the course I set up a new Kubernetes cluster using Terraform and kubeadm. I configured Rook as a storage provider and ArgoCD to facilitate continuous deployments directly from the GitLab repository. On the cluster a monitoring stack was set up consisting of Blackbox Exporter, Prometheus, Alert Manager, Node Exporter, Grafana and Thanos. Bitwarden and Cryptpad were deployed on the cluster, which both had to be translated from Docker-Compose files to Kubernetes manifests, since Helm wasn't allowed.

**Read the full report [here](/assets/pdfs/IKT210_Final_Project_NoAccessPage.pdf)**

