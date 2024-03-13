Azure Kubernetes Service

* Kubernetes masters are managed by Azure, you only manage and maintain the agent nodes. 
 
* AKS is free; you only pay for the agent nodes within your clusters, not for the masters.

* You can create an AKS cluster using:

- The Azure CLI
- The Azure portal
- Azure PowerShell
- Using Azure Resource Manager templates, Bicep and Terraform.
***********************************************************************************************************************

# Core Components

1. Control Pane
2. Nodes and node pools and Node Selectors
3. Pod
4. Deployments and YAML manifests
5. Statefulset and Daemonset
6. Namespaces

# Other
1. Kubernetes RBAC
2. Kubenet and Azure CNI

***********************************************************************************************************************
1. Control Pane

- A managed Azure resource abstracted from the user

The Control Pane includes APIserver, etcd, scheduleer and Conrol Manager

2. Nodes and node pools and Node Selectors

- To run your applications and supporting services, you need a Kubernetes node. 

An AKS cluster has at least one node, an Azure virtual machine (VM) that runs the Kubernetes node components (kubelet, kube-proxy) and container runtime.

The Azure VM size for your nodes defines the storage CPUs, memory, size, and type available (such as high-performance SSD or regular HDD)

In AKS, the VM image for your cluster's nodes is based on Ubuntu Linux or Windows Server 2019.

When you create an AKS cluster or scale out the number of nodes, the Azure platform automatically creates and configures the requested number of VMs

If you need advanced configuration and control on your Kubernetes node container runtime and OS, you can deploy a self-managed cluster using Cluster API Provider Azure.

# * Node pools

Nodes of the same configuration are grouped together into node pools. A Kubernetes cluster contains at least one node pool. 

The initial number of nodes and size are defined when you create an AKS cluster, which creates a default node pool. 

This default node pool in AKS contains the underlying VMs that run your agent nodes.

# Node Selectors

In an AKS cluster with multiple node pools, you may need to tell the Kubernetes Scheduler which node pool to use for a given resource.

For example, ingress controllers shouldn't run on Windows Server nodes.

3. Pod

Kubernetes uses pods to run an instance of your application. A pod represents a single instance of your application.

A Pod (as in a pod of whales or pea pod) is a group of one or more containers, with shared storage and network resources, and a specification for how to run the containers

Pod is managed by Deployment, Statefulset a DaemonSet

4. Deployments and YAML manifests

A deployment represents identical pods managed by the Kubernetes Deployment Controller. 

A deployment defines the number of pod replicas to create.

The Deployment Controller:

Drains and terminates a given number of replicas.
Creates replicas from the new deployment definition.
Continues the process until all replicas in the deployment are updated.

Most stateless applications in AKS should use the deployment model rather than scheduling individual pods. When scheduled individually, pods aren't restarted if they encounter a problem, and aren't rescheduled on healthy nodes if their current node encounters a problem.

5. Statefulset and Daemonset

Using the Kubernetes Scheduler, the Deployment Controller runs replicas on any available node with available resources. While this approach may be sufficient for stateless applications, The Deployment Controller is not ideal for stateful applications

* StatefulSet

StatefulSets maintain the state of applications beyond an individual pod lifecycle, such as storage.

For stateful applications, like those that include database components, you can use StatefulSets.

Like deployments, a StatefulSet creates and manages at least one identical pod. Replicas in a StatefulSet follow a graceful, sequential approach to deployment, scale, upgrade, and termination

The naming convention, network names, and storage persist as replicas are rescheduled with a StatefulSet.

* DaemonSet

Replicas in a StatefulSet are scheduled and run across any available node in an AKS cluster.

For specific log collection or monitoring, you may need to run a pod on all, or selected, nodes,  DaemonSet Controller ensures that each node specified runs an instance of the pod.

The DaemonSet Controller can schedule pods on nodes early in the cluster boot process, before the default Kubernetes scheduler has started. This ability ensures that the pods in a DaemonSet are started before traditional pods in a Deployment or StatefulSet are scheduled.

Like StatefulSets, a DaemonSet is defined as part of a YAML definition using kind: DaemonSet.

Use a Deployment for stateless services, like frontends, where scaling up and down the number of replicas and rolling out updates are more important than controlling exactly which host the Pod runs on. Use a DaemonSet when it is important that a copy of a Pod always run on all or certain hosts

6. Namespaces

Kubernetes resources, such as pods and deployments, are logically grouped into a namespace to divide an AKS cluster and restrict create, view, or manage access to resources.   

********************************************************************************************************************

# Access, security, and monitoring

7. Kubernetes RBAC

To limit access to cluster resources, AKS supports Kubernetes RBAC. Kubernetes RBAC controls access and permissions to Kubernetes resources and namespaces.

- You assign users or user groups permission to create and modify resources or view logs from running application workloads.
- You can scope permissions to a single namespace or across the entire AKS cluster.
- You create roles to define permissions, and then assign those roles to users with role bindings.



*********************************************************************************************************************

# Kubenet
By default, AKS clusters use kubenet and an Azure virtual network and subnet are created for you.

With kubenet
- nodes get an IP address from the Azure virtual network subnet.
- Pods receive an IP address from a logically different address space to the Azure virtual network subnet of the nodes
- Network address translation (NAT) is then configured so that the pods can reach resources on the Azure virtual network.

This approach greatly reduces the number of IP addresses that you need to reserve in your network space for pods to use.

# Azure CNI Azure Container Networking Interface (CNI)

- With Azure Container Networking Interface (CNI), every pod gets an IP address from the subnet and can be accessed directly
- These IP addresses must be unique across your network space, and must be planned in advance. 
- Each node has a configuration parameter for the maximum number of pods that it supports. The equivalent number of IP addresses per node are then reserved up front for that node

This approach requires more planning, and often leads to IP address exhaustion or the need to rebuild clusters in a larger subnet as your application demands grow.

*************************************************************************************************************************
