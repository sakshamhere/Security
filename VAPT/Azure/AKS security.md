

1. Access control to API Server using Kubernetes RBAC and Azure RBAC

2. Limit access to Kubeconfig files/ Cluster configuration file using Azure RBAC

3. Secure access to API server using authorized IP address ranges in AKS

4. Encrypt data in etcd using Azure key Vault (Preview)

5. Enable Azure AD Integration

6. Custom certificate authorities to establish trust between (AKS) cluster and your workloads (Preview)

7. Certificate rotation in Azure Kubernetes Service (AKS) (enabled by default for RBAC enabled clusters)

8. Enforce built-in and custom (preview) security policies on your cluster using Azure Policy

9. AKS Network policy

10. Microsoft Defender for Containers

*******************************************************************************************************************
# Build Security

As the entry point for the Supply Chain, it is important to conduct static analysis of image builds before they are promoted down the pipeline. This includes vulnerability and compliance assessment.

# #################################################################################################################

# Registry Security

Assessing the vulnerability state of the image in the Registry will detect drift and will also catch images that didn't come from your build environment. Use Notary V2 to attach signatures to your images to ensure deployments are coming from a trusted location.

# ###################################################################################################################

# Cluster Security

- In AKS, the Kubernetes master components are part of the managed service provided, managed, and maintained by Microsoft.


# *********************************************************************************************************************

2. Access control to API Server using Kubernetes RBAC and Azure RBAC

# *********************************************************************************************************************

3. Limit access to Kubeconfig files/ Cluster configuration file using Azure RBAC

Note - A file that is used to configure access to clusters is called a kubeconfig file. 
This is a generic way of referring to configuration files. It does not mean that there is a file named kubeconfig.

When you interact with an AKS cluster using the kubectl tool, a configuration file is used that defines cluster connection information. 

This configuration file is typically stored in ~/.kube/config. Multiple clusters can be defined in this kubeconfig file. 


The az aks get-credentials command lets you get the access credentials for an AKS cluster and merges them into the kubeconfig file.

* Azure RBAC
You can use Azure role-based access control (Azure RBAC) to control access to these credentials. 
These Azure roles let you define who can retrieve the kubeconfig file, and what permissions they then have within the cluster.

The two built-in roles are:
1. Azure Kubernetes Service Cluster Admin Role
2. Azure Kubernetes Service Cluster User Role

On clusters that use Azure AD, users with the clusterUser role have an empty kubeconfig file that prompts a log in. Once logged in, users have access based on their Azure AD user or group settings. Users with the clusterAdmin role have admin access.

On clusters that do not use Azure AD, the clusterUser role has same effect of clusterAdmin role.

# *********************************************************************************************************************

4. Secure access to API server using authorized IP address ranges in AKS

In Kubernetes, the API server receives requests to perform actions in the cluster such as to create resources or scale the number of nodes,  The API server is the central way to interact with and manage a cluster. 

To improve cluster security and minimize attacks, the API server should only be accessible from a limited set of IP address ranges.

AKS provides a single-tenant cluster control plane, with a dedicated API server. By default, the API server is assigned a public IP address, and you should control access using Kubernetes role-based access control (Kubernetes RBAC) or Azure RBAC.

To secure access to the otherwise publicly accessible AKS control plane / API server, you can enable and use authorized IP ranges. 

These authorized IP ranges only allow defined IP address ranges to communicate with the API server. A request made to the API server from an IP address that isn't part of these authorized IP ranges is blocked


NOTE -
API server authorized IP address ranges aren't supported with private clusters.
API server authorized IP address ranges are only supported on the Standard SKU load balancer.
When using this feature with clusters that use Public IP per Node, those node pools with public IP per node enabled must use public IP prefixes, and those prefixes must be added as authorized ranges.

# ***********************************************************************************************************************

5. Encrypt data in etcd using Azure key Vault (Preview)

# ***********************************************************************************************************************

6. Enable Azure AD Integration

1. Azure AD Integration (Legacy) (will be deprecated in 2024)

In this users were required to create a client and server app, client app here is application registration

In this configuration, you log into an AKS cluster using an Azure AD authentication token.

a. First Create Azure AD server component

To integrate with AKS, you create and use an Azure AD application that acts as an endpoint for the identity requests.Now create a service principal for the server app and then provide permissions to service principal

b. Second Create Azure AD Client component

The second Azure AD application is used when a user logs to the AKS cluster with the Kubernetes CLI (kubectl)

2. AKS-managed Azure AD

AKS-managed Azure AD integration simplifies the Azure AD integration process Previously, users were required to create a client and server app, and required the Azure AD tenant to grant Directory Read permissions. 

When enabled, this integration allows customers to use Azure AD users, groups, or service principals as subjects in Kubernetes RBAC, see more here. This feature frees you from having to separately manage user identities and credentials for Kubernetes. However, you still have to set up and manage Azure RBAC and Kubernetes RBAC separately.

Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. Once authenticated, you can use the built-in Kubernetes role-based access control (Kubernetes RBAC) to manage access to namespaces and cluster resources based on a user's identity or group membership.

In this, the AKS resource provider manages the client and server apps for you.

# ***********************************************************************************************************************

7. Custom certificate authorities to establish trust between (AKS) cluster and your workloads (Preview)

Custom certificate authorities (CAs) allow you to establish trust between your Azure Kubernetes Service (AKS) cluster and your workloads, such as private registries, proxies, and firewalls. A Kubernetes secret is used to store the certificate authority's information, then it's passed to all nodes in the cluster.

This feature is applied per nodepool, so new and existing nodepools must be configured to enable this feature.

# ***********************************************************************************************************************

8. Certificate rotation in Azure Kubernetes Service (AKS)

If you have a RBAC-enabled cluster built after March 2022 it is enabled with certificate auto-rotation. Periodically, you may need to rotate those certificates for security or policy reasons. For example, you may have a policy to rotate all your certificates every 90 days.

Certificate auto-rotation will not be enabled by default for non-RBAC enabled AKS clusters.

# ***********************************************************************************************************************

9. Enforce built-in security policies on your cluster using Azure Policy

Create and assign a custom policy definition (preview)

# Node Security

AKS nodes are Azure virtual machines (VMs) that you manage and maintain.

Linux nodes run an optimized Ubuntu distribution using the containerd or Docker container runtime.
Windows Server nodes run an optimized Windows Server 2019 release using the containerd or Docker container runtime.

- Nodes are deployed into a private virtual network subnet, with no public IP addresses assigned. For troubleshooting and management purposes, SSH is enabled by default and only accessible using the internal IP address.

- To provide storage, the nodes use Azure Managed Disks, To improve redundancy, Azure Managed Disks are securely replicated within the Azure datacenter.

# Network Security

1. NSG/Network Security Group

- Default rules are created to allow TLS traffic to the Kubernetes API server.
- You create services with load balancers, port mappings, or ingress routes. AKS automatically modifies the network security group for traffic flow.


2. Kubernetes network policy

- To limit network traffic between pods in your cluster, AKS offers support for Kubernetes network policies
- With network policies, you can allow or deny specific network paths within the cluster based on namespaces and label selectors.
- The Network Policy feature in Kubernetes lets you define rules for ingress and egress traffic between pods in a cluster.
- All pods in an AKS cluster can send and receive traffic without limitations, by default.


* AKS Network policy
- Azure provides two ways to implement network policy. we choose a network policy option when you create an AKS cluster. The policy option can't be changed after the cluster is created:

1. Azure's own implementation, called Azure Network Policies.
2. Calico Network Policies, an open-source network and network security solution founded by Tigera

- To use Azure Network Policy, you must use the Azure CNI plug-in. Calico Network Policy could be used with either this same Azure CNI plug-in or with the Kubenet CNI plug-in

Differences between Azure and Calico policies and their capabilities
[https://docs.microsoft.com/en-us/azure/aks/use-network-policies#differences-between-azure-and-calico-policies-and-their-capabilities]

# Application security

1. Microsoft Defender for Containers

To detect and restrict cyber attacks against your applications running in your pods

- Run continual scanning to detect drift in the vulnerability state of your application and implement a "blue/green/canary" process to patch and replace the vulnerable images.