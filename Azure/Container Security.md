Container Security best practises

1. Building own Secure image and avoid using public images, Using Smaller base images

2. Image signing or fingerprinting                                  - Azure Container Registry Docker Content Trust model

3. Scanning container images and container registries                - Defender for Cloud

4. Using Private container registry                                  - Azure Container Registry, Docker Trusted Registry

5. Secure access to registry                           - Azure RBAC, Azure Key Vault

6. Enforcing least privileges in runtime

7. Ensure container to access only safe listed files and executables

8. Periodic auditing of images deployed in production

9. Enforce network segmentation on running containers   - Azure Virtual network, Firewall, WAF

10. Monitor and log container activity and user access      - Azure Monitor Container Insights, other from marketplace


# Building own Secure image and avoid using public images

- choose smaller base images
- eliminate unnecessory dependencies / libraries and untrusted sources while developing image
- when building the image we should create a service user and run the application with that user instead of using root user

When a vulnerability surfaces in a self-built container image, customers can find a quicker path to a resolution. With a public image, customers would need to find the root of a public image to fix it or get another secure image from the publisher.

# Image signing or fingerprinting     

Image signing or fingerprinting can provide a chain of custody that enables you to verify the integrity of the containers. 

Azure Container Registry supports Docker's content trust model, which allows image publishers to sign images that are pushed to a registry, and image consumers to pull only signed images.

# Scanning container images and registry/repository

- Azure Container Registry optionally integrates with Microsoft Defender for Cloud to automatically scan all Linux images pushed to a registry.

- there are various tool that scan for vulnerabilities in image like Synk, Sysdig etc

we can do this scanning in CI CD pipeline just after the image is build before pushing it to repository
Continuous integration (CI) pipeline with integrated security scanning to build secure images and push them to your private registry

A CI pipeline failure ensures that vulnerable images are not pushed to the private registry that’s used for production workload deployments. It also automates image security scanning if there’s a significant number of images.

we should also scan images in repository as they might have vulnerability that might not have updated in scanner database

# Use Private container registry

A publicly available container image does not guarantee security. Container images consist of multiple software layers, and each software layer might have vulnerabilities. 

To help reduce the threat of attacks, you should store and retrieve images from a private registry, such as Azure Container Registry or other like Docker Trusted Registry. 

# Secure access to registry 

- Privilaged access management by RBAC
In addition to providing a managed private registry, Azure Container Registry supports service principal-based authentication through Azure Active Directory for basic authentication flows. This authentication includes role-based access for read-only (pull), write (push), and other permissions.

- Protect Credentials
Containers can spread across several clusters and Azure regions. So, you must secure credentials required for logins or API access, such as passwords or tokens

Azure Key Vault is a cloud service that safeguards encryption keys and secrets (such as certificates, connection strings, and passwords) for containerized applications.

# Enforce least privileges in runtime

Ensuring that containers operate with the lowest privileges and access required to get the job done reduces your exposure to risk.

Privileged containers run as root. If a malicious user or workload escapes in a privileged container, the container will then run as root on that system.

when building the image we should create a service user and run the application with that user instead of using root user

# Ensure container to access only safe listed files and executables

Limiting containers so they can access or run only preapproved or safe listed files and executables is a proven method of limiting exposure to risk.

A safe list not only reduces the attack surface but can also provide a baseline for anomalies and prevent the use cases of the "noisy neighbor" and container breakout scenarios.


# Periodic auditing of images deployed in production

A thoroughly scanned image deployed in production is not guaranteed to be up-to-date for the lifetime of the application. Security vulnerabilities might be reported for layers of the image that were not previously known or were introduced after the production deployment.

# Enforce network segmentation on running containers

To help protect containers in one subnet from security risks in another subnet, maintain network segmentation (or nano-segmentation) or segregation between running containers. 

Maintaining network segmentation may also be necessary to use containers in industries that are required to meet compliance mandates.

# Monitor container activity and user access

- Azure monitor container insights

Container insights is a feature designed to monitor the performance of container workloads deployed to:
Managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS)
Self-managed Kubernetes clusters hosted on Azure using AKS Engine
Azure Container Instances
Self-managed Kubernetes clusters hosted on Azure Stack or on-premises
Azure Arc-enabled Kubernetes

- Security monitoring and image scanning solutions such as Twistlock and Aqua Security are also available through the Azure Marketplace.