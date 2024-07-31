
# 1. Network Segmentation


Any workload that could incur higher risk for the organization should be in isolated virtual networks.

- Basic Segmentation
    - Vnet
        - Subnet


Enhance segmentation strategy by restricting or monitoring traffic between internal resources using network controls.

This can be a highly secure `"deny by default, permit by exception"` approach by restricting the ports, protocols, source, and destination IPs of the network traffic.

Use `network security groups (NSG)` as a network layer control to restrict or monitor traffic by port, protocol, source IP address, or destination IP address.

You can also use `application security groups (ASGs)` to simplify complex configuration. Instead of defining policy based on explicit IP addresses in network security groups, ASGs enable you to configure network security as a natural extension of an application's structure, allowing you to group virtual machines and define network security `policies based on those groups`.

- Segmentation by Following

    - Vnet
        - Subnet

    - NSG (Network Security Group)

    - ASG (Application Security Group)

    - Azure Bastion Host (Jumpserver)

    - Service Endpoint (Subnet privately accessing azure resource)