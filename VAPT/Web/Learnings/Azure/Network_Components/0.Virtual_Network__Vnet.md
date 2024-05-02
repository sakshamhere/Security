https://learn.microsoft.com/en-us/training/modules/introduction-to-azure-virtual-networks/2-explore-azure-virtual-networks


# VNet (Azure Virtual Network)
VNets enable you to build complex virtual networks that are similar to an on-premises network, with additional benefits of Azure infrastructure such as scale, availability, and isolation

    - Communication within Azure
        - Allows communication between VMS in Vnet
        - Allows communication between Vnet and other Azure resources using `Service Endpoints`
        - Allows communication between two Vnets by `Vnet Peering`

    - Communication between Vnet and On-Prem
        - `Point-to-site` virtual private network (VPN)
        - `Site-to-site` VPN 
        - `Azure ExpressRoute`.

    - Each Vnet has its own CIDR block and can be linked to other VNets and on-premises networks as long as the CIDR blocks don't overlap.

    - Network Filtering within Vnet
        - Allows network filtering Using any combination of `network security groups` and network virtual appliances like firewalls, gateways, proxies, and Network Address Translation (NAT) services.
        
    - Traffic Routing
        - Azure routes traffic between subnets, connected virtual networks, on-premises networks, and the Internet, by default. You can implement route tables or `border gateway protocol` (BGP) routes to override the default routes Azure creates.

    - Reserved Ips in Vnet (.0 .1 .2 .3 .255)
        - For example, the IP address range of 192.168.1.0/24 has the following reserved addresses:
            - 192.168.1.0 : Network address
            - 192.168.1.1 : Reserved by Azure for the default gateway
            - 192.168.1.2, 192.168.1.3 : Reserved by Azure to map the Azure DNS IPs to the VNet space
            - 192.168.1.255 : Network broadcast address.

    - Subnet
        - Vnet can be segmented into diffrent size subnets each with unique ip addressing