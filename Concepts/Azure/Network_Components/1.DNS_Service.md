https://learn.microsoft.com/en-us/training/modules/introduction-to-azure-virtual-networks/5-design-name-resolution-virtual-network
https://medium.com/petabytz/azure-dns-overview-c6c3fc262d3b

Depending on how you use Azure to host IaaS, PaaS, and hybrid solutions, you might need to allow the virtual machines (VMs), and other resources deployed in a virtual network to communicate with each other. Although you can enable communication by using IP addresses, it is much simpler to use names that can be easily remembered, and do not change.


Types of DNS Service in Azure

- `Azure Provided DNS`
- `Public DNS` 
- `Private DNS`
- `Integrating On-Premises DNS with Azure Vnets`


# Azure Provided DNS

Azure provides its own default internal DNS. It provides an internal DNS zone that always exists, supports automatic registration, requires no manual record creation, and is created when the VNet is created. And it's a free service. Azure provided name resolution provides only basic authoritative DNS capabilities. If you use this option, the DNS zone names and records will be automatically managed by Azure, and you will not be able to control the DNS zone names or the life cycle of DNS records.

# Public DNS

The Azure DNS service can be used to resolve public domain names.

Azure does not allow direct purchase of public domains, but assuming that you have a public domain, you can use the Azure DNS to resolve domain names.

1. Create `DNS Zone`

To do so you need to proceed with the creation of a `Dns Zone`, In the activation process of a DNS zone you are prompted to specify the location of the Resource Group, that determines where the metadata associated with the DNS zone are maintained. 

The creation process is very quick and, at the end of the service creation, you can check the 4 name servers that you can use for the zone created.


2. Delegate the name resolution for the domain to name servers in Azure

Every Registar has its own tool for managing names, where you can specify NS records, making them point to the four Name Servers provided by Azure DNS service.

At this point you can add and manage any public DNS records on yours DNS zone hosted in Azure environment.

- `Child Domains`

If you want to set up a separate child zone, you can delegate a subdomain in Azure DNS. For example, after configuring contoso.com in Azure DNS, you could configure a separate child zone for partners.contoso.com.


# Private DNS 

In Azure Virtual Networks the DNS is integrated into the platform and it is available by default, however  you can specify custom DNS Servers by enabling `private DNS zone.`

Private DNS zones in Azure are available to internal resources only. They are global in scope, so you can access them from any region, any subscription, any VNet, and any tenant. If you have permission to read the zone, you can use it for name resolution. Private DNS zones are highly resilient, being replicated to regions all throughout the world. They are not available to resources on the internet.


The presence of the Private Zone in the Azure DNS service allows to be adopted in different scenarios.
For Example

- Name resolution for a single Virtual Network 
- Name resolution between different Virtual Networks


# Integrating On-Premises DNS with Azure Vnets