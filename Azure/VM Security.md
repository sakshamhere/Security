Azure VM Security

1. Virus and Malware Protection                     - Microsoft Antimalware, MDE
2. Secret, key & Certificate Management             - Azure Key Vault
3. Disk Encryption                                  - Azure Disk Encryption
4. Backup                                           - Azure Backup
5. Network Security                                 - NSG, JIT VM access etc
6. Security policy management and reporting         - Defender for Cloud


# Virus and Malware Protection

1. Antimalware

- With Azure, you can use antimalware software from security vendors such as Microsoft, Symantec, Trend Micro, and Kaspersky.

* Microsoft Antimalware

Microsoft Antimalware for Azure is a single-agent solution for Azure Cloud Services and Virtual Machines is a real-time protection capability that helps identify and remove viruses, spyware, and other malicious software

2. MDE / Windows Defender Advanced Threat Protection.

**********************************************************************************************************************
# Secret, key & Certificate Management

1. Azure Key Vault

* Vault

- You can simplify the management and security of your critical secrets and keys by storing them in Azure Key Vault.

* Managed HSM

- Key Vault provides the option to store your keys in hardware security modules (HSMs) certified to FIPS 140-2 Level 2 standards.

HSM is actually a physical device that provides extra security for sensitive data, typically used to manage cryptographic keys

In Azure key-vault there are two protection methods for keys

1. Software-protected - this is done by Vault,the cryptographic operations are done over a compute service

2. HSM protected - In this cryptographic operations like encryption/decyrption are done over a HSM device, it wont go outside HSM module, HSM is more protected and highly secured

ex - Your SQL Server encryption keys for backup or transparent data encryption can all be stored in Key Vault with any keys or secrets from your applications.
*************************************************************************************************************************
# Disk Encryption

1.Azure Disk encryption

Azure Disk encryption can be applied to
- Linux Virtual Machine
- Windows virtual machines
- Virtual machine scale sets

Azure Disk Encryption uses following to provide volume encryption for the OS and the data disks.

- industry-standard BitLocker feature of Windows
- dm-crypt feature of Linux

The solution is integrated with Azure Key Vault to help you control and manage the disk encryption keys and secrets in your key vault subscription.

*************************************************************************************************************************
# Backup

1. Azure Backup

Azure Backup provides independent and isolated backups to guard against unintended destruction of the data on your VMs

As part of the backup process, a snapshot is taken, and the data is transferred to the Recovery Services vault with no impact on production workloads

* Recovery Service Vault

- A Recovery Services vault is a storage entity in Azure that houses data. 
- The data is typically copies of data, or configuration information for virtual machines (VMs), workloads, servers, or workstations.
- You can use Recovery Services vaults to hold backup data for various Azure services such as IaaS VMs (Linux or Windows) and SQL Server in Azure VMs.

* Recovery Point
Recovery points are created from snapshots of VM disks taken at a specific point in time. When you fail over a VM, you use a recovery point to restore the VM in the target location.

Backup Process

- During the first backup, a backup extension is installed on the VM if the VM is running.For Windows VMs, the VMSnapshot extension is installed. For Linux VMs, the VMSnapshotLinux extension is installed.
- After Backup takes the snapshot, it transfers the data to the vault.
*************************************************************************************************************************

# Network Security

Since VM require network connectivity we need to make sure that only legitimate traffic is allowed.

1. Network Access Control

The goal of network access control is to restrict virtual machine communication to the necessary systems. Other communication attempts are blocked.

* Network security rules (NSGs)

- An NSG is a basic, stateful, packet filtering firewall provides basic network level access control (based on IP address and the TCP or UDP protocols),

- It enables you to control access based on a *" 5-tuple" *, A 5-tuple refers to a set of five different values that comprise a Transmission Control Protocol/Internet Protocol (TCP/IP) connection. It includes a source IP address/port number, destination IP address/port number and the protocol in use.

2. Just-in-Time access (Defender for Cloud)

Threat actors actively hunt accessible machines with open management ports, like RDP or SSH. All of your virtual machines are potential targets for an attack.

In Azure, we can block inbound traffic on specific ports, by enabling just-in-time VM access.

Defender for Cloud ensures "deny all inbound traffic" rules exist for your selected ports in the network security group (NSG) and Azure Firewall rules.

When a user requests access to a VM, Defender for Cloud checks that the user has Azure role-based access control (Azure RBAC) permissions for that VM. If the request is approved, Defender for Cloud configures the NSGs and Azure Firewall to allow inbound traffic to the selected ports from the relevant IP address (or range), for the amount of time that was specified

In AWS, Defender for Cloud creates a new EC2 security group that allows inbound traffic to the specified ports.

JIT does not support VMs protected by Azure Firewalls controlled by Azure Firewall Manager.
************************************************************************************************************************

# Security policy management and reporting

1. Microsoft Defender for Cloud

- Providing security recommendations for the virtual machines. Example recommendations include: apply system updates, configure ACLs endpoints, enable antimalware, enable network security groups, and apply disk encryption.

- Monitoring the state of your virtual machines.
Learn more: