The Azure Command-Line Interface (CLI) is a cross-platform command-line tool to connect to Azure and execute administrative commands on Azure resources.

we can install the Azure CLI 
- locally on Linux, 
- Mac, 
- or Windows computers. 
- It can also be used from a browser through the Azure Cloud Shell 
- or run from inside a Docker container.

Azure CLI has an installer that makes its commands executable in all four shell environments.

4 Shell Enviornments
- Cmd
- Bash
- Windows Powershell
- Powershell

# Example Commands
- az login -u <username> -p <password>
- az login                                                                  - sign in with Azure CLI
- az extension add --name <extension-name>                                  - Install any extension
- az group create --name <ResourceGroupName> --location eastus              - Create Resource Group

- az storage account create --name <StorageAccountName> --resource-group <ResourceGroupName> --location eastus --sku Standard_LRS --kind StorageV2                                                - Create Azure Storage Account


# Azure Cloud Shell
Azure Cloud Shell is a hosted shell environment that runs on an Ubuntu container.
Cloud Shell provides two shell environments: Bash (with Azure CLI preinstalled) and PowerShell (with Azure PowerShell preinstalled)

# *********************************************************************************************************************

# Azure Resource Manager
Azure Resource Manager enables you to work with the resources in your solution as a group
You use a template for deployment and that template can work for different environments such as testing, staging, and production.
Azure Resource Manager provides security, auditing, and tagging features to help you manage your resources after deployment.

- Best Practises

* Define and deploy your infrastructure through the declarative syntax in ARM / Azure Resource Manager templates, rather than through imperative commands.

* Define all deployment and configuration steps in the template. You should have no manual steps for setting up your solution.

- ARM Template

- A JavaScript Object Notation (JSON) file that defines one or more resources to deploy to a resource group. It also defines the dependencies between the deployed resources. The template can be used to deploy the resources consistently and repeatedly.

- The Resource Manager template is an example of declarative syntax. In the file, you define the properties for the infrastructure to deploy to Azure.

- Resource providers

-Some common resource providers are Microsoft.Compute, which supplies the virtual machine resource, Microsoft.Storage, which supplies the storage account resource, and Microsoft.Web, which supplies resources related to web apps.

-Before deploying your resources, you should gain an understanding of the available resource providers. Knowing the names of resource providers and resources helps you define resources you want to deploy to Azure. Also, you need to know the valid locations and API versions for each resource type.