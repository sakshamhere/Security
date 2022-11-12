https://learn.hashicorp.com/tutorials/terraform/aks

So we will need providers
- Azurerm
- random

1. aks-cluster.tf provisions a resource group and an AKS cluster. 

2. variables.tf declares the appID and password so Terraform can use reference its configuration

3. terraform.tfvars defines the appId and password variables to authenticate to Azure

4. outputs.tf declares values that can be useful to interact with your AKS cluster

5. versions.tf sets the Terraform version to at least 0.14 and defines the required_provider block
**************************************************************************************************************
 
* First we create a Resource Group

* Then we create AKS cluster

* Now we need to authenticate to Azure 

Ways to authenticate  - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs#authenticating-to-azure

Terraform recommend using either a Service Principal or Managed Service Identity when running Terraform non-interactively (such as when running Terraform in a CI server) - and authenticating using the Azure CLI when running Terraform locally.

We use "Authenticating using a Service Principal with a Client Secret"

A Service Principal is an application within Azure Active Directory whose authentication tokens can be used as the client_id, client_secret, and tenant_id fields needed by Terraform (subscription_id can be independently recovered from your Azure account details).

So we need to Create AD Service Principal using Azure CLI - https://docs.microsoft.com/en-us/cli/azure/create-an-azure-service-principal-azure-cli#1-create-a-service-principal

Create an Azure service principal with the " az ad sp create-for-rbac " command. - https://docs.microsoft.com/en-us/cli/azure/ad/sp?view=azure-cli-latest#commands

" az ad sp create-for-rbac " - Create a service principal and configure its access to Azure resources.

After running this command make sure the appid and passowrd are there in Variable file

Terraform will use these values to authenticate to Azure before provisioning your resources.

* After you have saved your customized variables file, initialize your Terraform workspace, which will download the provider and initialize it with the values provided in your terraform.tfvars file.

* Provision the AKS cluster - In your initialized directory, run terraform apply and review the planned actions. Your terminal output should indicate the plan is running and what resources will be created.

You can see this terraform apply will provision an Azure resource group and an AKS cluster. Confirm the apply with a yes.

* Now that you've provisioned your AKS cluster, you need to configure kubectl.

Run the following command to retrieve the access credentials for your cluster and automatically configure kubectl.

az aks get-credentials --resource-group $(terraform output -raw resource_group_name) --name $(terraform output -raw kubernetes_cluster_name)