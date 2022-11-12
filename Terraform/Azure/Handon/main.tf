terraform {
  required_version = ">= 0.12"
  required_providers {
    azurerm = {
        # version = ">=1.25, <1.26"
        version = "=3.0.0"        

    }
  }
}

# Configure the Microsoft Azure Provider
provider "azurerm" {
  features {}
}

# # Create a resource group
# resource "azurerm_resource_group" "my_rg" {
#   name     = "${var.prefix}-rg"
#   location = "East US"
# }


# resource "azurerm_virtual_network" "main" {
#   name                = "${var.vnet[count.index]}-mynetwork"
#   address_space       = ["10.0.0.0/16"]
#   location            = azurerm_resource_group.my_rg.location
#   resource_group_name = azurerm_resource_group.my_rg.name
#   count = length(var.vnet)
# }


resource "azurerm_resource_group" "myRG" {
  name     = "example-resources"
  location = "East US"
}

module "any-name-webserver"{
  source = "../../modules/webserver-module"          # this will all .tf files in that module

#  provider                                   # we can also specify another provider for module, this will ovveride the one we are using in root modlue

  vnet_name = "webApplication"
  vnet_address_space = ["10.0.0.0/16"]
  rg_location = "East US"
  rg_name = azurerm_resource_group.myRG.name
  sub_address_space = ["10.0.2.0/24"]
  vm_name = "Webserver"
}

# If we want to have some output from this module we can have it by output variable in module

# For example, if a virtual machine requires software installation, antivirus protection, 
# or the ability to run a script inside it, you can use a VM extension.

# resource "azurerm_virtual_machine_extension" "example" {
#   name                 = "hostname"
#   virtual_machine_id   =  tostring(module.any-name-webserver.webserver-details)
#   publisher            = "Microsoft.Azure.Extensions"
#   type                 = "CustomScript"
#   type_handler_version = "2.0"

#   settings = <<SETTINGS
#     {
#         "commandToExecute": "hostname && uptime"
#     }
# SETTINGS


#   tags = {
#     environment = "Production"
#   }
# }
