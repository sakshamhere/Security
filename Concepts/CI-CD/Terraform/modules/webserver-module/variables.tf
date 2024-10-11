variable "vnet_name" {
    type = string
    description = "Virtual Network name"
}

variable "vnet_address_space" {
    type = list
    description = "Address space for virtual network"
}

variable "rg_location" {
    type = string
    description = "resource group location"
}

variable "rg_name" {
    type = string
    description = "resource group name"
}

variable "sub_address_space" {
    type = list
    description = "subnet address"
}

variable "vm_name" {
    type = string
    description = "nameof vm"
}

variable "vm_env" {
    default = "Prod"
}