To deploy infrastructure with Terraform:

Scope -             Identify the infrastructure for your project.
Author -            Write the configuration for your infrastructure.
Initialize -        Install the plugins Terraform needs to manage the infrastructure.
Plan -              Preview the changes Terraform will make to match your configuration.
Apply -              Make the planned changes.
Terraform Validate - You can run this command whenever you like to check whether the code is correct. Once you run this command, if there is no output, it means that there are no errors in the code.
terraform get -      This command is used to download and install the modules for that configuration.
terraform get -update - It checks the downloaded modules and checks for the recent versions if any.


HCL Syntex

<block name> <provider>_<resource type> <logical name>{

    Key value arguments specific to type of resource we are creating
}

basic variables type - String, Number, bool, any(default value)
other variables types - list, ,map, set, tuple, objects

TIP - When creating names, do not give any "space" because it throws an error. The name may contain word characters like". ", "_" or "-" .

**************************************************************************************************************
## Explaining .tf file

- Resource blocks

resource "azurerm_virtual_network""myterraformnetwork"
  {
     name = "myvnet"
     address_space = ["10.0.0.0/16"]
     location="East US"
     resource_group_name="er-tyjy"
   }

Resource blocks define the infrastructure
It contains the two strings - type of the resource(azurerm_virtualnetwork) and name of the resource(myterraformnetwork).

## Running .tf file

Once the file is created, run terraform init command.

This command initializes the provider plugins and initializes data that can be used by subsequent commands.

Terraform uses plugin based architecture to support the various services providers and infrastructure available.

When you run Terraform init command, it downloads and installs provider binary for the corresponding providers.

Now, you can run the terraform plan command. It shows all the changes it is going to make.

If the output is as you expected and there are no errors, then you can run Terraform apply

For larger infrastructures, to query a resource it takes time. Many cloud providers do not have APIs to perform a query on the multiple resources at a time.There is an API rate limitation due to which you can request only a certain number of resources.
You can avoid API calling multiple times by using -refresh =false or -target flag. The cached state is considered as the record of truth.

terraform plan -refresh=false

## Destroying Infrastructure

You can destroy the infrastructure by using Terraform destroy command.

When you run the command, the resources that are going to be destroyed is shown by using -

After this, Terraform shows the execution plan and waits for approval before making any changes.

As like apply, the terraform shows the plan in the order it is going to destroy.

## Syncing
If multiple persons are working on the same infrastructure and making changes at the same time, it causes problems.

There is a solution to this problem. Remote state, fully featured backend so that terraform can use the remote locking to avoid running terraform at the same time and it ensures that terraform is running with the most recent update.

# Backend
Advantages of having backend:

Working in a team: In the previous card, you have seen the advantage of using locks. There are some backends like terraform enterprise that stores the history of all state versions.

Keeping sensitive info off the disk: The state file is maintained in the backends in memory and can be retrieved only on demand. For example, if you are using backend as Amazon s3, the only location state is persisted in s3.

Remote Operations: For large infrastructures, terraform apply takes more time. If you are using backend, then all the changes are done remotely. You can turn off the computer, and the operations will still be completed.

If you are an individual, then it is likely that you can almost certainly escape without using backends.

## Modules
Till now, when you need to add a resource, you are dealing with the configuration files directly.

If you have more resources, adding the resources again and again will make the job tedious.

In general purpose programming languages, if you like to avoid writing duplicate code, it is written in the library.

In terraform, we will make the use of the module for repeatability.

A module is like a reusable blueprint of infrastructure.

A module is nothing but a folder of Terraform files.

In terraform the modules are categorized into two types:

Root modules - The current directory of Terraform files on which you are running the commands.

Child modules - The modules sourced by the root module.

To create a child module, add resources to it.

# Module Syntax

module "child"
{
source = "../child"
}

The difference between adding the resources and module is *for adding the resource (***Eg **: resource "azurerm_virtual_network" 'test") you need type and name but for adding a module (Eg: module "child") only the name is enough.

The name of the module should be unique within configurations because it is used as a reference to the module and outputs.

Modules are like packages in python, we can call modules and pass the variables

We can actually publish our modules to terraform or load the ones created by others

You can destroy the modules same as deleting the resources.

## Benefits of Modules

Code reuse: When there is a need to provision the group of resources on another resource at the same time, a module can be used instead of copying the same code. It helps in resolving the bugs easily. If you want to make changes, changing the code in one place is enough.

Abstraction layer: It makes complex configurations easier to conceptualize.

For example, if you like to add vault(Another harshicop's tool for managing secrets) cluster to the environment, it requires dozens of components. Instead of worrying about individual components, it gives ready-to-use vault cluster.

## Meta Parameters

- COUNT

Consider a scenario where you would like to create 3 virtual networks at a time. You can't repeat the same code, again and again. That's not why Terraform is designed for.

Terraform has a meta parameter called as count. It defines how many parameters you like to create.After writing the code, run terraform validate to check the errors.

resource "azurerm_virtual_network""multiplevnets"
{
   name = "multiplevnets-${count.index}"
   resource_group_name="${var.resource_group}"
   location="${var.location}"
   address_space=["10.0.0.0/16"]
   count = 3
}

When you run the Terraform plan, it shows the following actions will be performed.

+ azurerm_virtual_network.multiple[0]
+ azurerm_virtual_network.multiple[1]
+ azurerm_virtual_network.multiple[2]

If you proceed further and run terraform apply, three virtual networks are created.


* Now You wish to increase the count from 3 yo 5 what should be done inorder to achieve this

Don't worry just increase the count to five. Terraform has a state called Actual state which remembers how many virtual networks are present and how many should be added to achieve the Desired state

Now, your main.tf file will look like this

resource "azurerm_virtual_network""multiplevnets"
{
name = "multiplevnets-${count.index}"
resource_group_name="${var.resource_group}"
location="${var.location}"
address_space=["10.0.0.0/16"]
count = 5   //Updated value from 3 to 5
}

Terraform performs a quick refresh and notice that there are already three vnets and two more are created.

+ azurerm_virtual_network.multiple[3]
+ azurerm_virtual_network.multiple[4]


* Now 5 virtual networks are up and running you feel like to remove 3 vnets what should be done?

Don't worry change the count to 2 and the last created 3 virtual networks will be deleted.

Edit 'count' in your main.tf to 2 and If you run terraform plan you will get an output like this:

- azurerm_virtual_network.multiple[2]

- azurerm_virtual_network.multiple[3]

- azurerm_virtual_network.multiple[4]


* Now Suppose you like to create the three virtual networks with names vnet-A, vnet-B and vnet-C
you can do this easily with the help of list

Mention how many vnets you are going to create with the help of list and define it in variables.tf file

variable "name"
{
  type= "list"
  default = ["A","B","C"]
}

Now, you can call this variable in the main.tf file in the following way

count = "${length(var.name)}" - It returns number of elements present in the list. you should store it in meta parameter count.

"${element(var.name,count.index)}" - It acts as a loop, it takes the input from list and repeats untill there are no elements in list.

Now, change the main.tf file and it looks like this

resource "azurerm_virtual_network""multiple"
{
name =                "vnet-${element(var.name,count.index)}" or "vnet-${var.name[count.index]}"
resource_group_name = "${var.resource_group}"
location =            "${var.location}"
address_space=        ["10.0.0.0/16"]
count=                "${length(var.name)}"
}

When you run terraform apply, It creates three resources.

NOTE - If we put COUNT = 0 then no resource is created, this also helps in putting conditions

- TERNARY OPERATOR in terraform.

For example, a vnet has to be created only, if the variable number of vnets is 3 or else no.

Declare a variable in variables.tf.

variable "env"
{
   default = "Prod"
}

Make the changes in main.tf file to pass this as a value to the ternary operator

So as we know if count is 0 it wont create any resource while if 1 then it will create 1 resource, 

* Now if we want to create a resource only if the env is production we can use this with ternanry operator

count = "${var.env == 3 ? 1  : 0}"