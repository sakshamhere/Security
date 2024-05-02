variable "filename" {
  default = ".files/newpets.txt"
  # type        = This argument specifies what value types are accepted for the variable.
  # description = "This specifies the input variable's documentation."
  # validation = "A block to define validation rules, usually in addition to type constraints."
  # sensitive = "Setting a variable as sensitive prevents Terraform from showing its value in the plan or apply output, when you use that variable elsewhere in your configuration."
  # nullable = "Specify if the variable can be null within the module."

}

variable "filenamelist" {
  default = [
    ".files/file1.txt",
     ".files/file2.txt",
      ".files/file3.txt"
  ]
}

variable "content" {
  default = "This is new contnet"
}

variable "prefix" {
  default = "Mr"

  validation {
    condition     = length(var.prefix) > 1
    error_message = "the lenght of prefix should be more than 1"
  }

}

variable "separator" {
  default = "."
}

variable "length" {
  default = 1
}

variable "prefix-list" {
  # type = list
  default = ["Mr", "Mrs", "Other"]

  # we can also apply type contraint for default value as
  type      = list(string) # if its number thn error is shown in this code
  sensitive = true

}

variable "file-content" {
  type = map(string)
  default = {
    "statement1" = "This is content for key 1",
    "statement2" = "This is content for key 2"
  }
}

variable "prefix-set" {
  default = ["A", "B", "C", "D"] #adding any duplicate value will give error
  type    = set(string)
}

variable "rohan" {
  type = object({
    name         = string
    color        = string
    food         = list(string)
    favorite_pet = bool
  })

  default = {
    name         = "Rohan"
    color        = "red"
    age          = "21"
    food         = ["rice", "dal"]
    favorite_pet = true
  }
}

# the diff bw list and tuple here is that list can onlt have same type while tuple can have multiple data type

variable "kitty" {
  type    = tuple([string, number, bool])
  default = ["cat", 4, true] # the variable to be passed in this should be exactly be 3 in number and of that specific type
  # adding additonal value or of diff type will give error
}

#***********************************************************************************************************************
# WAYS TO USE VARIABLES

# 1. The default value of variable is optional, if we do not pass one we have to enter it interactively on command line

# 2. if we dont want it in interactive mode we can also use command line flags using -var

# terraform plan -var "length=2" -var "filename="./newfile.txt" 


# 3. When we are dealing with lot of variables we can use .tfvars or .tfvars.json file , 
# file with this extension is automatically loaded by terraform
# we need this as we have diffrent env where diff variables are needed so we can use .tfvars \

#if file name is terraform then it will be loaded automatically if file name is terraform.tfvars or tfvars.jason or with auto.tfvars
# otherwise use as plan -var-file="xyz.tfvars"


# PRECEDENCE 
# 1. command line flag : -var or -var-file
# 2. auto.tfvars (alphabetical order)
# 3. terraform.tfvars
# 4. Enviornment variables: TF_VAR_filename