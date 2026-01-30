terraform {
  required_providers {
    random = {
      source = "hashicorp/random"
    }
  }
  # Backend will be initialized via -backend-config=backend.hcl
  backend "http" {}
}

provider "random" {}

variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "subscription_id" {
  type = string
}

variable "instance_count" {
  type = number
}

resource "random_pet" "server" {
  count  = var.instance_count
  prefix = "${var.project_name}-${var.environment}-${var.subscription_id}"
}

output "server_names" {
  value = random_pet.server[*].id
}
