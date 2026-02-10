# Variables for ZTNA Sovereign PoP deployment on OVHcloud

variable "ovh_application_key" {
  description = "OVHcloud API application key"
  type        = string
  sensitive   = true
}

variable "ovh_application_secret" {
  description = "OVHcloud API application secret"
  type        = string
  sensitive   = true
}

variable "ovh_consumer_key" {
  description = "OVHcloud API consumer key"
  type        = string
  sensitive   = true
}

variable "ovh_service_name" {
  description = "OVHcloud Public Cloud project ID"
  type        = string
}

variable "ssh_public_key" {
  description = "SSH public key for server access"
  type        = string
}

variable "control_plane_url" {
  description = "URL of the ZTNA Control Plane API"
  type        = string
  default     = "https://api.ztna-sovereign.fr"
}

variable "pop_configs" {
  description = "Configuration for each PoP to deploy"
  type = map(object({
    name     = string
    region   = string  # OVH region: GRA11, SBG5, RBX-A
    flavor   = string  # Instance type: d2-2, d2-4, b2-7, etc.
  }))
  default = {
    gravelines = {
      name   = "pop-gravelines"
      region = "GRA11"
      flavor = "d2-4"
    }
    strasbourg = {
      name   = "pop-strasbourg"
      region = "SBG5"
      flavor = "d2-4"
    }
    roubaix = {
      name   = "pop-roubaix"
      region = "GRA11"  # Roubaix uses GRA region
      flavor = "d2-4"
    }
  }
}

variable "wireguard_port" {
  description = "WireGuard listen port on PoP servers"
  type        = number
  default     = 51820
}
