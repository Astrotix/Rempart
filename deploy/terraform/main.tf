# ZTNA Sovereign - OVHcloud PoP Deployment
# Deploys WireGuard PoP servers across French datacenters

terraform {
  required_version = ">= 1.5"
  required_providers {
    ovh = {
      source  = "ovh/ovh"
      version = "~> 0.40"
    }
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.54"
    }
  }
}

# OVHcloud provider configuration
provider "ovh" {
  endpoint           = "ovh-eu"
  application_key    = var.ovh_application_key
  application_secret = var.ovh_application_secret
  consumer_key       = var.ovh_consumer_key
}

# OpenStack provider for OVHcloud Public Cloud
provider "openstack" {
  auth_url    = "https://auth.cloud.ovh.net/v3"
  domain_name = "Default"
  tenant_name = var.ovh_service_name
}

# SSH Key
resource "openstack_compute_keypair_v2" "ztna_key" {
  name       = "ztna-sovereign-key"
  public_key = var.ssh_public_key
}

# Security Group for PoP servers
resource "openstack_networking_secgroup_v2" "pop_sg" {
  name        = "ztna-pop-sg"
  description = "Security group for ZTNA PoP servers"
}

# Allow WireGuard UDP
resource "openstack_networking_secgroup_rule_v2" "wireguard" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = var.wireguard_port
  port_range_max    = var.wireguard_port
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.pop_sg.id
}

# Allow SSH (restrict to your IP in production)
resource "openstack_networking_secgroup_rule_v2" "ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "0.0.0.0/0"  # RESTRICT THIS IN PRODUCTION
  security_group_id = openstack_networking_secgroup_v2.pop_sg.id
}

# Allow HTTPS for management API
resource "openstack_networking_secgroup_rule_v2" "https" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.pop_sg.id
}

# PoP Instances
resource "openstack_compute_instance_v2" "pop" {
  for_each = var.pop_configs

  name            = each.value.name
  region          = each.value.region
  flavor_name     = each.value.flavor
  image_name      = "Ubuntu 24.04"
  key_pair        = openstack_compute_keypair_v2.ztna_key.name
  security_groups = [openstack_networking_secgroup_v2.pop_sg.name]

  user_data = templatefile("${path.module}/cloud-init.yaml", {
    pop_name          = each.value.name
    pop_id            = each.key
    control_plane_url = var.control_plane_url
    wireguard_port    = var.wireguard_port
    pop_location      = each.value.region
  })

  metadata = {
    role     = "ztna-pop"
    location = each.value.region
    managed  = "terraform"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Floating IPs for each PoP
resource "openstack_networking_floatingip_v2" "pop_ip" {
  for_each = var.pop_configs
  pool     = "Ext-Net"
  region   = each.value.region
}

# Associate floating IPs
resource "openstack_compute_floatingip_associate_v2" "pop_ip_assoc" {
  for_each    = var.pop_configs
  floating_ip = openstack_networking_floatingip_v2.pop_ip[each.key].address
  instance_id = openstack_compute_instance_v2.pop[each.key].id
}
