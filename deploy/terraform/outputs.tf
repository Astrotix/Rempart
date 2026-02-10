# Outputs for ZTNA Sovereign PoP deployment

output "pop_instances" {
  description = "Deployed PoP instances with their public IPs"
  value = {
    for key, pop in openstack_compute_instance_v2.pop : key => {
      name      = pop.name
      region    = pop.region
      public_ip = openstack_networking_floatingip_v2.pop_ip[key].address
      id        = pop.id
    }
  }
}

output "pop_public_ips" {
  description = "List of PoP public IPs for DNS configuration"
  value = {
    for key, ip in openstack_networking_floatingip_v2.pop_ip : key => ip.address
  }
}

output "wireguard_port" {
  description = "WireGuard port used across all PoPs"
  value       = var.wireguard_port
}

output "deployment_summary" {
  description = "Summary of deployed infrastructure"
  value       = <<-EOT
    ZTNA Sovereign - Deployment Summary
    ====================================
    PoPs deployed: ${length(var.pop_configs)}
    WireGuard port: ${var.wireguard_port}
    Provider: OVHcloud (France)
    
    Next steps:
    1. Build and upload the PoP binary to each server
    2. Configure DNS records pointing to PoP IPs
    3. Start the PoP services
    4. Register PoPs in the Control Plane
  EOT
}
