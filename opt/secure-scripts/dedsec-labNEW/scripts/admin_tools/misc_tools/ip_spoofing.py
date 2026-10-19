import subprocess
import os
import requests

def set_egress_ip(interface, target_ip):
    """
    Forces traffic through a specific source IP on the VPS.
    This changes the 'public' IP seen by the destination.
    """
    # Flush existing SNAT rules
    subprocess.run(["iptables", "-t", "nat", "-F", "POSTROUTING"], check=True)
    
    # Add rule to SNAT to the desired IP
    cmd = f"iptables -t nat -A POSTROUTING -o {interface} -j SNAT --to-source {target_ip}"
    subprocess.run(cmd.split(), check=True)

def spoof_x_forwarded_for(url, spoofed_ip="1.2.3.4"):
    """
    Injects headers that common geo-location services trust.
    """
    headers = {
        "X-Forwarded-For": spoofed_ip,
        "X-Real-IP": spoofed_ip,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36..."
    }
    
    # Ensure traffic is routed through your local VPN tunnel (YOUR_LAB_VPN_IP is typical)
    proxies = {
        "http": "http://YOUR_LAB_VPN_IP:8080", 
        "https": "http://YOUR_LAB_VPN_IP:8080"
    }
    
    response = requests.get(url, headers=headers, proxies=proxies, verify=False)
    return response.text

def switch_geo_profile(country_code):
    # Mapping of country codes to interface/IP blocks
    profiles = {
        "US": "198.51.100.1",
        "UK": "203.0.113.1"
    }
    
    target_ip = profiles.get(country_code)
    if target_ip:
        print(f"Switching egress to {country_code} ({target_ip})...")
        # Apply the iptables SNAT rule defined in step 1
        set_egress_ip("eth0", target_ip)
        
        # Test the new egress IP
        output = subprocess.check_output(["curl", "-4", "http://ipinfo.io"]).decode()
        print(f"Current public IP (after change): {output.splitlines()[0]}")
        
        # Now you can use spoof_x_forwarded_for() to make requests appear as if they're coming from the spoofed location
    else:
        print("Profile not found.")

# Usage:
# switch_geo_profile("US") # Switches the egress to the US location
# spoof_x_forwarded_for("https://example.com", spoofed_ip="198.51.100.1") # Spoofs the X-Forwarded-For header

# Example usage:
if __name__ == "__main__":
    interface = "eth0"  # Change to the interface you want to use
    target_ip = "198.51.100.1"  # Change to the target IP
    country_code = "US"  # Change to the desired country code
    
    set_egress_ip(interface, target_ip)
    print(f"Current public IP (before change): {subprocess.check_output(['curl', '-4', 'http://ipinfo.io']).decode().splitlines()[0]}")
    
    switch_geo_profile(country_code)
    # After switching, you can use spoof_x_forwarded_for() or similar functions to make requests appear as if they're coming from the spoofed location
