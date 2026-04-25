#!/usr/bin/env python3
"""
Test script to verify ConpotService integration
"""

import os
import sys
import subprocess
import time
import json

def test_conpot_direct():
    print("Testing Conpot Direct Execution...")
    
    # Set PYTHONPATH
    conpot_dir = os.path.join(os.getcwd(), "conpot")
    python_path = os.environ.get("PYTHONPATH", "")
    if python_path:
        python_path += os.pathsep
    python_path += conpot_dir
    os.environ["PYTHONPATH"] = python_path
    
    print(f"PYTHONPATH set to: {python_path}")
    
    # Create Windows config
    config_content = """[common]
sensorid = default

[virtual_file_system]
data_fs_url = default
fs_url = default

[session]
timeout = 30

[daemon]
; Windows doesn't support user/group daemon settings

[json]
enabled = False
filename = conpot_logs/conpot.json

[sqlite]
enabled = False

[syslog]
enabled = False
device = /dev/log
host = localhost
port = 514
facility = local0
socket = dev

[hpfriends]
enabled = False
host = hpfriends.honeycloud.net
port = 20000
ident = 3Ykf9Znv
secret = 4nFRhpm44QkG9cvD
channels = ["conpot.events", ]

[taxii]
enabled = False
host = taxiitest.mitre.org
port = 80
inbox_path = /services/inbox/default/
use_https = False

[fetch_public_ip]
enabled = True
urls = ["http://whatismyip.akamai.com/", "http://wgetip.com/"]
"""
    
    config_path = os.path.join(os.getcwd(), "conpot", "windows_config.cfg")
    with open(config_path, "w") as f:
        f.write(config_content)
    
    print(f"Created config file: {config_path}")
    
    # Test conpot start
    try:
        print("Starting Conpot with Windows config...")
        process = subprocess.Popen(
            ["py", "conpot/bin/conpot", "-c", config_path, "-v"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ.copy()
        )
        
        # Wait a bit for startup
        time.sleep(5)
        
        # Check if process is still running
        if process.poll() is None:
            print("✅ Conpot started successfully in real mode!")
            
            # Get some output
            try:
                stdout, stderr = process.communicate(timeout=2)
                if stdout:
                    print("STDOUT:", stdout[:500])
                if stderr:
                    print("STDERR:", stderr[:500])
            except subprocess.TimeoutExpired:
                pass
            
            # Stop conpot
            process.terminate()
            process.wait(timeout=5)
            print("✅ Conpot stopped successfully!")
            return True
        else:
            stdout, stderr = process.communicate()
            print("❌ Conpot failed to start!")
            print("STDOUT:", stdout)
            print("STDERR:", stderr)
            return False
            
    except Exception as e:
        print(f"❌ Error testing conpot: {e}")
        return False

def test_conpot_ports():
    print("\nTesting Conpot Ports...")
    
    # Check if conpot is listening on expected ports
    import socket
    
    ports_to_check = [5020, 8800, 10201, 16100, 47808, 6230, 2121, 6969, 44818]
    
    for port in ports_to_check:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            
            if result == 0:
                print(f"✅ Port {port} is open (Conpot is listening)")
            else:
                print(f"❌ Port {port} is closed")
        except Exception as e:
            print(f"❌ Error checking port {port}: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("OTSHIELD ConpotService Integration Test")
    print("=" * 60)
    
    # Test direct conpot execution
    if test_conpot_direct():
        print("\n" + "=" * 40)
        print("Conpot is working in real mode!")
        print("=" * 40)
        
        # Test ports
        test_conpot_ports()
        
        print("\n🎉 ConpotService should now work in real mode!")
        print("The backend will use real Conpot instead of simulation.")
    else:
        print("\n❌ Conpot failed to start in real mode!")
        print("The system will fall back to simulation mode.")
    
    print("\n" + "=" * 60) 