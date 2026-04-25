#!/usr/bin/env python3
"""
Test script to verify Conpot integration
"""

import os
import sys
import subprocess
import time

def test_conpot():
    print("Testing Conpot Integration...")
    
    # Set PYTHONPATH to include conpot directory
    conpot_dir = os.path.join(os.getcwd(), "conpot")
    python_path = os.environ.get("PYTHONPATH", "")
    if python_path:
        python_path += os.pathsep
    python_path += conpot_dir
    os.environ["PYTHONPATH"] = python_path
    
    print(f"PYTHONPATH set to: {python_path}")
    
    # Test if conpot can be executed
    try:
        # Test conpot help
        result = subprocess.run(
            ["py", "conpot/bin/conpot", "--help"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print("✅ Conpot help command works!")
            print("Conpot output:")
            print(result.stdout)
            return True
        else:
            print("❌ Conpot help command failed!")
            print("Error:", result.stderr)
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Conpot command timed out!")
        return False
    except Exception as e:
        print(f"❌ Error running conpot: {e}")
        return False

def test_conpot_start():
    print("\nTesting Conpot start...")
    
    # Set PYTHONPATH
    conpot_dir = os.path.join(os.getcwd(), "conpot")
    python_path = os.environ.get("PYTHONPATH", "")
    if python_path:
        python_path += os.pathsep
    python_path += conpot_dir
    os.environ["PYTHONPATH"] = python_path
    
    try:
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
        
        # Start conpot in background with Windows config
        process = subprocess.Popen(
            ["py", "conpot/bin/conpot", "-c", config_path, "-v"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait a bit for startup
        time.sleep(3)
        
        # Check if process is still running
        if process.poll() is None:
            print("✅ Conpot started successfully!")
            
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
        print(f"❌ Error testing conpot start: {e}")
        return False

if __name__ == "__main__":
    print("=" * 50)
    print("OTSHIELD Conpot Integration Test")
    print("=" * 50)
    
    # Test basic conpot functionality
    if test_conpot():
        print("\n" + "=" * 30)
        print("Basic test passed! Conpot is working.")
        print("=" * 30)
        
        # Test conpot start
        if test_conpot_start():
            print("\n🎉 All tests passed! Conpot integration is working correctly.")
            print("\nThe system should now be able to run Conpot in real mode instead of simulation mode.")
        else:
            print("\n⚠️  Conpot start test failed, but basic functionality works.")
            print("This might be due to port conflicts or other runtime issues.")
    else:
        print("\n❌ Basic conpot test failed!")
        print("The system will fall back to simulation mode.")
    
    print("\n" + "=" * 50) 