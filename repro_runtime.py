
from modules.runtime_analyzer import RuntimeAnalyzer
import os

def test_substring_logic():
    analyzer = RuntimeAnalyzer()
    # Mock data to simulate the issue
    # "net.dll" should NOT match "dotnet.dll"
    
    analyzer.loaded_dlls = {
        r"c:\windows\system32\dotnet.dll": [1001],
        r"c:\windows\system32\net.dll": [1002],
        r"c:\program files\common\inet.dll": [1003]
    }
    analyzer.process_map = {
        1001: "dotnet_app.exe",
        1002: "net_tool.exe",
        1003: "inet_service.exe"
    }

    target = "net.dll"
    users = analyzer.get_users_of_dll(target)
    
    print(f"Searching for: {target}")
    print("Found users:")
    for pid, name in users:
        print(f"  - {name} ({pid})")

    # Verification
    pids = [u[0] for u in users]
    if 1001 in pids: 
        print("FAIL: Matched 'dotnet.dll' (substring match on filename/path)")
    if 1003 in pids:
        print("FAIL: Matched 'inet.dll' (substring match on filename/path)")
    
    if 1002 in pids and len(pids) == 1:
        print("PASS: Only matched exact 'net.dll'")

if __name__ == "__main__":
    test_substring_logic()
