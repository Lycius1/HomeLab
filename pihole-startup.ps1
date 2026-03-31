Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
# Wait for WSL2 to be ready
Start-Sleep -Seconds 10

# Get fresh WSL2 IP
$wslIP = (wsl hostname -I).Trim().Split(" ")[0]

# Ensure Pi-hole is running inside WSL2
wsl -e sudo systemctl start pihole-FTL

# Remove old portproxy
netsh interface portproxy delete v4tov4 listenport=53 listenaddress=0.0.0.0 2>$null
netsh interface portproxy delete v4tov4 listenport=80 listenaddress=0.0.0.0 2>$null

# Add fresh portproxy for web UI (TCP only, port 80)
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=80 connectaddress=$wslIP connectport=80

# Kill any existing dnsproxy
Get-Process dnsproxy -ErrorAction SilentlyContinue | Stop-Process -Force

# Start dnsproxy for DNS (UDP+TCP port 53)
Start-Process -WindowStyle Hidden -FilePath "C:\dnsproxy\windows-amd64\dnsproxy.exe" -ArgumentList "-l 0.0.0.0 -p 53 -u $wslIP`:53"