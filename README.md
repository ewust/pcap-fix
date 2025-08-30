# pcap-fix
Fix a corrupted pcap file

## Build

`go build pcap-fix.go`

## Run

`./pcap-fix -in ./pcaps/corrupted.pcap -out ./fixed.pcap`

corrupted.pcap is a file with 10 bytes removed from normal.pcap (and will not parse with tcpdump)
