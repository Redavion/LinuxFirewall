## Final Project Design Specifications

### High Level Project Design

1. Need to initialize an IP table that will IPs are supposed to be blocked and a log for all blocked traffic.
2. Need a function to parse out the user input for which IP addresses should be blocked in the firewall.
3. Need a function using NAT to inspect the network interaction every time a packet is received.
4. Need a function to filter all ingoing and outgoing traffic to find source and destination IP addresses.
5. Need a function to check if a source IP is supposed to be blocked in the IP table.
6. Need a function to log the blocked traffic if the source IP is one of the addressed to be blocked using dmsg and printk.
7. Need a main function that uses all aforementioned functions to take in user's IP restrict list and blocks traffic accordingly.

### Notes 
NET_FILTER under networking options of networking support 

Every time packet is received, inspect the network interaction - NAT

Block traffic/allow traffic from these IPs - IP Table maybe??

Keep log for all of the blocked traffic - Printk

Filter all ingoing outgoing traffic

Build module to extend kernel so it isn’t permanently built in

/Proc file system is how to build the module.

### Project Testing
1. Build out the hello.c module to understand how to first interact with modules
2. Put together a list of IPs to restrict
3. Check the blocking log to see if traffic from that IP address is actually being blocked
4. Check with machine's built in network monitor/firewall as expected results for verification

