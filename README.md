# DNS Scanner and Listener (with Spoof Scanning)

>Disclaimer - This code was written for educational purposes. Although it could be used to scan the entire IP range, this should be avoided.
Most hosts have a TOS that prevents this kind of thing. People who scan globally suck, so don't be that person. 

TO-DO:

-Finish listener and filter

-Finish adding threaded support to scanner

-Write attack scripts (maybe not publicly?)

-Add other common methods (SSDP, NTP) to work in a single scanner

## What Is Scanning ?

Scanning is often done to find DNS resolvers which readily respond to queries, so that they can be used in 
DNS Amplification Attacks (DDOS).

## What is Spoofed Scanning ?


As noted earlier most hosts won't let you scan. People who want to DDOS need to use servers that can spoof ip headers (usually expensive). If a person DDOSing
has a host that doesn't ban them for modifying the IP header and they ignore the insane amounts of traffic as well, then this server could
also be used to scan lists with spoofing. This allows the person the ability to spoof the IP of a cheap vps server they own which will act like
the listener and filter, while the spoof server is the scanner.
Let spoofable server = S, cheap 5$ vps = L, some dns resolver = D 

1) L starts running dns_listen
2) S starts scanning IP range, sets source address = <VPS IP>
3) S sends D a query with <VPS IP>
4) D sends response to <VPS IP>
5) L filters and stores lists

The benefit of this, is obscurity. No new traffic is leaving the spoofed server, so there is no new reason for your host to ban you.
As far as the other VPS provider knows, your cheap filter server didn't create those packets (could block responses if router filters)
and you aren't the responsible party. win-win.

## What is EDNS ?

EDNS is Extended DNS. The significance of this is previously DNS had a limit of 512 bytes per packet. EDNS modified this allowing users to include information about the size of packets they can handle. This in and of itself made DNS amplification attacks feasible.