# coercive_aiocoap_rd
Query and listen for multicast-accessible IoTivity resources.

Essentially, a CoAP resource directory which coercively registers IoTivity
resources in particular. This is achieved by querying IPv4 and IPv6 multicast
addresses for the /oic/res path, as well as registering in the multicast groups
and listening for advertisements of CoAP resources with a 2.05 CONTENT message
code. By storing both, it is possible to have a complete map of
multicast-addressible resources on the local network. If an IoTivity device is
configured to disregard multicast requests and respond only to unicast, those
resources must be tracked separately. This could be achieved by adding a manual
"register" function to this module, but I'm unsure how to automate it.

DONE:

    0. Implement active interrogation of the network for resources. [✔]
        0a. Send queries for /oic/res to multicast group addresses. [✔]
        0b. Parse received answers for storage as known resources. [✔]
    1. Implement passive listening for multicast resource advertisement. [✔]
        1a. Create and bind IPv4 sockets at relevant multicast addresses. [✔]
            1a(i). Unpack responses to parse header code and URI. [✔]

            1a(ii). Listen on bound sockets for URIs containing /oic/ad. [ ]
            1a(iii). Listen on bound sockets for URIs containing /oic/res. [ ]
                note: listening for all CONTENT messages; not filtering by URI.

            1a(iv). Discard non-matching noise on socket silently. [✔]

        1b. Create and bind IPv6 sockets at relevant multicast addresses. [✔]
            1b(i). Unpack responses to parse header code and URI. [✔]

            1b(ii). Listen on bound sockets for URIs containing /oic/ad. [ ]
            1b(iii). Listen on bound sockets for URIs containing /oic/res. [ ]

            1b(iv). Discard non-matching noise on socket silently. [✔]

        1c. Listen to bound sockets in threads or asynchronously. [✔]
        1d. Filter messages for "2.05 Content" (instead of URI filtering)? [✔]
            (Code is 0x45 for 2.05, after 8 bits of other coap header data.)
    2. Store known resources sensibly in memory. [✔]
        2a. Implement a class representing IoT resources. [✔]
        2b. Store a set of them somewhere that it will be kept up-to-date. [✔]
            2b(i). Implement an iterable class representing the set which
                updates timestamps instead of silently ignoring duplicates. [✔]
            2b(ii). Instantiate and utilize the Resource_Set [✔]

TODO:

    3. Implement manual registration for unicast-only resource storage? [ ]
    4. Implement persistent storage of known resources (files or db?). [ ]
    5. TEST THOROUGHLY. [ ]
    6. REFACTOR INTO SEPARATE MODULES. [ ]

BUG LIST:

    1. Testing against the IoTivity example simpleserver, the console gets full
        of 'INFO:coap:Duplicate NON, ACK or RST received' messages.
        These are issued from line 230 of aiocoap/protocol.py, in the
        \_deduplicate_message(self, message) method defined at line 218.

        POSSIBLE FIXES:

            * Modify the library to only transmit once: we retransmit every few
                minutes anyway. (note: there is a FIXME comment in the library
                which alludes to the idea that the CoAP spec differs from the
                aiocoap implementation of multicast retransmission.)
            * Extend the library to override the \_deduplicate_message method in
                order to change that behavior without modifying the library.
            * Reroute error output to an actual log file?
            * Silently ignore (disable) INFO-level logging?
