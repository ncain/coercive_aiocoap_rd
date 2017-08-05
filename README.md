# coercive_aiocoap_rd
Query and listen for multicast-accessible IoTivity resources.

Tested only in Python 3.6 so far.

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
        2a. Implement a class representing IoT resources. [x]
        2b. Store a set of them somewhere that it will be kept up-to-date. [x]
            2b(i). Implement an iterable class representing the set which
                updates timestamps instead of silently ignoring duplicates. [x]
            2b(ii). Instantiate and utilize the Resource_Set [x]
        2c. Replace with database integration [✔]
    3. Implement persistent storage of known resources (db). [✔]

TODO:

    4. Implement manual registration for unicast-only resource storage? [ ]
        note: on roadmap, not a priority.
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

        IMPLEMENTED FIX:
            * currently disabling INFO-level logging.
    2. Not currently writing any discovered resources to the database.
        *   Database is now being written when \_insert() is called with
            contrived inputs. Still need to test actual discovery of networked
            resources.
    3. Passive listener decodes resources incorrectly: always places them at
        /oic/ad, because Message decodes based on the header rather than the
        payload. Need to parse the bytes given by recvfrom in order to construct
        the correct URI for the resource. Message payloads are commonly CBOR.
        *   CBOR: is it used always by IoTivity? Is it just common?
        *   Is this a result of the IoTivity Presence Server example being out
            of spec? There is (according to Wireshark's CoAP parser) a malformed
            section of the /oic/ad announcements sent by it (option #3: type 12)
            with length 1 and then the invalid option number 65524 (the delta is
            4 bits long, and specified as 0xe after the previous option number
            was 0xb or 11- is this a bug in wireshark's parser? Saving the pcap
            for further investigation. Will upload to GitHub if anyone asks.)
    4. When the presence server advertises at /oic/ad, the 2.05 CONTENT message
        has a payload that fails to parse with cbor.loads(). A basic Python
        program to demonstrate that issue exists as cbor_test.py in this
        repository. Payloads decode correctly when a CONTENT message is sent as
        a response to a GET request, though. Is this a solution to a problem we
        don't have? Did the active request produce bad results by querying the
        uri-path instead of parsing the payload?
        *   By changing to the cbor2 library, it now parses as a dictionary
            directly, rather than throwing an exception. However, the only
            useful information in the message is the resource type, which isn't
            enough to uniquely identify the resource. We probably need to have
            the RD subscribe in response to the /oic/ad message, per
            https://wiki.iotivity.org/resource_presence
            in order to get more complete resource information. This likely
            amounts to just another CoAP message designed to correspond (match
            nonce? same message id? review spec to be sure.) Also helpfully, the
            cbor2 lib has good documentation available at
            http://cbor2.readthedocs.io/en/latest/usage.html
