"""Query and listen for multicast-accessible IoTivity resources.

Essentially, a CoAP resource directory which coercively registers IoTivity
resources in particular. This is achieved by querying IPv4 and IPv6 multicast
addresses for the /oic/res path, as well as registering in the multicast groups
and listening for advertisements of resources in the /oic/ad URI path. By
storing both, it is possible to have a complete map of multicast-addressible
resources on the local network. If an IoTivity device is configured to
disregard multicast requests and respond only to unicast, those resources must
be tracked separately. This could be achieved by adding a manual "register"
method or function to this module, but I'm unsure how to automate it.

TODO:
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
    3. Implement manual registration for unicast-only resource storage? [ ]
    4. Implement persistent storage of known resources (files or db?). [ ]
    5. TEST THOROUGHLY. [ ]
    6. REFACTOR INTO SEPARATE MODULES. [ ]

BUG LIST:
    0. Running this script makes my home WiFi unusable. Need packet captures to
        figure out why.
        Possible explanations:
            * Not using as many sleep() calls as initially planned
            * Generating packets as expected, but it's too many for my router
            * The Edison board's IoTivity examples could be generating too much
                traffic
            * The Edison could be DoSing my router with DNS requests
            * The Edison might be misconfigured in some other way
        Going to use my mobile phone as a hotspot, connect Edison and laptop,
            and try to gather some data.
            * Couldn't reproduce. 1357 packets seen by laptop in 378 seconds.
                Not much traffic.
        Next step: soft AP broadcasted from laptop in order to capture all
            traffic. USB tether to still have internet access? Bridge to a cat5
            cable?
    1. Testing against the IoTivity example simpleserver, the console gets full
        of 'INFO:coap:Duplicate NON, ACK or RST received' messages.
        These are issued from line 230 of aiocoap/protocol.py, in the
        _deduplicate_message(self, message) method defined at line 218.

Created on Jun 7, 2017

@author: Noah Cain
Based in part on code from:
http://aiocoap.readthedocs.io/en/latest/examples.html
"""

import logging
import asyncio
from aiocoap import Context, Message, protocol
from aiocoap.numbers import GET, NON, CONTENT
import datetime
import socket
import struct
# from threading import Lock, Thread
# import time


logging.basicConfig(level=logging.INFO)

COAP_PORT = 5683
# Multicast Addresses to query for /oic/res:
# IPv6:
# [FF02:0:0:0:0:0:0:FD]:5683 (All CoAP Nodes in Link-Local Scope)
ALL_LINK_LOCAL_COAP = 'FF02:0:0:0:0:0:0:FD'
# [FF05:0:0:0:0:0:0:FD]:5683 (All CoAP Nodes in Site-Local Scope)
ALL_SITE_LOCAL_COAP = 'FF05:0:0:0:0:0:0:FD'
# [FF02::1]:5683 (All nodes in Link-Local)
ALL_LINK_LOCAL_NODES = 'FF02:0:0:0:0:0:0:1'
# [FF05::1]:5683 (All nodes in Site-Local)
ALL_SITE_LOCAL_NODES = 'FF05:0:0:0:0:0:0:1'
# IPv4:
# 224.0.1.187:5683 (All CoAP Nodes, from Internetwork Control Block)
ALL_COAP_THIS_NETWORK = '224.0.1.187'
# 224.0.0.1:5683   (All Systems on this Subnet)
ALL_SYSTEMS_THIS_SUBNET = '224.0.0.1'
#
# The port 5683 is the default CoAP port.
# The port 5684 is the default DTLS-secured CoAP (coaps) port.
# Need to listen on a network-attached interface for 2.05 Content messages
# (generally sent as response to multicast, or as multicasts themselves)
#
# Address scope constants:
LINK_LOCAL_SCOPE = 2
SITE_LOCAL_SCOPE = 5


class IoT_Resource:
    """An IoTivity resource, described by URI path and a timestamp.

    This class is defined so that it can be stored in a set, in order to avoid
    the need to deduplicate by hand.
    """

    def __init__(self, message: Message):
        """Construct the resource."""
        self.uri = message.opt.uri_path
        self.last_seen = datetime.datetime.now()
        self.code = message.code

    def __hash__(self):
        """Hash the object by returning the hash of the URI path.

        Caveat: string hashes involve a random salt. The same string won't have
        the same hash from one execution of a script to another. Don't rely on
        storing the hashes persistently; store the source strings.
        """
        return hash(self.uri)

    def __eq__(self, other):
        """Compare objects by URI alone. Timestamp is updated otherwise."""
        return self.uri is other.uri

    def __repr__(self):
        return repr(self.uri) + " seen at " + self.last_seen.isoformat(' ')

    def update_timestamp(self):
        """Set the last_seen field to the current datetime."""
        self.last_seen = datetime.datetime.now()


class IoT_Resource_Set:
    """A synchronized collection of IoT_Resource objects."""
    def __init__(self, lock: asyncio.Lock=None):
        if lock is None:
            self.lock = asyncio.Lock()
        else:
            self.lock = lock
        self.set = set()

    async def add(self, element: IoT_Resource):
        """Add an element to the set."""
        with await self.lock:
            if element is not None and element.code is CONTENT:
                if element not in self.set:
                    set.add(element)
                else:
                    set.remove(element)
                    element.update_timestamp()
                    set.add(element)

    def __iter__(self):
        """Return an iterator for the underlying set."""
        for element in self.set:
            self.lock.acquire()
            yield element
            self.lock.release()


async def main():
    """
    Gather and store (print, currently) IoTivity resource information.

    Actively queries and passively listens for 2.05 CONTENT messages at
    multicast addresses.
    """
    link_coap_sock = bind_multicast_listener(ALL_LINK_LOCAL_COAP)
    site_coap_sock = bind_multicast_listener(ALL_SITE_LOCAL_COAP)
    link_node_sock = bind_multicast_listener(ALL_LINK_LOCAL_NODES)
    site_node_sock = bind_multicast_listener(ALL_SITE_LOCAL_NODES)
    snet_coap_sock = bind_multicast_listener(ALL_COAP_THIS_NETWORK)
    snet_node_sock = bind_multicast_listener(ALL_SYSTEMS_THIS_SUBNET)

    found = IoT_Resource_Set()
    client_protocol = await Context.create_client_context()

    while True:
        await found.add(await multicast_listen(link_coap_sock))
        await found.add(await multicast_listen(site_coap_sock))
        await found.add(await multicast_listen(link_node_sock))
        await found.add(await multicast_listen(site_node_sock))
        await found.add(await multicast_listen(snet_coap_sock))
        await found.add(await multicast_listen(snet_node_sock))
        for address in (
            ALL_COAP_THIS_NETWORK,
            ALL_SYSTEMS_THIS_SUBNET,
            v6(ALL_LINK_LOCAL_COAP),
            v6(ALL_SITE_LOCAL_COAP),
            v6(ALL_LINK_LOCAL_NODES),
            v6(ALL_SITE_LOCAL_NODES)
        ):
            for resource in await multicast(client_protocol, address):
                await found.add(resource)
        if found.set:
            print('Found resources: ')
            for resource in found:
                if resource is not None:
                    print(repr(resource))
        await asyncio.sleep(180)


def v6(addr: str) -> str:
    """Wrap an IPv6 address in square braces for use with aiocoap."""
    return '[' + addr + ']'


def uri_oic_res(addr: str) -> str:
    """Modify an IP address so that it's a complete CoAP resource URI."""
    return 'coap://' + addr + '/oic/res'


async def multicast(client_protocol: protocol.Context, address: str):
    """Send a multicast request for /oic/res, giving 10 seconds to answer."""
    answers = set()
    message = Message(code=GET, mtype=NON, uri=uri_oic_res(address))
    request = protocol.MulticastRequest(client_protocol, message)
    if not request.responses._queue.empty():
        async for response in request.responses:
            if response not in answers:
                answers.add(IoT_Resource(message))
    return answers


def bind_multicast_listener(addr: str, port: int=COAP_PORT) -> socket.socket:
    """
    Bind a socket at addr and port, and listen in non-exclusive mode.

    Creates and binds the socket, returning it with options set.
    """
    return (bind_v4_socket(addr) if "." in addr else bind_v6_socket(addr))


def bind_v4_socket(addr: str, port: int=COAP_PORT) -> socket.socket:
    """Create and bind a UDP multicast socket on an IPv4 address."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((addr, port))
    mreq = struct.pack("=4sl", socket.inet_aton(addr), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.setblocking(False)
    return sock


def bind_v6_socket(addr: str, port: int=COAP_PORT) -> socket.socket:
    """Create and bind a UDP multicast socket on an IPv6 address."""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM,
                         socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    scope_id = LINK_LOCAL_SCOPE
    if 'FF05' in addr:
        scope_id = SITE_LOCAL_SCOPE
    sock.bind((addr, port, 2, scope_id))
    sock.setblocking(False)
    return sock


async def multicast_listen(sock: socket.socket):
    """Wrap a generator so it can be awaited."""
    try:
        raw = sock.recvfrom(1152)
        message = Message.decode(raw[0], raw[1][0])
        while (message.code is not CONTENT):
            raw = sock.recvfrom(1152)
            message = Message.decode(raw[0], raw[1][0])
        return IoT_Resource(message)
    except BlockingIOError:
        return None


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
