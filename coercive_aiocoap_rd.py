"""
Gather information about IoTivity resources on the network by way of multicast.
See README.md for in-depth module description.
@author: Noah Cain
"""

import logging
import asyncio
from aiocoap import Context, Message, protocol
from aiocoap.error import UnparsableMessage
from aiocoap.numbers import GET, NON, CONTENT
from contextlib import suppress
import socket
import struct
import sqlite3
import cbor2


logging.basicConfig(level=logging.INFO)
logging.disable(logging.INFO)

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
#
# Address scope constants:
LINK_LOCAL_SCOPE = 2
SITE_LOCAL_SCOPE = 5

# Well-Known IoTivity resources (uninteresting - don't collect info about them)
# also incomplete
WELL_KNOWN_TYPES = (
    'oic.wk.ad', 'oic.wk.p', 'oic.wk.d', 'oic.r.pstat', 'oic.r.doxm'
    )

running = True


class IoT_Resource:
    """A simple representation of an IoTivity resource at a particular URI."""
    def __init__(self, path: str, resource_type: str):
        self.path = path
        self.type = resource_type

    def __eq__(self, other):
        return self.path == other.path

    def __ne__(self, other):
        return not self.__eq__(other)


def connect_to_database(sqlite_db_file: str) -> sqlite3.Connection:
    try:
        return sqlite3.connect(sqlite_db_file)
    except sqlite3.Error:
        print('Failed to create a connection to the database.')


async def _insert(cursor: sqlite3.Cursor, message: Message,
                  client_protocol: Context):
    if message is None:
        print('Why are we getting None messages!?')
    elif message.code is CONTENT:
        for resource in await get_resource_links(client_protocol, message):
            cursor.execute("""REPLACE INTO resources
                              (uri, type)
                              VALUES (?, ?)""", (resource.path, resource.type))


async def main(database_connection: sqlite3.Connection,
               cursor: sqlite3.Cursor):
    """
    Gather and store (print, currently) IoTivity resource information.

    Actively queries and passively listens for 2.05 CONTENT messages at
    multicast addresses.
    """
    cursor.execute("""CREATE TABLE IF NOT EXISTS resources (
                   id integer PRIMARY KEY,
                   uri text UNIQUE NOT NULL,
                   type text NOT NULL,
                   last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                   );""")
    sockets = list()
    for address in (
        ALL_LINK_LOCAL_COAP,
        ALL_SITE_LOCAL_COAP,
        ALL_LINK_LOCAL_NODES,
        ALL_COAP_THIS_NETWORK,
        ALL_SYSTEMS_THIS_SUBNET,
        ALL_SITE_LOCAL_NODES
    ):
        sockets.append(bind_multicast_listener(address))

    client_protocol = await Context.create_client_context()
    while running:
        for sock in sockets:
            async for resource in multicast_listen(sock, client_protocol):
                await _insert(cursor, resource, client_protocol)
        for address in (
            ALL_COAP_THIS_NETWORK,
            ALL_SYSTEMS_THIS_SUBNET,
            v6(ALL_LINK_LOCAL_COAP),
            v6(ALL_SITE_LOCAL_COAP),
            v6(ALL_LINK_LOCAL_NODES),
            v6(ALL_SITE_LOCAL_NODES)
        ):
            for resource in await multicast(client_protocol, address):
                await _insert(cursor, resource, client_protocol)
        cursor.execute('SELECT uri, last_seen FROM resources')
        all_rows = cursor.fetchall()
        if all_rows:
            print('Found resources: ')
            for row in cursor:
                print(row["uri"] + ' last seen at ' + row["last_seen"])
        await asyncio.sleep(10)


def v6(addr: str) -> str:
    """Wrap an IPv6 address in square braces for use with aiocoap."""
    return '[' + addr + ']'


def uri_oic_res(addr: str) -> str:
    """Modify an IP address so that it's a complete CoAP resource URI."""
    return 'coap://' + addr + '/oic/res'


async def unicast_request(client_protocol: Context, address: str,
                          resource: str='/oic/res', resource_type: str=None,
                          destport: int=COAP_PORT):
    """Send a unicast request for a resource at address via client_protocol"""
    request_uri = 'coap://' + address + resource
    if resource_type is not None:
        request_uri += '?rt=' + resource_type
    msg = Message(code=GET, mtype=NON, uri=request_uri)
    req = protocol.Request(client_protocol, msg)
    response = await req.response
    return response if response.code is CONTENT else None


async def multicast(client_protocol: Context, address: str):
    """Send a multicast request for /oic/res once.

    Well, ask the aiocoap library to request once. It requests six times.

    Returns an aiocoap Message.
    """
    answers = set()
    message = Message(code=GET, mtype=NON, uri=uri_oic_res(address))
    request = protocol.MulticastRequest(client_protocol, message)
    with suppress(asyncio.StopAsyncIteration):
        # which should be implicitly caught and handled by async for...
        async for response in request.responses:
            if response not in answers:
                answers.add(message)
    return answers


def bind_multicast_listener(addr: str, port: int=COAP_PORT) -> socket.socket:
    """
    Bind a socket at addr and port.

    Creates and binds the socket, returning it with appropriate options set.
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


async def multicast_listen(sock: socket.socket,
                           client_protocol: Context) -> IoT_Resource:
    """Wrap recvfrom in an async generator which yields aiocoap Messages."""
    while True:
        try:
            # PATH IS ONLY EVER /oic/ad
            # because it's decoded from metadata, NOT payload!
            # Need to parse raw[0] ourselves, most likely.
            # although uri-host should be about "the resource being requested"
            # ...is the IoTivity Presence Server example out-of-spec?
            # further investigation is needed.
            #
            # message.payload is CBOR encoded (in this case - how to tell?)
            # message.payload is also CBOR when running simpleserver and client
            #
            # grabbing and reading pcaps isn't necessarily the most efficient
            # way to determine payload encoding. URI-Path is /oic/res when in
            # the simpleserver and simpleclient pcap, so URI-Path was a dead
            # end either way. Need to parse the payload.
            with suppress(UnparsableMessage):
                raw = sock.recvfrom(1152)
                message = Message.decode(rawdata=raw[0], remote=raw[1][0])
                print('payload: ' + repr(message.payload))
                print('options:')
                for number, option in message.opt._options.items():
                    print(repr(number) + ':')
                    for element in option:
                        print(element.value)
                links = await get_resource_links(client_protocol, message)
                while (message.code is not CONTENT or links is None):
                    raw = sock.recvfrom(1152)
                    message = Message.decode(raw[0], raw[1][0])
                    links = await get_resource_links(client_protocol, message)
                for link in links:
                    yield link
        except BlockingIOError:
            await asyncio.sleep(5)


def get_resource_types(message: Message) -> list:
    """Parse a message payload in search of an 'rt' field."""
    print('Getting types from message ' + message.mid + ' from '
          + message.remote + ' sent to ' + message.opt.uri_host)
    types = list()
    if message.payload:
        payload = cbor2.loads(message.payload)
        if isinstance(payload, dict) and 'rt' in payload:
            types.append(payload.get('rt'))
        elif isinstance(payload, list) and 'links' in payload[0]:
            for link in payload[0]['links']:
                for resource_type in link['rt']:
                    if resource_type not in WELL_KNOWN_TYPES:
                        types.append(resource_type)
    return types if types else None


async def get_resource_links(client_protocol: Context,
                             message: Message) -> list:
    """Parse a message payload in search of 'href' fields."""
    print('Getting links from message ' + message.mid + ' from '
          + message.remote + ' sent to ' + message.opt.uri_host)
    links = list()
    host = message.remote
    if message.payload:
        payload = cbor2.loads(message.payload)
        if isinstance(payload, list) and 'links' in payload[0]:
            payload = payload[0]
        if isinstance(payload, dict) and 'links' in payload:
            for link in payload['links']:
                for resource_type in link['rt']:
                    if (resource_type not in WELL_KNOWN_TYPES):
                        res = IoT_Resource(host + link['href'], resource_type)
                        if res in links:
                            for current in links:
                                if res == current:
                                    current.resource_type += ', '
                                    current.resource_type += resource_type
                        else:
                            links.append(res)
        elif isinstance(payload, dict) and 'href' in payload:
            links.append(link['href'])
        elif isinstance(payload, dict) and 'rt' in payload:
            # send a GET for whatever resource type at the port used in message
            for resource_type in get_resource_types(message):
                response = await unicast_request(client_protocol,
                                                 message.remote,
                                                 '/oic/res',
                                                 resource_type,
                                                 message.opt.uri_port)
                links.append(await get_resource_links(client_protocol,
                                                      response))
    return links if links else None


if __name__ == "__main__":
    database_connection = connect_to_database('known_resources.db')
    cursor = database_connection.cursor()
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(main(database_connection, cursor))
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        running = False
        pending = asyncio.Task.all_tasks()
        for task in pending:
            task.cancel()
            with suppress(asyncio.CancelledError):
                loop.run_until_complete(task)
        loop.close()
        cursor.close()
        database_connection.commit()
        database_connection.close()
        print()
