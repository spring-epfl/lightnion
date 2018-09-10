# https://docs.python.org/3/library/asyncio-protocol.html

#
# 1st draft (see below for 2nd draft)
#

# perform handshake (as client) -> lnn.accept(handler) as server
async with lnn.link(host, port, *, ssl, transport=lnn.io.link) as link:
    await link.write(*cells) # sends all cells provided

    async with link.fast(*, transport=lnn.io.circuit) as circuit:
    async with link.ntor(descriptor, transport=lnn.io.circuit) as circuit:
        circuit.write(*payloads) # sends all payloads provided (add header)

        # extend the circuit to target nodes
        await circuit.extend(*descriptors)

        async with circuit.raw(*, transport=lnn.io.stream) as raw:
            raw.write(*payloads) # sends all payloads provided (add header)

            # receive RELAY payloads
            async for payload in raw:
                # perform work

        async with circuit.dir(query, *, transport=lnn.io.stream) as request:
            request.{headers,data,text, ...} # (query already performed)

        # returns the protocol
        async with circuit.tcp(host, port, *,
            protocol=lnn.io.socket, transport=lnn.io.stream) as socket:

            # socket-like interface
            socket.send(data)
            socket.recv()

# class custom(lnn.io.{link,circuit,stream}):
#    # custom control (or non-"relay_data") cells handling
#    async def perform_control(self, cells): # (cells is an async generator)
#        async for cell in super().perform_control(cells):
#            # ... do some work ...
#            if condition:
#                yield cell # cells not yielded are hidden in lower layers

#
# 2nd draft (see below for stack summary)
#

async with lnn.link(host, port, handler=None, *, ssl, transport=lnn.t.link) as link:
    # note that explicitly ssl=None must be stated to disable ssl cert. auth.
    #   (a context can be provided either way)
    #
    # if (handler == None), defaults to lnn.lp.initiator (if lnn.link)
    #                                or lnn.lp.responder (if lnn.accept)
    #
    # (inherit from lnn.lp.basic)
    # (context manager can only be used if (handler == None) here)
    #
    # See link.fast below for handler-related behaviors.
    #
    #
    # lnn.link is a convenience wrapper around:
    #   lnn.create_link(lnn.io.ssl, lnn.lp.initiator, *kargs, *
    #       transport=lnn.t.link, loop=None)
    # lnn.accept is a convenience wrapper around:
    #   lnn.create_link(lnn.io.ssl, lnn.lp.responder, *kargs, *,
    #       transport=lnn.t.link, loop=None)
    #
    # (where internally lnn.io.ssl is build using given lnn.lp, kargs & loop)
    #
    #
    # They all have extra callbacks:
    #   raw(self, data)         (called with raw incoming payloads)
    #   ready(self)             (called when the link is ready)
    #   early(self, cell)       (called before each cell is handled)
    #   control(self, cell)     (called with control cells not handled)
    #
    # And expose:
    #   fast
    #   ntor

    async with link.fast(handler=None, *, transport=lnn.t.circuit) as circuit:
        # if (handler == None), defaults to lnn.cp.fast  (if link.fast)
        #                                or lnn.cp.ntor  (if link.ntor)
        # (inherit from lnn.cp.basic)
        # (context manager can only be used if (handler == None) here)
        #
        #
        # link.fast is a convenience wrapper around:
        #   lnn.create_circuit(lnn.cp.fast, link, *kargs, *,
        #       transport=lnn.t.circuit)
        #
        # link.ntor is a convenience wrapper around:
        #   lnn.create_circuit(lnn.cp.ntor, link, *kargs, *,
        #       transport=lnn.t.circuit)
        #
        # (where protocol is build using link and *kargs)
        #
        #
        # They all have extra callbacks:
        #   ready(self)                 (called when the circuit is ready)
        #   early(self, cell)           (called before each cell is handled)
        #   control(self, cell)         (called with control cells not handled)
        #   destroyed(self, reason)     (called when a DESTROY cell comes)
        #
        # And expose:
        #   raw
        #   dir
        #   tcp

    # if handler is a callable, the transport is passed as:
    async with link.fast(handler=None, *, transport=lnn.io.circuit) as circuit:
        await handler(circuit)

    # thus expected call is:
    asyncio.ensure_future(link.fast(handler))

# pre-build transports:
#   lnn.t.link for lightnion.transports.link
#   lnn.t.circuit for lightnion.transports.circuit
#   lnn.t.stream for lightnion.transports.stream

# pre-build protocols:
#   lnn.lp for lightnion.link_protocols
#       lnn.lp.basic
#       lnn.lp.initiator
#       lnn.lp.responder
#   lnn.cp for lightnion.circuit_protocols
#       lnn.cp.basic
#       lnn.cp.raw
#       lnn.cp.fast
#       lnn.cp.ntor
#   lnn.sp for lightnion.stream_protocols
#       lnn.sp.basic
#       lnn.sp.raw
#       lnn.sp.dir
#       lnn.sp.tcp
#   lnn.dp for lightnion.data_protocols
#       lnn.dp.basic
#       lnn.dp.socket

# stack summary
#
# · lnn.link
# | ~ lnn.create_link
# |
# | io
# | lnn.transports.link
# | lnn.link_protocols.{initiator, responder} (responder NOT implemented)
# |
# · link.{raw, fast, ntor}
# | ~ lnn.create_circuit
# |
# | lnn.transports.circuit
# | lnn.circuit_protocols.{raw, fast, ntor}
# |
# · circuit.{raw, dir, tcp}
# | ~ lnn.create_stream
# |
# | lnn.transports.stream
# | lnn.stream_protocols.{raw, dir, tcp}
# @

# raw protocols gives direct access to cell reader/writer
async with circuit.raw() as stream:
    reader, writer = stream.get_transports()

def handler(reader, writer):
    pass

asyncio.ensure_future(circuit.raw(handler))

# tcp also gives direct access, but to data reader/writer
async with circuit.tcp(host, port) as stream:
    reader, writer = stream.get_transports()

def handler(reader, writer):
    pass

asyncio.ensure_future(circuit.tcp(handler))

# dir is just like tcp, but sends a BEGIN_DIR instead

# providing a lnn.adapters.socket(circuit) can be fun
#   - returns an object that exposes main socket modules functions
#       create_connection
#
#       close
#       getblocking
#       gettimeout
#       recv
#       recvfrom
#       recv_into
#       send
#       sendall
#       sendfile
#       setblocking
#       settimeout
#
#       # goals:
#       #   - have python native ssl module working
#       #   - have asyncio.get_event_loop().create_connection(sock=) working
#
# providing a lnn.adapters.requests(circuit) can be fun
#   - returns an object that exposes main requests module functions
#
#       adapters.HTTPAdapter (must work for both HTTP & HTTPs)
#       Session (builds a session object, but with the right adapters)
#
#       request
#       head
#       get
#       post
#       put
#       patch
#       delete
#
# providing a lnn.adapters.directory(circuit) can be fun
#   - same a lnn.adapters.requests, but create dir streams instead
#
#       adapters.HTTPAdapter (but building dir streams)
#
