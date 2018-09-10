# https://docs.python.org/3/library/asyncio-protocol.html

#
# 1st draft (see below for 2nd draft)
#

# perform handshake (as client) -> br.accept(handler) as server
async with br.link(host, port, *, ssl, transport=br.io.link) as link:
    await link.write(*cells) # sends all cells provided

    async with link.fast(*, transport=br.io.circuit) as circuit:
    async with link.ntor(descriptor, transport=br.io.circuit) as circuit:
        circuit.write(*payloads) # sends all payloads provided (add header)

        # extend the circuit to target nodes
        await circuit.extend(*descriptors)

        async with circuit.raw(*, transport=br.io.stream) as raw:
            raw.write(*payloads) # sends all payloads provided (add header)

            # receive RELAY payloads
            async for payload in raw:
                # perform work

        async with circuit.dir(query, *, transport=br.io.stream) as request:
            request.{headers,data,text, ...} # (query already performed)

        # returns the protocol
        async with circuit.tcp(host, port, *,
            protocol=br.io.socket, transport=br.io.stream) as socket:

            # socket-like interface
            socket.send(data)
            socket.recv()

# class custom(br.io.{link,circuit,stream}):
#    # custom control (or non-"relay_data") cells handling
#    async def perform_control(self, cells): # (cells is an async generator)
#        async for cell in super().perform_control(cells):
#            # ... do some work ...
#            if condition:
#                yield cell # cells not yielded are hidden in lower layers

#
# 2nd draft (see below for stack summary)
#

async with br.link(host, port, handler=None, *, ssl, transport=br.t.link) as link:
    # note that explicitly ssl=None must be stated to disable ssl cert. auth.
    #   (a context can be provided either way)
    #
    # if (handler == None), defaults to br.lp.initiator (if br.link)
    #                                or br.lp.responder (if br.accept)
    #
    # (inherit from br.lp.basic)
    # (context manager can only be used if (handler == None) here)
    #
    # See link.fast below for handler-related behaviors.
    #
    #
    # br.link is a convenience wrapper around:
    #   br.create_link(br.io.ssl, br.lp.initiator, *kargs, *
    #       transport=br.t.link, loop=None)
    # br.accept is a convenience wrapper around:
    #   br.create_link(br.io.ssl, br.lp.responder, *kargs, *,
    #       transport=br.t.link, loop=None)
    #
    # (where internally br.io.ssl is build using given br.lp, kargs & loop)
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

    async with link.fast(handler=None, *, transport=br.t.circuit) as circuit:
        # if (handler == None), defaults to br.cp.fast  (if link.fast)
        #                                or br.cp.ntor  (if link.ntor)
        # (inherit from br.cp.basic)
        # (context manager can only be used if (handler == None) here)
        #
        #
        # link.fast is a convenience wrapper around:
        #   br.create_circuit(br.cp.fast, link, *kargs, *,
        #       transport=br.t.circuit)
        #
        # link.ntor is a convenience wrapper around:
        #   br.create_circuit(br.cp.ntor, link, *kargs, *,
        #       transport=br.t.circuit)
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
    async with link.fast(handler=None, *, transport=br.io.circuit) as circuit:
        await handler(circuit)

    # thus expected call is:
    asyncio.ensure_future(link.fast(handler))

# pre-build transports:
#   br.t.link for bronion.transports.link
#   br.t.circuit for bronion.transports.circuit
#   br.t.stream for bronion.transports.stream

# pre-build protocols:
#   br.lp for bronion.link_protocols
#       br.lp.basic
#       br.lp.initiator
#       br.lp.responder
#   br.cp for bronion.circuit_protocols
#       br.cp.basic
#       br.cp.raw
#       br.cp.fast
#       br.cp.ntor
#   br.sp for bronion.stream_protocols
#       br.sp.basic
#       br.sp.raw
#       br.sp.dir
#       br.sp.tcp
#   br.dp for bronion.data_protocols
#       br.dp.basic
#       br.dp.socket

# stack summary
#
# · br.link
# | ~ br.create_link
# |
# | io
# | br.transports.link
# | br.link_protocols.{initiator, responder} (responder NOT implemented)
# |
# · link.{raw, fast, ntor}
# | ~ br.create_circuit
# |
# | br.transports.circuit
# | br.circuit_protocols.{raw, fast, ntor}
# |
# · circuit.{raw, dir, tcp}
# | ~ br.create_stream
# |
# | br.transports.stream
# | br.stream_protocols.{raw, dir, tcp}
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

# providing a br.adapters.socket(circuit) can be fun
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
# providing a br.adapters.requests(circuit) can be fun
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
# providing a br.adapters.directory(circuit) can be fun
#   - same a br.adapters.requests, but create dir streams instead
#
#       adapters.HTTPAdapter (but building dir streams)
#
