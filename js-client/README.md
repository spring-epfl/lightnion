## lighttor-js

The Lighttor Javascript client.

_TL;DR: Use lighttor.open + lighttor.stream.tcp_

## Quick setup

**There is no release for now.**

You will have to clone the repository as follows:

```
git clone --recurse-submodules https://github.com/plcp/tor-scripts/
cd lighttor
git checkout ltor
cd js-client
make
```

Use `lighttor.bundle.js` in your projects.

## Usage

Here are a sample usage:

```
<script src="lighttor.bundle.js"></script>
<script>
lighttor.open('localhost', 4990, function(endpoint)
{
    if (endpoint.state == lighttor.state.success)
    {
        var tcp = lighttor.stream.tcp(endpoint, host, port, handler)
        tcp.send('ping')
    }
})

function handler(request)
{
    if (request.state == lighttor.state.pending)
    {
        console.log(request.recv())
        request.send('ping')
    }
}
</script>
```

See `./demo/` for more examples.

## Requirements

The bundle works on `firefox 61.0.2` and includes `sjcl+tweetnacl-js`.

If you wish to provide dependencies by yourself, include only:
```
nacl-fast.min.js
nacl-util.min.js
sjcl.js
lighttor.min.js
```
Note that you have to build few things with `sjcl.patch` to enable some
codecs.
