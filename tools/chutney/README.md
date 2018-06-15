# Using chutney

Bootstrap a small testing tor network on your computer:

```
git clone https://git.torproject.org/chutney.git
cd chutney

# (see: https://gitweb.torproject.org/chutney.git/tree/README#n76)
#
# Standard usage:

./chutney configure networks/basic  # configure nodes in ./net
./chutney start networks/basic      # start the nodes
./chutney status networks/basic     # check status of the network

sleep 20                            # (wait for few network consensus)
./chutney verify networks/basic     # verify if we can send some data
./chutney stop networks/basic       # stop everything

# (see: https://gitweb.torproject.org/chutney.git/tree/README#n121)
#
# Provided chutney test script:

cd ../chutney/tools/..
sh tools/test-network.sh
```

If you get strange `Permission denied` errors in your `net/nodes/*/info.log`
files, you may want to try the attached `sandbox_patch` – this disables the
builtin sandbox that may have been misbehaving depending on which `glibc` or
`libseccomp` version you have, you can also try to update those).

You can also run the `small-chut` script as an helping script if you like to
start/stop/clean your chutney every time you use it.
