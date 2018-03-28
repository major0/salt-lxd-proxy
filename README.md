Salt LXD Proxy
==============

The goal of the LXD proxy is to allow one to manage environments of a LXD Linux
Container without the need for running a Salt Minion within the container
itself. This is particularly useful as a container need not be attached to the
same network as the host.  For example a DMZ facing container where the
management of the host is done from the private network.  Further more, since a
container shares its primary resources with the host, there is less within the
container to monitor/manage.

Currently the LXD Proxy Minion only supports contacting the LXD server and
collecting grains information about the target container.

TODO
----
To satisfy the basics of the example proxy API we need to support at minimum
the following:
 - services
 - packages

Management of these would also be useful.
 - users
 - mounts
 - files

Likely much of this functionality would be better handled as a separate lxd
container runtime module which abstracted these interfaces as opposed to
attempting to support them all w/in the proxy itself.

See Also
--------
- http://pylxd.readthedocs.io/en/latest/index.html
- https://docs.saltstack.com/en/latest/topics/proxyminion/index.html
