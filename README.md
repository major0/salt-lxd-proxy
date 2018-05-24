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

In Progress
-----------
Satisfying the basics:
 - services
 - packages

TODO
----
 - users
 - mounts
 - files

Thoughts
--------
Likely much of this functionality would be better handled as a separate lxd
container runtime module which abstracted these interfaces as opposed to
attempting to support them all w/in the proxy itself.

It is worth noting that the vast majority of this project would be made
obsolete by rewriting salt-ssh to support connection methods "other" than ssh
(telnet+ssl, telnet-gssapi, rsh, 'lxc exec', winrm, etc).

See Also
--------
- http://pylxd.readthedocs.io/en/latest/index.html
- https://docs.saltstack.com/en/latest/topics/proxyminion/index.html
