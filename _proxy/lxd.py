# -*- coding: utf-8 -*-
'''
LXD
===

The LXD Proxy Minion interface module for management of the Linux
services/packages within LXD container.

Tested Distributions:
    - Ubuntu
    - Debian

More in-depth reading on Proxy Minions can be found in the
:ref:`Proxy Minion <proxy-minion>` section of Salt's documentation.

Dependancies
------------

- pylxd: http://pylxd.readthedocs.io/en/latest/installation.html
- shlex

Pillar
------

The LXD API uses HTTPS and requires mutual trust between endpoints. Optionally
the LXD Proxy can authenticate to the server after establishing a secure
connection, at which point the server will automatically trust the client's
certs.

.. code-block:: shell
    openssl req -newkey rsa:2048 -nodes -keyout lxd-client.key -out lxd-client.csr
    openssl x509 -signkey lxd-client.key -in lxd-client.csr -req -days 365 -out lxd-client.crt
.. versionadded:: 2018.03.24

The lxd proxy configuration requires a 'url' property (the LXD https address),
the paths to the generated SSL 'cert' and 'key', and the 'name' of the
container to manage.  Verification of the server certificate can be disabled
with 'verify' option should the server use a self-signed certificate. The
optional 'password' entry is only used to establish trust between the client
and server certificates.  Further more, it is acceptable to generate a
different client cert/key pair for each proxy configured to contact the LXD
server.

.. code-block:: yaml
    #!yaml|gpg

    proxy:
        name: container1
        proxytype: lxd
        https_address: https://my-lxd.mydomain.com:8443
        cert: /etc/salt/pki/lxd-client.crt
        key: /etc/salt/pki/lxd-client.key
        verify: False
        password: |
            -----BEGIN PGP MESSAGE-----
                Version: GnuPG v1
            ...
            -----END PGP MESSAGE-----

.. versionadded:: 2018.03.24
'''
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
import logging
import shlex

# Import LXD Libs
from pylxd.client import Client
from pylxd.exceptions import *

# This must be present or the Salt loader won't load this module
__proxyenabled__ = ['lxd']
__virtualname__ = 'lxd'

DETAILS = { 'grains_cache': {}}

# Want logging!
log = logging.getLogger(__file__)


def __virtual__():
    '''
    Only return if all the modules are available
    '''
    log.info('lxd proxy __virtual__() called...')

    return __virtualname__


def init(opts=None):
    '''
    Required.
    Can be used to initialize the server connection.
    '''

    if opts == None:
        opts = __opts__
    try:
        DETAILS['server'] = Client(endpoint=opts['proxy']['url'],
                                   cert=(opts['proxy']['cert'],
                                         opts['proxy']['key']),
                                   verify=opts['proxy']['verify'])
        if not DETAILS['server'].trusted:
            DETAILS['server'].authenticate(opts['proxy']['password'])
        DETAILS['container'] = DETAILS['server'].get(opts['proxy']['name'])

    except (LXDAPIException, ClientConnectionFailed) as e:
        log.error(e)
        return False

    DETAILS['initialized'] = True
    return True


def initialized():
    '''
    Since grains are loaded in many different places and some of those
    places occur before the proxy can be initialized, return whether
    our init() function has been called
    '''
    return DETAILS.get('initialized', False)


def grains():
    '''
    Get the grains from the proxied device
    '''

    if not DETAILS['grains_cache']:
        DETAILS['grains_cache'] = {
                # Collect information from the container object
                'virtual':      'lxd',
                'host':         DETAILS['container'].name,
                'localhost':    DETAILS['container'].name,
                'cpuarch':      DETAILS['container'].architecture,
                'uid':          0,

                # Collect information from w/in the container
                'username':     sendline('id -un'),
                'uid':          sendline('id', '-u'),
                'groupname':    sendline('id', '-gn'),
                'gid':          sendline('id', '-g'),

                # FIXME not every distro supports lsb_release
                'os':           sendline('lsb_release -s -i'),
                'osrelease':    sendline('lsb_release -s -r'),
                'osfinger':     '%s-%s' % \
                                    (DETAILS['grains_cache']['os'],
                                     DETAILS['grains_cache']['osrelease']),
                'oscodename':   sendline('lsb_release -s -c']),
        }

        # FIXME this would do better w/ some generator luvin...
        DETAILS['grains_cache']['ip_interfaces'] = {}
        DETAILS['grains_cache']['ip4_interfaces'] = {}
        DETAILS['grains_cache']['ip6_interfaces'] = {}
        for iface in DETAILS['container'].state().network.keys():
            DETAILS['grains_cache']['hwaddr_interfaces'] = \
                { iface, DETAILS['container'].state().network[iface]['hwaddr'] }
            DETAILS['grains_cache']['ip_interfaces'][iface] = []
            DETAILS['grains_cache']['ip4_interfaces'][iface] = []
            DETAILS['grains_cache']['ip6_interfaces'][iface] = []
            for address in DETAILS['container'].state().network[iface]['addresses']:
                DETAILS['grains_cache']['ip_interfaces'][iface].append(address['address'])
                if address['family'] == 'inet':
                    DETAILS['grains_cache']['ip4_interfaces'][iface].append(address['address'])
                elif address['family'] == 'inet6':
                    DETAILS['grains_cache']['ip6_interfaces'][iface].append(address['address'])

    return {'lxd': DETAILS['grains_cache']}


def execute(command=[]):
    '''
    Run a command within the container
    '''
    if ping() is False:
        init()
    DETAILS['container'].start()
    ret, out, err = DETAILS['container'].execute(command)
    return out.split('\n')[0]


def sendline(command):
    '''
    Run a command line within the container
    '''
    return execute(shlex.split(command))


def grains_refresh():
    '''
    Refresh the grains from the proxied device
    '''
    DETAILS['grains_cache'] = {}
    return grains()


def ping():
    '''
    Required.
    Ping the device on the other end of the connection
    '''
    try:
        DETAILS['container'].start()
        if DETAILS['container'].status() == 'Running':
            return True
    except ClientConnectionFailed as e:
        log.error(e)
    return False


def shutdown(opts):
    '''
    Disconnect
    '''
    # The LXD API is restful and doesn't need shutdown.


def package_list():
    '''
    List "packages" by executing a command via ssh
    This function is called in response to the salt command

    ..code-block::bash
        salt target_minion pkg.list_pkgs

    '''
    # Send the command to execute
    out, err = DETAILS['server'].sendline('pkg_list\n')

    # "scrape" the output and return the right fields as a dict
    return parse(out)


def package_install(name, **kwargs):
    '''
    Install a "package" on the ssh server
    '''
    cmd = 'pkg_install ' + name
    if kwargs.get('version', False):
        cmd += ' ' + kwargs['version']

    # Send the command to execute
    out, err = DETAILS['server'].sendline(cmd)

    # "scrape" the output and return the right fields as a dict
    return parse(out)


def package_remove(name):
    '''
    Remove a "package" on the ssh server
    '''
    cmd = 'pkg_remove ' + name

    # Send the command to execute
    out, err = DETAILS['server'].sendline(cmd)

    # "scrape" the output and return the right fields as a dict
    return parse(out)


def service_list():
    '''
    Start a "service" on the ssh server

    .. versionadded:: 2015.8.2
    '''
    cmd = 'ps'

    # Send the command to execute
    out, err = DETAILS['server'].sendline(cmd)

    # "scrape" the output and return the right fields as a dict
    return parse(out)


def service_start(name):
    '''
    Start a "service" on the ssh server

    .. versionadded:: 2015.8.2
    '''
    cmd = 'start ' + name

    # Send the command to execute
    out, err = DETAILS['server'].sendline(cmd)

    # "scrape" the output and return the right fields as a dict
    return parse(out)


def service_stop(name):
    '''
    Stop a "service" on the ssh server

    .. versionadded:: 2015.8.2
    '''
    cmd = 'stop ' + name

    # Send the command to execute
    out, err = DETAILS['server'].sendline(cmd)

    # "scrape" the output and return the right fields as a dict
    return parse(out)


def service_restart(name):
    '''
    Restart a "service" on the ssh server

    .. versionadded:: 2015.8.2
    '''
    cmd = 'restart ' + name

    # Send the command to execute
    out, err = DETAILS['server'].sendline(cmd)

    # "scrape" the output and return the right fields as a dict
    return parse(out)
