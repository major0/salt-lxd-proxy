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

Pillar
------

The LXD API uses HTTPS and requires mutual trust between endpoints. Optionally
the LXD Proxy can authenticate to the server after establishing a secure
connection, at which point the server will automatically trust the client's
certs.

.. code-block:: shell
    openssl req -newkey rsa:2048 -nodes -keyout lxd.key -out lxd-client.csr
    openssl x509 -signkey lxd.key -in lxd.csr -req -days 365 -out lxd-client.crt
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

# Import LXD Libs
import pylxd

# This must be present or the Salt loader won't load this module
__proxyenabled__ = ['lxd']

DETAILS = {}

# Want logging!
log = logging.getLogger(__file__)


# This does nothing, it's here just as an example and to provide a log
# entry when the module is loaded.
def __virtual__():
    '''
    Only return if all the modules are available
    '''
    log.info('lxd proxy __virtual__() called...')

    return True


def init(opts):
    '''
    Required.
    Can be used to initialize the client connection.
    '''

    try:
        DETAILS['client'] = pylxd.client.Client(endpoint=__opts__['proxy']['url'],
                                                cert=(__opts__['proxy']['cert'],
                                                      __opts__['proxy']['key']),
                                                verify=__opts__['proxy']['verify'])
        if not DETAILS['client'].trusted:
            DETAILS['client'].authenticate(__opts__['proxy']['password'])
        DETAILS['container'] = DETAILS['client'].get(__opts__['proxy']['name'])
        DETAILS['initialized'] = True
        return True
    except ClientConnectionFailed as e:
        return False


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

    if not DETAILS.get('grains_cache', {}):
        ##
        # Collect information from the container object
        DETAILS['grains_cache']['virtual'] = 'container'
        DETAILS['grains_cache']['host'] = container.name
        DETAILS['grains_cache']['nodename'] = container.name
        DETAILS['grains_cache']['localhost'] = container.name
        DETAILS['grains_cache']['cpuarch'] = DETAILS['container'].architecture
        DETAILS['grains_cache']['uid'] = 0

        ##
        # Collect information from w/in the container
        container.start()
        ret, stdout, stderr = container.execute(['id', '-un'])
        DETAILS['grains_cache']['username'] = stdout.split('\n')[0]
        ret, stdout, stderr = container.execute(['id', '-u'])
        DETAILS['grains_cache']['uid'] = stdout.split('\n')[0]
        ret, stdout, stderr = container.execute(['id', '-gn'])
        DETAILS['grains_cache']['groupname'] = stdout.split('\n')[0]
        ret, stdout, stderr = container.execute(['id', '-g'])
        DETAILS['grains_cache']['gid'] = stdout.split('\n')[0]

        # FIXME not every distro supports lsb_release
        ret, stdout, stderr = container.execute(['lsb_release', '-s', '-i'])
        DETAILS['grains_cache']['os'] = stdout.split('\n')[0]
        ret, stdout, stderr = container.execute(['lsb_release', '-s', '-r'])
        DETAILS['grains_cache']['osrelease'] = stdout.split('\n')[0]
        DETAILS['grains_cache']['osfinger'] = '%s-%s' % \
                (DETAILS['grains_cache']['os'], DETAILS['grains_cache']['osrelease'])
        ret, stdout, stderr = container.execute(['lsb_release', '-s', '-c'])
        DETAILS['grains_cache']['oscodename'] = stdout.split('\n')[0]

        # FIXME this would do better w/ some generator luvin...
        DETAILS['grains_cache']['ip_interfaces'] = {}
        DETAILS['grains_cache']['ip4_interfaces'] = {}
        DETAILS['grains_cache']['ip6_interfaces'] = {}
        for iface in container.state().network.keys():
            DETAILS['grains_cache']['hwaddr_interfaces'] = \
                { iface, container.state().network[iface]['hwaddr'] }
            DETAILS['grains_cache']['ip_interfaces'][iface] = []
            DETAILS['grains_cache']['ip4_interfaces'][iface] = []
            DETAILS['grains_cache']['ip6_interfaces'][iface] = []
            for address in container.state().network[iface]['addresses']:
                DETAILS['grains_cache']['ip_interfaces'][iface].append(address['address'])
                if address['family'] == 'inet':
                    DETAILS['grains_cache']['ip4_interfaces'][iface].append(address['address'])
                elif address['family'] == 'inet6':
                    DETAILS['grains_cache']['ip6_interfaces'][iface].append(address['address'])

    return DETAILS['grains_cache']


def grains_refresh():
    '''
    Refresh the grains from the proxied device
    '''
    DETAILS['grains_cache'] = None
    return grains()


def fns():
    return {'details': 'This key is here because a function in '
            'grains/ssh_sample.py called fns() here in the proxymodule.'}


def ping():
    '''
    Required.
    Ping the device on the other end of the connection
    '''
    try:
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
