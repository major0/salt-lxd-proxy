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
from pylxd.exceptions import ClientConnectionFailed, LXDAPIException

# This must be present or the Salt loader won't load this module
__proxyenabled__ = ['lxd']
__virtualname__ = 'lxd'
DETAILS = {'grains_cache': {}}

# Want logging!
log = logging.getLogger(__file__) # pylint: disable=locally-disabled, invalid-name

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
    log.debug('LXD-Proxy Init')

    if opts is None:
        opts = __opts__ # pylint: disable=locally-disabled, undefined-variable

    try:
        log.debug("LXD-Proxy Init: " \
                "Client(endpoint='" + opts['proxy']['url'] + "', " \
                "cert='" + opts['proxy']['cert'] + "', " \
                "key='" + opts['proxy']['key'] + "')")
        DETAILS['server'] = Client(endpoint=opts['proxy']['url'],
                                   cert=(opts['proxy']['cert'],
                                         opts['proxy']['key']),
                                   verify=opts['proxy']['verify'])
    except ClientConnectionFailed as err:
        log.debug('LXD-Proxy Init: Client() failed')
        log.error(err)
        return False

    if not DETAILS['server'].trusted:
        # Don't log the password
        try:
            DETAILS['server'].authenticate(opts['proxy']['password'])
        except LXDAPIException as err:
            log.debug('LXD-Proxy Init: authenticate() failed')
            log.error(err)
            return False

    try:
        log.debug('LXD-Proxy Init: container.get(name=' + opts['proxy']['name'] + ')')
        DETAILS['container'] = DETAILS['server'].containers.get(opts['proxy']['name'])
    except LXDAPIException as err:
        log.debug('LXD-Proxy Init: container.get() failed')
        log.error(err)
        return False

    log.debug('LXD-Proxy Init: Success')
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
    log.debug('LXD-Proxy grains()')

    if not DETAILS['grains_cache']:
        DETAILS['container'].start()
        DETAILS['grains_cache'] = {
            # Collect information from the container object
            'virtual':      'lxd',
            'host':         DETAILS['container'].name,
            'localhost':    DETAILS['container'].name,
            'cpuarch':      DETAILS['container'].architecture,
            # No need to query this stuff..
            'username': 'root', 'uid': 0,
            'groupname': 'root', 'gid': 0,
        }

        try:
            osdata = DETAILS['container'].files.get('/etc/os-release')
            osdata = dict(item.split('=') for item in shlex.split(osdata))

            # Handle the special cases first
            if osdata['ID'].lower() in ['redhat', 'rhel']:
                DETAILS['grains_cache']['os'] = 'RedHat'
            elif osdata['ID'].lower() == 'centos':
                DETAILS['grains_cache']['os'] = 'CentOS'
            else:
                DETAILS['grains_cache']['os'] = osdata['ID'].capitalize()

            if osdata.has_key('ID_LIKE'):
                DETAILS['grains_cache']['os_family'] = osdata['ID_LIKE'].capitalize()

            # Not everyone sets the code-name, some hide it off in random other
            # places
            if osdata.has_key('VERSION_CODENAME'):
                DETAILS['grains_cache']['oscodename'] = osdata['VERSION_CODENAME']

            # Everyone at least does this one correct .. right?
            DETAILS['grains_cache']['osrelease'] = osdata['VERSION_ID']
            DETAILS['grains_cache']['osfinger'] = '%s-%s' % \
                    (DETAILS['grains_cache']['os'],
                     DETAILS['grains_cache']['osrelease'])
            DETAILS['grains_cache']['osrelease_info'] = \
                    DETAILS['grains_cache']['osrelease'].split('.')
            DETAILS['grains_cache']['osmajorrelease'] = \
                    DETAILS['grains_cache']['osrelease_info'][0]

        except LXDAPIException:
            log.error('Unsupported Linux distribution')

    # this would do better w/ some generator luvin...
    DETAILS['grains_cache']['ip_interfaces'] = {}
    DETAILS['grains_cache']['ip4_interfaces'] = {}
    DETAILS['grains_cache']['ip6_interfaces'] = {}

    for iface in DETAILS['container'].state().network.keys():
        DETAILS['grains_cache']['hwaddr_interfaces'] = \
                {iface: DETAILS['container'].state().network[iface]['hwaddr']}
        DETAILS['grains_cache']['ip_interfaces'][iface] = []
        DETAILS['grains_cache']['ip4_interfaces'][iface] = []
        DETAILS['grains_cache']['ip6_interfaces'][iface] = []
        for address in DETAILS['container'].state().network[iface]['addresses']:
            DETAILS['grains_cache']['ip_interfaces'][iface].append(address['address'])
            if address['family'] == 'inet':
                DETAILS['grains_cache']['ip4_interfaces'][iface].append(address['address'])
            elif address['family'] == 'inet6':
                DETAILS['grains_cache']['ip6_interfaces'][iface].append(address['address'])

    return DETAILS['grains_cache']


def execute(command):
    '''
    Run a command within the container
    '''
    if ping() is False:
        init()
        DETAILS['container'].start()
    try:
        _, out, _ = DETAILS['container'].execute(command)
    except TypeError:
        return None
    except LXDAPIException:
        # Restart the connection and try again
        DETAILS['container'].start()
        _, out, _ = DETAILS['container'].execute(command)
    return out.split('\n')[0]


def sendline(command):
    '''
    Run a command line within the container
    '''
    log.debug('LXD-Proxy sendline(' + command + ')')
    return execute(shlex.split(command))


def grains_refresh():
    '''
    Refresh the grains from the proxied device
    '''
    log.debug('LXD-Proxy grains_refresh()')
    DETAILS['grains_cache'] = {}
    return grains()


def ping():
    '''
    Required.
    Ping the device on the other end of the connection
    '''
    log.debug('LXD-Proxy ping()')

    if DETAILS['container'].status == 'Running':
        return True
    return False


def shutdown(_=None):
    '''
    Disconnect
    '''
    # The LXD API is restful and doesn't need shutdown.
    log.debug('LXD-Proxy shutdown()')


def package_list():
    '''
    List installed packages

    ..code-block::bash
        salt target_minion pkg.list_pkgs

    '''
    log.debug('LXD-Proxy: package_list()')
    _, out, _ = sendline('dpkg --list')
    return out


def package_install(name, **kwargs):
    '''
    Install a "package" on the ssh server
    '''
    log.debug('LXD-Proxy: package_install(' + name + ')')
    cmd = 'apt install ' + name
    if kwargs.get('version', False):
        cmd += '-' + kwargs['version']
    _, out, _ = sendline(cmd)
    return out


def package_remove(name):
    '''
    Remove a "package" on the ssh server
    '''
    log.debug('LXD-Proxy: package_remove(' + name + ')')
    _, out, _ = sendline('apt remove ' + name)
    return out


def service_list():
    '''
    List services in the container

    .. versionadded:: 2018.3.29
    '''
    log.debug('LXD-Proxy: service_list()')
    # FIXME this needs some heavy parsing
    _, out, _ = sendline('service status --status-all')
    return out


def service_start(name):
    '''
    Start a "service" in the container

    .. versionadded:: 2018.3.29
    '''
    log.debug('LXD-Proxy: service_start(' + name + ')')
    _, out, _ = sendline('service start ' + name)
    return out


def service_stop(name):
    '''
    Stop a "service" in the container

    .. versionadded:: 2018.3.29
    '''
    log.debug('LXD-Proxy: service_stop(' + name + ')')
    _, out, _ = sendline('service stop ' + name)
    return out


def service_restart(name):
    '''
    Restart a "service" on the ssh server

    .. versionadded:: 2018.3.29
    '''
    log.debug('LXD-Proxy: service_restart(' + name + ')')
    _, out, _ = sendline('service restart ' + name)
    return out
