# -*- coding: utf-8 -*-
'''
Provide the service module for the lxd proxy used in integration tests
'''
# Import python libs
from __future__ import absolute_import, print_function, unicode_literals
import logging

# Import Salt libs
import salt.utils.platform


log = logging.getLogger(__name__) # pylint: disable=locally-disabled,invalid-name


__func_alias__ = {
    'list_': 'list'
}


# Define the module's virtual name
__virtualname__ = 'service'


def __virtual__():
    '''
    Only work on systems that are an lxd proxy minion
    '''
    try:
        if salt.utils.platform.is_proxy() \
                and __opts__['proxy']['proxytype'] == 'lxd': # pylint: disable=locally-disabled,undefined-variable
            return __virtualname__
    except KeyError:
        return (
            False,
            'The lxd_service execution module failed to load. Check '
            'the proxy key in pillar or /etc/salt/proxy.'
        )

    return (
        False,
        'The lxd_service execution module failed to load: only works '
        'on the integration testsuite lxd proxy minion.'
    )


def get_all():
    '''
    Return a list of all available services

    .. versionadded:: 2018.05.24

    CLI Example:

    .. code-block:: bash

        salt '*' service.get_all
    '''
    proxy_fn = 'lxd.service_list'
    return __proxy__[proxy_fn]() # pylint: disable=locally-disabled,undefined-variable


def list_():
    '''
    Return a list of all available services.

    .. versionadded:: 2018.05.24

    CLI Example:

    .. code-block:: bash

        salt '*' service.list
    '''
    return get_all()


def start(name, sig=None): # pylint: disable=locally-disabled,unused-argument
    '''
    Start the specified service on the lxd

    .. versionadded:: 2018.05.24

    CLI Example:

    .. code-block:: bash

        salt '*' service.start <service name>
    '''
    proxy_fn = 'lxd.service_start'
    return __proxy__[proxy_fn](name) # pylint: disable=locally-disabled,undefined-variable


def stop(name, sig=None): # pylint: disable=locally-disabled,unused-argument
    '''
    Stop the specified service on the lxd

    .. versionadded:: 2018.05.24

    CLI Example:

    .. code-block:: bash

        salt '*' service.stop <service name>
    '''
    proxy_fn = 'lxd.service_stop'
    return __proxy__[proxy_fn](name) # pylint: disable=locally-disabled, undefined-variable


def restart(name, sig=None): # pylint: disable=locally-disabled,unused-argument
    '''
    Restart the specified service with lxd.

    .. versionadded:: 2018.05.24

    CLI Example:

    .. code-block:: bash

        salt '*' service.restart <service name>
    '''
    proxy_fn = 'lxd.service_restart'
    return __proxy__[proxy_fn](name) # pylint: disable=locally-disabled, undefined-variable


def status(name, sig=None): # pylint: disable=locally-disabled,unused-argument
    '''
    Return the status for a service via lxd, returns a bool
    whether the service is running.

    .. versionadded:: 2018.05.24

    CLI Example:

    .. code-block:: bash

        salt '*' service.status <service name>
    '''
    proxy_fn = 'lxd.service_status'
    resp = __proxy__[proxy_fn](name) # pylint: disable=locally-disabled, undefined-variable
    if resp['comment'] == 'stopped':
        return False
    if resp['comment'] == 'running':
        return True


def running(name, sig=None): # pylint: disable=locally-disabled,unused-argument
    '''
    Return whether this service is running.

    .. versionadded:: 2018.05.24

    '''
    proxy_fn = 'lxd.service_status'
    resp = __proxy__[proxy_fn](name) # pylint: disable=locally-disabled, undefined-variable
    if resp['comment'] == 'running':
        return True
    return False


def enabled(name, sig=None): # pylint: disable=locally-disabled,unused-argument
    '''
    Only the 'redbull' service is 'enabled' in the test

    .. versionadded:: 2018.05.24

    '''
    return name == 'redbull'
