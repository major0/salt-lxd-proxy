# -*- coding: utf-8 -*-
'''
Execution module for LXD Proxy minions

.. versionadded:: 2018.03.28

For documentation on setting up the lxd proxy minion look in the documentation
for :mod:`salt.proxy.lxd <salt.proxy.lxd>`.
'''
from __future__ import absolute_import

import salt.utils

__proxyenabled__ = ['lxd']
__virtualname__ = 'lxd'

def __virtual__():
    if salt.utils.is_proxy():
        return __virtualname__
    return (False, 'The lxd execution module failed to load: '
                   'only available on proxy minions.')

def cmd(command, *args, **kwargs):
    '''
    run commands from __proxy__
    :mod:`salt.proxy.lxd<salt.proxy.lxd>`

    command
        function from `salt.proxy.lxd` to run

    args
        positional args to pass to `command` function

    kwargs
        key word arguments to pass to `command` function

    .. code-block:: bash

        salt '*' lxd.cmd sendline 'uptime'
    '''
    proxy_prefix = __opts__['proxy']['proxytype']  # pylint: disable=locally-disabled, undefined-variable
    proxy_cmd = '.'.join([proxy_prefix, command])
    if proxy_cmd not in __proxy__: # pylint: disable=locally-disabled, undefined-variable
        return False
    for k in list(kwargs):
        if k.startswith('__pub_'):
            kwargs.pop(k)
    return __proxy__[proxy_cmd](*args, **kwargs) # pylint: disable=locally-disabled, undefined-variable
