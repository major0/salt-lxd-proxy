# -*- coding: utf-8 -*-
'''
Package support for the lxd proxy
'''
from __future__ import absolute_import, print_function, unicode_literals

# Import python libs
import logging
import salt.utils.data
import salt.utils.platform
from salt.ext import six


log = logging.getLogger(__name__) # pylint: disable=locally-disabled,invalid-name


# Define the module's virtual name
__virtualname__ = 'pkg'


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
            'The lxd_package execution module failed to load. Check '
            'the proxy key in pillar or /etc/salt/proxy.'
        )

    return (
        False,
        'The lxd_package execution module failed to load: only works '
        'on a lxd proxy minion.'
    )


def list_pkgs(versions_as_list=False, **kwargs): # pylint: disable=locally-disabled,unused-argument
    '''
    List packages installed into an lxd container
    '''
    return __proxy__['lxd.package_list']() # pylint: disable=locally-disabled,undefined-variable


def install(name=None, refresh=False, fromrepo=None,  # pylint: disable=locally-disabled,unused-argument
            pkgs=None, sources=None, **kwargs): # pylint: disable=locally-disabled,unused-argument
    '''
    Install packages into an lxd container
    '''
    return __proxy__['lxd.package_install'](name, **kwargs) # pylint: disable=locally-disabled,undefined-variable


def remove(name=None, pkgs=None, **kwargs): # pylint: disable=locally-disabled,unused-argument
    '''
    Remove packages from an lxd container
    '''
    return __proxy__['lxd.package_remove'](name) # pylint: disable=locally-disabled,undefined-variable


def version(*names, **kwargs): # pylint: disable=locally-disabled,unused-argument
    '''
    Returns a string representing the package version or an empty string if not
    installed. If more than one package name is specified, a dict of
    name/version pairs is returned.

    CLI Example:

    .. code-block:: bash

        salt '*' pkg.version <package name>
        salt '*' pkg.version <package1> <package2> <package3> ...
    '''
    if len(names) == 1:
        vers = __proxy__['lxd.package_status'](names[0]) # pylint: disable=locally-disabled,undefined-variable
        return vers[names[0]]
    else:
        results = {}
        for name in names:
            vers = __proxy__['lxd.package_status'](name) # pylint: disable=locally-disabled,undefined-variable
            results.update(vers)
        return results


def upgrade(name=None, pkgs=None, refresh=True, skip_verify=True,  # pylint: disable=locally-disabled,unused-argument
            normalize=True, **kwargs): # pylint: disable=locally-disabled,unused-argument
    '''
    Upgrade packages installed into an lxd container
    '''
    old = __proxy__['lxd.package_list']() # pylint: disable=locally-disabled,undefined-variable
    new = __proxy__['lxd.uptodate']() # pylint: disable=locally-disabled,undefined-variable,unused-variable
    pkg_installed = __proxy__['lxd.upgrade']() # pylint: disable=locally-disabled,undefined-variable
    ret = salt.utils.data.compare_dicts(old, pkg_installed)
    return ret


def installed(name,
              ver=None,
              refresh=False,
              fromrepo=None,
              skip_verify=False,
              pkgs=None,
              sources=None,
              **kwargs): # pylint: disable=locally-disabled,unused-argument,too-many-arguments
    '''
    Return the installation status of a package in an lxd container
    '''
    package = __proxy__['lxd.package_status'](name) # pylint: disable=locally-disabled,undefined-variable
    if ver is None:
        if 'ret' in package:
            return six.text_type(package['ret'])
        else:
            return True
    else:
        if package is not None:
            return ver == six.text_type(package)
