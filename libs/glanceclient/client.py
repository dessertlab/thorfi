# Copyright 2012 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import warnings

#from oslo_utils import importutils
import sys
from glanceclient.common import utils


def Client(version=None, endpoint=None, session=None, *args, **kwargs):
    """Client for the OpenStack Images API.

    Generic client for the OpenStack Images API. See version classes
    for specific details.

    :param string version: The version of API to use.
    :param session: A keystoneauth1 session that should be used for transport.
    :type session: keystoneauth1.session.Session
    """
    # FIXME(jamielennox): Add a deprecation warning if no session is passed.
    # Leaving it as an option until we can ensure nothing break when we switch.
    if session:
        if endpoint:
            kwargs.setdefault('endpoint_override', endpoint)

            if not version:
                __, version = utils.strip_version(endpoint)

        if not version:
            msg = ("You must provide a client version when using session")
            raise RuntimeError(msg)

    else:
        if version is not None:
            warnings.warn(("`version` keyword is being deprecated. Please pass"
                           " the version as part of the URL. "
                           "http://$HOST:$PORT/v$VERSION_NUMBER"),
                          DeprecationWarning)

        endpoint, url_version = utils.strip_version(endpoint)
        version = version or url_version

        if not version:
            msg = ("Please provide either the version or an url with the form "
                   "http://$HOST:$PORT/v$VERSION_NUMBER")
            raise RuntimeError(msg)

    def import_versioned_module(module, version, submodule=None):
        """Import a versioned module in format {module}.v{version][.{submodule}].

        :param module: the module name.
        :param version: the version number.
        :param submodule: the submodule name.
        :raises ValueError: For any invalid input.

        .. versionadded:: 0.3

        .. versionchanged:: 3.17
           Added *module* parameter.
        """

        # NOTE(gcb) Disallow parameter version include character '.'
        if '.' in '%s' % version:
            raise ValueError("Parameter version shouldn't include character '.'.")
        module_str = '%s.v%s' % (module, version)
        if submodule:
            module_str = '.'.join((module_str, submodule))

        __import__(module_str)
        return sys.modules[module_str]
        #return import_module(module_str) 


    #module = importutils.import_versioned_module('glanceclient', int(version),
    #                                             'client')
    module = import_versioned_module('glanceclient', int("2"),
                                                 'client')

    client_class = getattr(module, 'Client')
    return client_class(endpoint, *args, session=session, **kwargs)
