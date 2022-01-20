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

#from oslo_utils import importutils
import sys

def Client(version, *args, **kwargs):


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


    #module = importutils.import_versioned_module('heatclient',
    #                                             version, 'client')
    #client_class = getattr(module, 'Client')


    module = import_versioned_module('heatclient', '1', 'client')
    client_class = getattr(module, 'Client')

    return client_class(*args, **kwargs)
