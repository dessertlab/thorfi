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

import inspect
import warnings

#import pbr.version
import wrapt

#__version__ = pbr.version.VersionInfo('positional').version_string()
__version__ = "1.1.1"

class positional(object):
    """A decorator to enforce passing arguments as keywords.

    When you have a function that takes a lot of arguments you expect people to
    pass those arguments as keyword arguments. Python however does not enforce
    this. In future then if you decide that you want to insert a new argument
    or rearrange the arguments or transition to using **kwargs you break
    compatibility with users of your code who (wrongly) gave you 20 positional
    arguments.

    In python 3 there is syntax to prevent this however we are not all in the
    position where we can write python 3 exclusive code. Positional solves the
    problem in the mean time across both pythons by enforcing that certain
    arguments must be past as keyword arguments.

    :param max_positional_args: the maixmum number of arguments that can be
        passed to this function without keyword parameters. Defaults to
        enforcing that every parameter with a default value must be passed as a
        keyword argument.
    :type max_positional_args int

    :param enforcement: defines the way incorrect usage is reported. Currenlty
        accepts :py:attr:`positional.EXCEPT` to raise a TypeError or
        :py:attr:`positional.WARN` to show a warning. A warning can be useful
        for applying to functions that are already public as a deprecation
        notice. Defaults to :py:attr:`positional.EXCEPT`.
    """

    EXCEPT = 'except'
    WARN = 'warn'

    def __init__(self, max_positional_args=None, enforcement=EXCEPT):
        self._max_positional_args = max_positional_args
        self._enforcement = enforcement

    @classmethod
    def method(cls, max_positional_args=None, enforcement=EXCEPT):
        if max_positional_args is not None:
            max_positional_args += 1

        def f(func):
            return cls(max_positional_args, enforcement)(func)
        return f

    @classmethod
    def classmethod(cls, *args, **kwargs):
        def f(func):
            return classmethod(cls.method(*args, **kwargs)(func))
        return f

    def __call__(self, func):
        if self._max_positional_args is None:
            spec = inspect.getargspec(func)
            self._max_positional_args = len(spec.args) - len(spec.defaults)

        plural = '' if self._max_positional_args == 1 else 's'

        @wrapt.decorator
        def inner(wrapped, instance, args, kwargs):

            # If called on an instance, adjust args len for the 'self'
            # parameter.
            args_len = len(args)
            if instance:
                args_len += 1

            if args_len > self._max_positional_args:
                message = ('%(name)s takes at most %(max)d positional '
                           'argument%(plural)s (%(given)d given)' %
                           {'name': wrapped.__name__,
                            'max': self._max_positional_args,
                            'given': args_len,
                            'plural': plural})

                if self._enforcement == self.EXCEPT:
                    raise TypeError(message)
                elif self._enforcement == self.WARN:
                    warnings.warn(message, DeprecationWarning, stacklevel=2)

            return wrapped(*args, **kwargs)

        return inner(func)
