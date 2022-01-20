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

import testtools

from positional import positional


class TestPositional(testtools.TestCase):

    @positional(1)
    def no_vars(self):
        # positional doesn't enforce anything here
        return True

    @positional(3, positional.EXCEPT)
    def mixed_except(self, arg, kwarg1=None, kwarg2=None):
        # self, arg, and kwarg1 may be passed positionally
        return (arg, kwarg1, kwarg2)

    @positional(3, positional.WARN)
    def mixed_warn(self, arg, kwarg1=None, kwarg2=None):
        # self, arg, and kwarg1 may be passed positionally, only a warning
        # is emitted
        return (arg, kwarg1, kwarg2)

    def test_nothing(self):
        self.assertTrue(self.no_vars())

    def test_mixed_except(self):
        self.assertEqual((1, 2, 3), self.mixed_except(1, 2, kwarg2=3))
        self.assertEqual((1, 2, 3), self.mixed_except(1, kwarg1=2, kwarg2=3))
        self.assertEqual((1, None, None), self.mixed_except(1))
        self.assertRaises(TypeError, self.mixed_except, 1, 2, 3)

    def test_mixed_warn(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")

            self.mixed_warn(1, 2, 3)

        self.assertEqual(1, len(w))

        self.assertTrue(issubclass(w[0].category, DeprecationWarning))
        self.assertIn('takes at most 3 positional', str(w[0].message))

    @positional(enforcement=positional.EXCEPT)
    def inspect_func(self, arg, kwarg=None):
        return (arg, kwarg)

    def test_inspect_positions(self):
        self.assertEqual((1, None), self.inspect_func(1))
        self.assertEqual((1, 2), self.inspect_func(1, kwarg=2))
        self.assertRaises(TypeError, self.inspect_func)
        self.assertRaises(TypeError, self.inspect_func, 1, 2)

    @positional.classmethod(1)
    def class_method(cls, a, b):
        return (cls, a, b)

    @positional.method(1)
    def normal_method(self, a, b):
        self.assertIsInstance(self, TestPositional)
        return (self, a, b)

    def test_class_method(self):
        self.assertEqual((TestPositional, 1, 2), self.class_method(1, b=2))
        self.assertRaises(TypeError, self.class_method, 1, 2)

    def test_normal_method(self):
        self.assertEqual((self, 1, 2), self.normal_method(1, b=2))
        self.assertRaises(TypeError, self.normal_method, 1, 2)

    def test_argspec_preserved(self):

        @positional()
        def f_wrapped(my_arg=False):
            return my_arg

        def f_not_wrapped(my_arg=False):
            return my_arg

        self.assertEqual(inspect.getargspec(f_not_wrapped),
                         inspect.getargspec(f_wrapped))
