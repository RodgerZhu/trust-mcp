# Copyright (c) 2025 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup, Extension
from Cython.Build import cythonize

extensions = [
    Extension(
        name="quote_generator",
        sources=["quote_generator.pyx"],
        libraries=["tdx_attest"],
        library_dirs=["/usr/lib64"],
    )
]

setup(
    name='quote_generator',
    version='0.1.0',
    ext_modules=cythonize(extensions),
)

setup(
    name='cc-measure',
    version='0.5.0',
    packages=['tdxmeasure'],
    package_data={
        '': ['tdx_eventlogs', 'tdx_tdquote', 'tdx_rtmr', 'tdx_verify_rtmr']
    },
    include_package_data=True,
    python_requires='>=3.6.8',
    license='Apache License 2.0',
    scripts=['tdx_eventlogs', 'tdx_tdquote', 'tdx_rtmr', 'tdx_verify_rtmr'],
    long_description=load_readme(),
    long_description_content_type='text/markdown',
    install_requires=load_requirements()
)
