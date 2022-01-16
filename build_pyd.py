from distutils.core import setup
from Cython.Build import cythonize

setup(
    name='words you want',
    ext_modules=cythonize(["main.py"], language_level=3),
)