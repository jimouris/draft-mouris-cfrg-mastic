# Mastic reference implementation

This directory contains a Python implementation of Mastic. It requires
`sagemath` to run, as well as some packages installed through `pip`:

```shell
apt install sagemath
sage -pip install git+https://github.com/cfrg/draft-irtf-cfrg-vdaf@ea39dccccc83988029fd667555aa45f6589195b2#subdirectory=poc
```

The last line installs a package called `vdaf_poc` containing the reference
code for
[draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/).

To run unit tests:

```shell
git clone https://github.com/jimouris/draft-mouris-cfrg-mastic
cd draft-mouris-cfrg-mastic/poc
sage -python -m unittest
```
