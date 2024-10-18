# Mastic reference implementation

This directory contains a Python implementation of Mastic. It requires Python
3.12 or later to run, as well as some packages installed through `pip`:

```shell
python -m pip install -r requirements.txt
```

The last line installs a package called `vdaf_poc` containing the reference
code for
[draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/).

To run unit tests:

```shell
git clone https://github.com/jimouris/draft-mouris-cfrg-mastic
cd draft-mouris-cfrg-mastic/poc
python -m unittest
```
