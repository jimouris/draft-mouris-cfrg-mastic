# The Mastic VDAF
## The Mastic Verifiable Distributed Aggregation Function (VDAF)


[Verifiable Distributed Aggregation Functions (VDAFs)](https://github.com/cfrg/draft-irtf-cfrg-vdaf) is a family of multi-party protocols for computing aggregate statistics over user measurements.
These protocols are designed to ensure that, as long as at least one aggregation server executes the protocol honestly, individual measurements are never seen by any server in the clear.
At the same time, VDAFs allow the servers to detect if a malicious or misconfigured client submitted an invalid measurement.

Mastic is a new two-party VDAF for the following secure aggregation task each client holds an *input* and an *associated weight*, and the data collector wants to aggregate the weights of all clients whose inputs begin with a prefix chosen by the data collector.
This functionality enables two classes of applications:
1. First, it allows grouping metrics by client attributes without revealing
   which clients have which attributes. We call this **attribute-based
   metrics** and is a generalization over [Prio3](https://cfrg.github.io/draft-irtf-cfrg-vdaf/draft-irtf-cfrg-vdaf.html#name-prio3).
2. Second, it solves the **weighted heavy hitters** problem, where the goal is
   to compute the subset of inputs that have the highest total weight. This is a
   generalization of the (plain) heavy-hitters problem solved by works like
   [Poplar1](https://cfrg.github.io/draft-irtf-cfrg-vdaf/draft-irtf-cfrg-vdaf.html#name-poplar1).

This repository is the working area for the individual Internet-Draft, "The Mastic VDAF".

* [Editor's Copy](https://jimouris.github.io/draft-mouris-cfrg-mastic/#go.draft-mouris-cfrg-mastic.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-mouris-cfrg-mastic)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-mouris-cfrg-mastic)
* [Compare Editor's Copy to Individual Draft](https://jimouris.github.io/draft-mouris-cfrg-mastic/#go.draft-mouris-cfrg-mastic.diff)


## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```shell
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).

## Implementations

| Implementation                                                                      | Language | Version | Dependencies | Description |
|:------------------------------------------------------------------------------------|:---------|:--------|:-------------|:----|
| [**Reference**](https://github.com/jimouris/draft-mouris-cfrg-mastic/tree/main/poc) | Python   | main    | [draft-irtf-cfrg-vdaf](https://github.com/cfrg/draft-irtf-cfrg-vdaf)         | Reference Implementation |
| [mastic](https://github.com/TrustworthyComputing/mastic)                           | Rust     | main    | N/A          | Research Prototype (PoPETS’25) |
| [libprio-rs](https://github.com/divviup/libprio-rs)                                 | Rust     | [v0.16.7+](https://docs.rs/prio/0.16.7/prio/vdaf/mastic/index.html)    | N/A          | Implementation of [draft-mouris-cfrg-mastic-01](https://www.ietf.org/archive/id/draft-mouris-cfrg-mastic-01.html) |

## Contributing

See the
[guidelines for contributions](https://github.com/jimouris/draft-mouris-cfrg-mastic/blob/main/CONTRIBUTING.md).
