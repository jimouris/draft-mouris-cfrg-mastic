---
title: "The Mastic VDAF"
abbrev: "Mastic"
category: info

docname: draft-mouris-cfrg-mastic-latest
submissiontype: IRTF
number:
date:
consensus: true
v: 3
area: "IRTF"
workgroup: "Crypto Forum"
keyword:
  - Internet-Draft
venue:
  group: "Crypto Forum"
  type: "Research Group"
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/search/?email_list=cfrg"
  github: "jimouris/draft-mouris-cfrg-mastic"
<!--   latest: https://example.com/LATEST -->

author:
 -  fullname: Hannah Davis
    organization: Seagate
    email: hannahedavis@protonmail.com

 -
    fullname: Dimitris Mouris
    organization: University of Delaware
    email: jimouris@udel.edu
 -
    name: Christopher Patton
    organization: Cloudflare
    email: chrispatton+ietf@gmail.com
 -
    fullname: Pratik Sarkar
    organization: Boston University
    email: pratik93@bu.edu
 -
    fullname: Nektarios G. Tsoutsos
    organization: University of Delaware
    email: tsoutsos@udel.edu

normative:

informative:

  BBCGGI21:
    title: "Lightweight Techniques for Private Heavy Hitters"
    author:
      - ins: D. Boneh
      - ins: E. Boyle
      - ins: H. Corrigan-Gibbs
      - ins: N. Gilboa
      - ins: Y. Ishai
    date: 2021
    seriesinfo: IEEE S&P 2021
    target: https://ia.cr/2021/017

  CP22:
    title: "Lightweight, Maliciously Secure Verifiable Function Secret Sharing"
    author:
      - ins: Leo de Castro
      - ins: Anitgoni Polychroniadou
    date : 2022,
    seriesinfo: EUROCRYPT 2022
    target: https://iacr.org/cryptodb/data/paper.php?pubkey=31935

  DPRS23:
    title: "Verifiable Distributed Aggregation Functions"
    author:
      - ins: H. Davis
      - ins: C. Patton
      - ins: M. Rosulek
      - ins: P. Schoppmann
    target: https://ia.cr/2023/130

  GI14:
    title: "Distributed Point Functions and Their Applications"
    author:
      - ins: N. Gilboa
      - ins: Y. Ishai
    date: 2014
    seriesinfo: EUROCRYPT 2014
    target: https://link.springer.com/chapter/10.1007/978-3-642-55220-5_35

  MST23:
    title: "PLASMA: Private, Lightweight Aggregated Statistics against Malicious Adversaries"
    author:
      - ins: Dimitris Mouris
      - ins: Pratik Sarkar
      - ins: Nektarios Georgios Tsoutsos
    date : 2023,
    target: https://ia.cr/2023/080

--- abstract

This document describes Plabels, a two-party VDAF for the following aggregation
task: each Client holds a bit string, and the Collector wishes to count how
many of these strings begin with a candidate prefix. Such a VDAF can be used to
solve the heavy hitters problem, where the goal is compute the subset of the
measurements that occur most frequently. This document also describes various
modes of operation for Plabels. First, its output type can be enriched to
support aggregation functions beyond prefix counts. Second, an extension to the
aggregation phase is described that significantly reduces communication cost
compared to existing techniques. Third, a three-party variant is described that
is robust in the honest majority setting.

--- middle

# Introduction

> TODO Introduction. Outline:
> - Recall the heavy hitters problem
> - Describe Poplar {{BBCGGI21}}, IDPF, and how the VDAF abstraction relates to IDPF
> - Say that Poplar isn't ideal for solving this problem
> - Introduce {{MST23}}

Poplar {{BBCGGI21}} described a protocol for solving the `t`-heavy-hitters
problem in a privacy-preserving manner. Each client holds a bit-string of
length `n`, and the goal of the aggregation servers is to compute the set of
inputs that occur at least `t` times. The core primitive used in their protocol
is a specialized Distributed Point Function (DPF) {{GI14}}, called Incremental
DPF (IDPF), that allows the servers to "query" their DPF shares on any
bit-string of length shorter than or equal to `n`. As a result of this query,
each of the servers has an additive share of a bit indicating whether the
string is a prefix of the client's input. The protocol also specifies a
multi-party computation for verifying that at most one string among a set of
candidates is a prefix of the client's input.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Preliminaries

This document makes use of Fully Linear Proofs (FLPs) and eXtendable Output
Functions (XOFs) as described in {{?VDAF=I-D.draft-irtf-cfrg-vdaf}}. It also
makes use of an extension of Incremental Distributed Point Functions (IDPFs),
known as "Verifiable IDPFs (VIDFS)" first described by {{MST23}}. VIDPFs are
specified below.

## Verifiable IDPF (VIDPF) {#vidpf}

De Castro and Polychroniadou {{CP22}} introduced Verifiable DPF (VDPF), a DPF
scheme that supports a well-formedness check. More specifically, VDPFs allows
verifying that the client’s inputs are well-formed, meaning that the client
will not learn any unauthorized information about the servers' database or
modify the database in an unauthorized way.

PLASMA {{MST23}} introduced the notion of Verifiable Incremental DPF (VIDPF)
that builds upon IDPF {{BBCGGI21}} and VDPF {{CP22}}. VIDPF is an IDPF that
allows verifying that clients’ inputs are valid by relying on hashing while
preserving the client’s input privacy.

> TODO(Dimitris)

## Interactive Aggregation for VDAFs {#vdaf-interactive-agg-extension}

In order to accommadating Plabel's improvemnt in communication cost require, it
is necessary to replace the non-interactive aggregation algorithm
`Vdaf.aggregate()`  with a 1-round, interactive protocol implemented by the
following methods:

* `Vdaf.aggregate_init(agg_info: AggInfo, out_shares: list[OutShare]) ->
  tuple[AggState, AggMessage]` is the deterministic aggregation initialization
  algorithm called by each Aggregator. It takes as input the set output shares
  to be aggregated and a parameter called the "aggregation information". Its
  outputs are the Aggregator's state and broadcast message.

* `Vdaf.aggregate_finish(agg_state: AggState, agg_msgs: list[AggMessage]) ->
  AggShare`. is the deterministic aggregation finalization aglorithm called by
  each Aggregator on its aggregation state and the sequence of messages
  broadcast by each Aggregator.

> CP: The binary search described in {{MST23}} obviously doesn't fit into a
> 1-round protocol, as the number of rounds required depends on how deep down
> the Merkle we have to before we've identified all bad reports. The idea is
> that aggregation protocol would be invoked multiple times, each time with a
> different `agg_info`.

> CP: Let's try to come up with a better name than `agg_info`.

# The Plabels VDAF {#vdaf}

> TODO(Hannah) Describe the implementation of the base `Vdaf` interface.

# Reducing Communication Cost via Interactive Aggregation

> TODO(Dimitris) Describe the implementation of the interface in
> {{vdaf-interactive-agg-extension}}

# Improved Robustness via

> TODO Describe 3-party PLASMA

# Security Considerations

> TODO Security

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

> TODO(Dimitris)
