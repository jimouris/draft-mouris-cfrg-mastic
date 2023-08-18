---
title: "Private, Lightweight Aggregated Statistics against Malicious Adversaries"
abbrev: "PLASMA"
category: info

docname: draft-irtf-mouris-plasma-latest
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
  github: "jimouris/draft-irtf-mouris-plasma"
<!--   latest: https://example.com/LATEST -->

author:
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

This document describes PLASMA: a framework for Private, Lightweight Aggregated
Statistics against Malicious Adversaries. PLASMA is a multi-party protocol for
computing aggregate statistics over user measurements in the three-server
setting while protecting the privacy of honest clients and the correctness of
the protocol against a coalition of malicious clients and a malicious server.
PLASMA ensures that as long as at least one aggregation server executes the
protocol honestly, individual measurements are never seen by any server in the
clear. At the same time, PLASMA allow the servers to detect if a malicious
client submitted an input that would result in an incorrect aggregate result.
The core primitives in PLASMA are a verifiable incremental distributed point
function (VIDPF) and a batched consistency check, which are of independent
interest. The VIDPF reduces the server runtime by introducing new methods to
validate client inputs based on hashing and preemptively reject malformed ones.
The batched consistency check uses Merkle trees to validate multiple client
sessions together in a batch and reduce the server communication across
multiple client sessions.

--- middle

# Introduction

TODO Introduction

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


Verifiable Distributed Aggregation Functions (VDAFs) {{DPRS23}} ...


De Castro and Polychroniadou {{CP22}} introduced Verifiable DPF (VDPF), a DPF
scheme that supports a well-formedness check. More specifically, VDPFs allows
verifying that the client’s inputs are well-formed, meaning that the client
will not learn any unauthorized information about the servers' database or
modify the database in an unauthorized way.


PLASMA {{MST23}} introduced the notion of Verifiable Incremental DPF (VIDPF)
that builds upon IDPF {{BBCGGI21}} and VDPF {{CP22}}. VIDPF is an IDPF that
allows verifying that clients’ inputs are valid by relying on hashing while
preserving the client’s input privacy.



# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Definition of Verifiable DPF (VDPF) {#vdpf}

TODO from {{CP22}}

## Key Generation  {#sec-vdpf-key-gen}

TODO

## Evaluation  {#sec-vdpf-eval}

TODO

# Definition of Verifiable Incremental DPF (VIDPF) {#vidpf}

TODO from {{MST23}}

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
