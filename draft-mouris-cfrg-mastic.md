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
 -
    fullname: Hannah Davis
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
    organization: Supra Research
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
    date : 2022
    seriesinfo: EUROCRYPT 2022
    target: https://iacr.org/cryptodb/data/paper.php?pubkey=31935

  DPRS23:
    title: "Verifiable Distributed Aggregation Functions"
    author:
      - ins: H. Davis
      - ins: C. Patton
      - ins: M. Rosulek
      - ins: P. Schoppmann
    date: 2023
    seriesinfo: Proceedings on Privacy Enhancing Technologies (PoPETs)
    target: https://doi.org/10.56553/popets-2023-0126

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
    date : 2023
    target: https://ia.cr/2023/080

--- abstract

This document describes Mastic, a two-party VDAF for the following aggregation
task: each client holds a bit string, and the collector wishes to count how
many of these strings begin with a given prefix. Such a VDAF can be used to
solve the private heavy hitters problem, where the goal is compute the subset
of the strings that occur most frequently without learning which client
uploaded which string. This document describes different modes of operation for
Mastic that support a variety of use cases and admit various performance and
security trade-offs.

--- middle

# Introduction

[TO BE REMOVED BY RFC EDITOR: The source for this draft and the reference code
can be found at https://github.com/jimouris/draft-mouris-cfrg-mastic.]

The "private heavy hitters" problem is to recover the most popular measurements
uploaded by clients with out learning the measurements themselves. For example,
a browser vendor might want to know which websites are most popular without
learning which clients visited which websites. This problem can be solved using
a Verifiabile Distributed Aggregation Function, or VDAF
{{!VDAF=I-D.draft-irtf-cfrg-vdaf-07}}. In particular, the Poplar1 VDAF
described in {{Section 9 of !VDAF}} describes how to distribute this
computation amongst a small set of servers such that, as long as one server is
honest, no individual measurement is observed in the clear. At the same time,
Poplar1 allows the servers to detect if a client has submitted an invalid
measurment.

This document describes the Mastic VDAF that can be used as a drop-in
replacement for Poplar1, while offering improved performance and communication
cost. [CP: We'll need numbers to back this up.] Based on the PLASMA protocol
{{MST23}}, the scheme's design is also somewhat simpler, requiring just one
round for report preparation compared to Poplar1's two rounds.

Mastic is also highly extensible. Like Poplar1, Mastic's core functionality is
to compute how many of the measurements -- here viewed as bit strings of some
fixed length -- begin with a given prefix string. (Over several rounds of
aggregation, the prefix counting can be used to compute the heavy hitters as
described in {{Section 8 of !VDAF}}.) Mastic allows this basic counter data
type to be generalized to support a wide variety of secure aggreagtion tasks.
In particular, Mastic supports any data type for the output that can be
expressed as a type for the Prio3 VDAF {{Section 7 of !VDAF}}. For example, the
counter could be replaced with a bounded weight (say, representing a dollar
amount) such that the "heaviest weight" measurements are recovered. We describe
this mode of operation in {{weighted-heavy-hitters}}.

This generalization also allows Mastic to support another important use case. A
desirable feature for a secure aggregation systems is the ability to "drill
down" on the data by splitting up the aggregate based on specific properties of
the clients. For example, a browser vendor may wish to partition aggregates by
version (different versions of the browser may have different performance
profiles) or geographic location. We will call these properties "labels".

Aggregating by labels requires representing the information in such a way that
that the measurements submitted by clients with the same label are aggregated
together. Prio3 can be adapted for this purpose, but the communication cost
would be linear in the number of possible distinct label, which becomes
prohibitive if the label space is large. Mastic encodes the label and
measurement with constant communication overhead such that, for an arbitrary
sequence of labels, the reports can be "queried" to reveal the aggregate for
each label without learning the label or measurement of any client. We describe
this mode of operation in {{aggregation-by-labels}}.

Finally, two modes of operation for Mastic are described that admit useful
performance and security trade-offs.

First, we describe an optimization for plain heavy hitters that, in the best
case, reduces the communication cost of preparation from linear in the number
of reports to constant, leading to a dramatic improvement in performance
compared to Poplar1. This best-case behavior is observed when all clients
behave honestly: if a fraction of the clients submit invalid reports, then
additional rounds of communication are required in order isolate the invalid
reports and remove them. We describe this idea in detail in
{{plain-heavy-hitters-with-proof-aggregation}}.

Second, {{plain-heavy-hitters-with-three-aggregators}} describes an enhancement
for plain heavy hitters that allows Mastic to achieve robustness in the
presence of a malcioius server. Rather than two aggregation servers as in the
previous modes, this mode of operation involves three aggregation servers,
where every pair of servers communicate over a different channel. [CP: Anything
else to mention here? Is the transform generic, i.e., apply to any 2-party
VDAF, or are there tricks in {{MST23}} that we want to take advanatage of
for efficiency] While more complex to implement, this mode allows Mastic to
achieve "full security", where both privacy and robustness hold in the
honst majority setting.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Preliminaries

This document makes use of Fully Linear Proofs (FLPs) and eXtendable Output
Functions (XOFs) as described in {{!VDAF}}. It also makes use of an extension
of Incremental Distributed Point Functions (IDPFs), known as "Verifiable IDPFs
(VIDFS)" first described by {{MST23}}. VIDPFs are specified below.

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

# Definition

## Sharding

## Preparation

## Validity of Aggregation Parameters

## Aggregation

## Unsharding

# Modes of Operation

## Weighted Heavy-Hitters {#weighted-heavy-hitters}

## Aggregation by Labels {#aggregation-by-labels}

## Plain Heavy-Hitters with Proof Aggregation {#plain-heavy-hitters-with-proof-aggregation}

## Malicious Robustness for Plain Heavy-Hitters {#plain-heavy-hitters-with-three-aggregators}

# Security Considerations

TODO

# IANA Considerations

TODO

--- back

# Acknowledgments
{:numbered="false"}

TODO
