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
measurement.

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
type to be generalized to support a wide variety of secure aggregation tasks.
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
presence of a malicious server. Rather than two aggregation servers as in the
previous modes, this mode of operation involves three aggregation servers,
where every pair of servers communicate over a different channel. [CP: Anything
else to mention here? Is the transform generic, i.e., apply to any 2-party
VDAF, or are there tricks in {{MST23}} that we want to take advantage of for
efficiency] While more complex to implement, this mode allows Mastic to
achieve "full security", where both privacy and robustness hold in the
honest majority setting.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Preliminaries

Mastic makes use of three primitives described in the base VDAF specification
{{!VDAF}}: finie fields, eXtendable Output Functions (XOFs) and Fully Linear
Proofs (FLPs). It also makes use of a fourth primitive, which extends the
security properties of Incremental Distributed Point Functions (IDPFs), also
described in the base specification. All three primitives are described below.

## Finite fields {#field}

An implementation of the `Field` interface in {{Section 6.1 of !VDAF}} is
required. This object implements arithmetic in a prime field with a suitable
modulus.

> TODO: Describe the features of `Field` we need for Mastic.

## XOF {#xof}

An implementation of the `Xof` interface in {{Section 6.2 of !VDAF}} is
required. This object implements an XOF that takes a short seed and some
auxiliary data as input and outputs a string of any length required for the
application.

> TODO: Describe the features of `Xof` we need for Mastic.

## FLP {#flp}

An implementation of the `Flp` interface in {{Section 7.1 of !VDAF}} is
required. This object implements a zero-knowledge proof system used to verify
that the mesaurement encoded by the client's report conforms to the data type
required by the application. The Client generates a proof that its measurement
is valid and sends secret shares of this proof to each Aggregator. Verification
is split into two phases. In the first phase, each Aggregator "queries" its
share of the measurement and proof to obtain its "verifier share". In the
second phase, the Aggregators sum of the verifier shares and use the sum to
decide if the input is valid.

> TODO: Describe in more detail the features of `Flp` we require for Mastic.

## Distributed Point Functions (DPF) {#dpf}

Function secret sharing (FSS) allows secret sharing of the output of a function
`f()` into additive shares, where each function share is represented by a
separate key {{GI14}}. These keys enable their respective owners to efficiently
generate an additive share of the function’s output `f(x)` for a given input
`x`. Distributed Point Functions (DPF) are a particular case of FSS where `f()`
is a point function `f_{alpha, beta}(x) = beta if x = a, or 0 otherwise`.


### Incremental DPF (IDPF) {#idpf}

An Incremental Distribute Point Function (IDPF, {{Section 8.1 of !VDAF}}) is a
secret sharing scheme for a special type of function known as an "incremental
point function". Such a function involves two parameters: `alpha`, a bit-string
of some fixed size, which we denote by `BITS`; and `beta`, which in this
document shall be represented by a fixed-length vector over a finite field
`Field`. The function is well-defined for any non-empty string of length less
than or equal to `BITS`: on input of any prefix of `alpha`, the point function
returns `beta`; otherwise, if the input is not a prefix of `alpha`, the output
is `Field.zeros(OUTPUT_LEN)` (i.e., a length-`OUTPUT_LEN` vector of zeros).

An IDPF has two main operations. The first is the key-generation algorithm,
which is run by the Client. It takes as input `alpha` and `beta` and returns
three values: two "key shares", one for each of two Aggregators; and the
"public share", to be distributed to both Aggregators. The second is the
key-evaluation algorithm, run by each Aggregator. It takes as input a candidate
prefix string `prefix`, the public share, and the Aggregator's key share and
returns the Aggregator's share of the point function parameterized by `alpha`
and `beta` and evaluated at `prefix`.

Shares of the IDPF outputs can be aggregated together across multiple reports.
This is used in Poplar1 ({{Section 8 of !VDAF}}) to count how many input
strings begin with a candidate prefix. IDPFs are private in the sense that each
Aggregators learning nothing about the underlying inputs beyond the value of
this sum. However, IDPFs on their own do not provide robustness: it is possible
for a malicious to Client to fool the Aggregators into accepting malformed
counter (i.e., a value other than `0` or `1`).

### Verifiable DPF (VDPF) {#vdpf}

In the presence of a malicious client, standard DPFs and IDPFs suffer from
malicious clients, who can completely corrupt the result by sending corrupt DPF
keys. Even worse, malicious clients can craft the keys and manipulate the
statistics without the servers’ knowledge. Verifiable DPF (VDPF) {{CP22}} build
on standard DPFs and ensure that a DPF key is well-formed using hashing-based
techniques.

### Verifiable Incremental DPF (VIDPF) {#vidpf}

Mouris et al. {{MST23}} describe an extension of IDPF and VDPF called Verifiable
IDPF (VIDPF) that allows verifying that clients’ inputs are valid by relying on
hashing while preserving the client’s input privacy. VIDPF endows this basic
scheme with two properties, both of are used in Mastic to achieve robustness:

1. **One-hot Verifiability:** The verifiability property of VIDPF ensures that if
    two proofs (`proof_0` and `proof_1`) for a given level `k` are the same,
    then there is at most one value at that level (i.e., of length `k`) in the
    VIDPF tree whose evaluation outputs `beta`.

1. **Path Verifiability:** The One-hot Verifiability property alone is not
    sufficient to guarantee that the keys are well formed. The Aggregators still
    need to verify that: a) the non-zero values `beta` of the Client are across
    a single path in the tree, and b) the value of the root node is correctly
    propagated down the VIDPF tree. For example, if the root value is `beta`,
    then there is only a single path from root to the leaves with `beta` values.


> TODO(cjpatton) Define syntax and give overview of design. Point to reference
> implementation for details.

# Definition

TODO(cjpatton) overview

## Sharding

TODO(cjpatton) high-level, point to reference implementation

## Preparation

TODO(cjpatton) high-level, point to reference implementation

## Validity of Aggregation Parameters

TODO(cjpatton) high-level, point to reference implementation

## Aggregation

TODO(cjpatton) high-level, point to reference implementation

## Unsharding

TODO(cjpatton) high-level, point to reference implementation

# Modes of Operation

## Weighted Heavy-Hitters {#weighted-heavy-hitters}

TODO(cjpatton) high-level, point to example

## Aggregation by Labels {#aggregation-by-labels}

TODO(cjpatton) high-level, point to example

## Plain Heavy-Hitters with Proof Aggregation {#plain-heavy-hitters-with-proof-aggregation}

TODO(jimouris)

## Malicious Robustness for Plain Heavy-Hitters {#plain-heavy-hitters-with-three-aggregators}

TODO(jimouris)

# Security Considerations

TODO

# IANA Considerations

TODO

--- back

# Acknowledgments
{:numbered="false"}

TODO
