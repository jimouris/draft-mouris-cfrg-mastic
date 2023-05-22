---
title: "Private, Lightweight Aggregated Statistics against Malicious Adversaries"
abbrev: "PLASMA"
category: info

docname: draft-irtf-cfrg-plasma-latest
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
  github: "jimouris/draft-irtf-cfrg-plasma"
<!--   latest: https://example.com/LATEST -->

author:
 -
    fullname: Dimitris Mouris
    organization: University of Delaware
    email: jimouris@udel.edu
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


--- abstract

This document describes PLASMA: a framework for Private, Lightweight Aggregated Statistics against Malicious Adversaries. PLASMA is a multi-party protocol for computing aggregate statistics over user measurements in the three-server setting while protecting the privacy of honest clients and the correctness of the protocol against a coalition of malicious clients and a malicious server. PLASMA ensures that as long as at least one aggregation server executes the protocol honestly, individual measurements are never seen by any server in the clear. At the same time, PLASMA allow the servers to detect if a malicious client submitted an input that would result in an incorrect aggregate result. The core primitives in PLASMA are a verifiable incremental distributed point function (VIDPF) and a batched consistency check, which are of independent interest. The VIDPF reduces the server runtime by introducing new methods to validate client inputs based on hashing and preemptively reject malformed ones. The batched consistency check uses Merkle trees to validate multiple client sessions together in a batch and reduce the server communication across multiple client sessions.

--- middle

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
