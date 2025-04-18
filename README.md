mstpd: Multiple Spanning Tree Protocol Daemon
=============================================

MSTPD is an open source user-space daemon licensed under GPLv2.

MSTPD is reported to be compliant with IXIA ANVL RSTP test suite, with
the notable exception of looped-back BPDUs (see discussion on the matter
on the Implementation Features wiki page:
https://github.com/dtitech/mstpd/wiki/ImplementationFeatures).

**Important note!** MSTP part of the code is currently in experimental phase,
so it should be mostly stable, but it can behave unexpectedly in corner cases.
Be warry if using.

Official repository: https://github.com/dtitech/mstpd

Implementation Features
-----------------------

See the wiki page: https://github.com/dtitech/mstpd/wiki/ImplementationFeatures

Also MSTPD includes a number of useful features which are not defined in
802.1Q-2005 standard, but are found on many commercial switches. Namely:

  - BPDU Guard. Added by Satish Ashok.

  - Bridge Assurance. Added by Satish Ashok.
  (WARNING: it might be dropped in the future and replaced by the
  AutoIsolate feature of 802.1Q-2011)

  - Enhanced statistics: TX/RX BPDU/TCN counters, Forwarding/Blocking
  transitions counters, last 2 ports which caused topology change. Added
  by Satish Ashok.

Goals of the project
--------------------

 - Create reliable and well-tested MSTP code.

 - Get some user base - the more users of this code, the more test
 coverage is.

 - Replace rstpd.

Current state
-------------

The daemon depends on the bridge Linux kernel code to gather basic info
about bridge, such as bridge state (up/down, STP on/off), slave
interfaces for the bridge and their state (up/down). Also daemon
translates CIST states to the kernel bridge slaves, so mstpd in (r)stp
mode can be used as replacement for the current rstpd (and even for the
in-kernel stp!).

MSTP standard (802.1Q-2005) requires from the bridge to be heavily
interconnected with the VLANs infrastructure, namely:

  - Support several (2 .. 65) independent FIDs (Forwarding Information
  Databases). Each VLAN belongs to the one of FIDs, and learning of the
  MAC addresses is done independently in the each FID (independent
  learning as opposed to shared learning in the current Linux bridges);

  - Support several (2 .. 65) Multiple Spanning Tree Instances. Each FID
  belongs to the one of MSTIs;

  - Support per-MSTI port states (Discarding / Learning / Forwarding) so
  that each bridge port can have different states for different MSTIs.

Daemon is currently using Linux bridge per VLAN stp states, so MSTP is
usable on software bridge and on Mellanox Spectrum based platforms with
included kernel patches.

ACKNOWLEDGEMENTS
----------------

Initial code was written by looking at (and shamelessly stealing some
parts from):

  - rstpd by Srinivas Aji `<Aji_Srinivas ? emc DOT com>`

  - rstplib by Alex Rozin `<alexr ? nbase DOT co DOT il>` and Michael
  Rozhavsky `<mike ? nbase DOT co DOT il>`
