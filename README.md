☠️ There is a [better version][0] of this module ready to be merged in
the kernel (to appear in 4.18). A [backport][2] is available.

# Consistent source hashing scheduler for Linux IPVS

Based on [Google's Maglev algorithm][1], this scheduler builds a
lookup table in a way disruption is minimized when a change
occurs. This helps in case of active/active setup without
synchronization. Like for classic source hashing, this lookup table is
used to assign connections to a real server.

Both source address and port are used to compute the hash (unlike sh
where this is optional).

Weights are correctly handled. Unlike sh, servers with a weight of 0
are considered as absent. Also, unlike sh, when a server becomes
unavailable due to a threshold, no fallback is possible: doing so
would seriously impair the the usefulness of using a consistent hash.

The value of 65537 for the hash table size is currently not modifiable
at compile-time. This is the value suggested in the Maglev
paper. Another possible value is 257 (for small tests) and 655373 (for
very large setups).

[0]: http://archive.linuxvirtualserver.org/html/lvs-devel/2018-03/msg00023.html
[1]: https://research.google.com/pubs/pub44824.html
[2]: https://github.com/vincentbernat/ip_vs_mh

## Compilation

This is an out-of-tree module. Just type `make` and you should get an
`ip_vs_csh.ko` file. You can use `insmod` to load it. If your kernel
source are in a non-standard place, use `make KDIR=...`.

There is no option for this scheduler. You can use it by its name:

    ipvsadm -A -t 203.0.113.15:80 -s csh
    ipvsadm -a -t 203.0.113.15:80 -r 10.234.79.11:80 -m
    ipvsadm -a -t 203.0.113.15:80 -r 10.234.79.12:80 -m
    ipvsadm -a -t 203.0.113.15:80 -r 10.234.79.13:80 -m -w 2
