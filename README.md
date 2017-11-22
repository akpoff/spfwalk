About spfwalk
=============

**spfwalk** recursively looks up *SPF* records for the domains passed in
on the command line or stdin, printing the results to stdout, one line per
record.

The output is a list of IPv4 and IPv6 addresses and blocks.

**spfwalk** imports records from *include* domains, follows *redirect*
directives, resolves *a* names and *mx* directives found in *SPF* records.

### Features

+ Fully-recursive look ups
+ Specify just IPv4 or IPv6 records (defaults to both)

See the man page for further details.

### Example Output

Given a domain like **gmail.com** `spf_fetch` will return:

```
spf_fetch gmail.com

64.18.0.0/20
64.233.160.0/19
66.102.0.0/20
66.249.80.0/20
72.14.192.0/18
74.125.0.0/16
108.177.8.0/21
173.194.0.0/16
207.126.144.0/20
209.85.128.0/17
216.58.192.0/19
216.239.32.0/19
172.217.0.0/19
108.177.96.0/19
2001:4860:4000::/36
2404:6800:4000::/36
2607:f8b0:4000::/36
2800:3f0:4000::/36
2a00:1450:4000::/36
2c0f:fb50:4000::/36
```

Each domain from the list and all domains discovered as `include`,
`redirect`, or `mx` in the SPF records will be recursively looked up to
get their relevant IPs addresses.

Copyright and License
---------------------

Copyright (c) 2008-2017 Gilles Chehade <gilles@poolp.org>
Copyright (c) 2016-2017 Aaron Poffenberger <akp@hypernote.com>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
