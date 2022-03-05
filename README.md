# C port of the BLAKE3 Rust reference implementation

Run [`test.py`](test.py) to build and test the `blake3` binary. The binary
hashes stdin and prints the result to stdout. You can run it like this:

```
$ ./test.py
[build and test output...]
$ echo hello world | ./blake3
dc5a4edb8240b018124052c330270696f96771a63b45250a5c17d3000e823355
$ echo hello world | ./blake3 --key 0000000000000000000000000000000000000000000000000000000000000000
30f932e14e8cef63f94e658994059fba1a0cf548b01813714c2ce32e2e1c5d3d
$ echo hello world | ./blake3 --len 100
dc5a4edb8240b018124052c330270696f96771a63b45250a5c17d3000e823355675dacfc3ed1a06936ecae2697d6baeaa5e423c0efa51d45b322f3f2ca2ec03d1c5a692d6254d121c20dadf19e0d00e389deb89f2419da878379750df148e9883f482b56
```

This implementation tries to be as simple as possible, and the only performance
optimization here is liberal use of the `inline` keyword. Performance isn't
terrible though, and under `clang -O3` this is a hair faster than Coreutils
`sha512sum` on my laptop.
