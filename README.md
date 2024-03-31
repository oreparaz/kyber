# kyber.c - single-file Kyber KEM

This is a single-file minimization of the CRYSTALS-Kyber CCA2 KEM `ref` implementation. This should be portable C.
I wrestled with the build system so that you don't have to.

## Usage

Just include `kyber.h` and link against `kyber.c`. That's it.
See `demo.c` for a full demo.

 * You'll need to pass a call back function to provide randomness. This is different from the "official" API. See `demo.c` for an example.
 * You'll need to define `-DKYBER_K=3` (or another value) at compile time. This picks the parameter suite.

## TODO

* [ ] measure stack usage
* [ ] reduce memory usage
* [ ] use nix in CI
* [ ] enable ASAN
