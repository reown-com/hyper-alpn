# hyper-alpn

[![Travis Build Status](https://travis-ci.org/pimeys/hyper-alpn.svg?branch=master)](https://travis-ci.org/pimeys/hyper-alpn)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![crates.io](https://meritbadge.herokuapp.com/hyper-alpn)](https://crates.io/crates/hyper-alpn)

Provides an ALPN connector to be used together with
[hyper](https://github.com/hyperium/hyper).

[Documentation](https://docs.rs/hyper-alpn)

## Alpha status

The current master and alpha versions use `std::future` with async/await syntax,
and requires a beta compiler of version 1.39.0. 0.1 works with stable, hyper 0.12 and futures 0.1.

Bugfixes for the stable release should go against the `v0.1` branch.
