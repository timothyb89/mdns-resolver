# mdns-resolver

A simple mDNS resolver derived from [`simple-mdns`], in async Rust with no
native dependencies.

[`simple-mdns`]: https://github.com/balliegojr/simple-dns

## What is this?

This crate performs local DNS lookups in a similar fashion as
`avahi-resolve -n`; in other words, it translates Bonjour-style hostnames (e.g.
`foo.local`) to an IP address.

Most resolvers (including [`simple-mdns`]) are intended to browse or query
services by type rather than name. This crate is intended to reliably discover
the IP for a given hostname in the same fashion that a desktop device with Avahi
or another similar local resolver would resolve hosts under the virtual `.local`
domain.

It's derived from [`simple_mdns::OneShotMdnsResolver`][oneshot] with a few key
differences:
 * Uses async rather than blocking Rust
 * Rewritten packet processing handles an arbitrary number of concurrent queries
 * Listens on the correct interface for query replies

This library was developed for use in the [`homedns`] DNS server, which
translates regular DNS queries into mDNS for clients that don't (or can't)
support mDNS lookups on their own (such as Docker containers, pre-baked IoT
appliances, etc).

[oneshot]: https://docs.rs/simple-mdns/0.2.2/simple_mdns/struct.OneShotMdnsResolver.html
[`homedns`]: https://github.com/timothyb89/homedns

## Usage

The included example utility `mdns-query` can be used to lookup a single
hostname:

```bash
$ cargo run -q --features=bins --bin mdns-query linux.local
linux.local = 192.168.10.104
```

Take a look at [`mdns-query.rs`] for a simple library usage example. It should
handle concurrent requests just fine, and `MdnsQuery` is `Clone` for
multithreaded use.

[`mdns-query.rs`]: ./src/bin/mdns-query.rs
