# ecurvecp - Secure Transport Protocol

(__WARNING:__ This project is untested in a production environment. Do not use in production.)

`ecurvecp` is based on CurveCP but has more in common with CurveZMQ.

### Protocol

Rather than poorly describing the protocols in my own words, I recommend reading:

[CurveCP](https://curvecp.org/packets.html)
[CurveZMQ](http://curvezmq.org/page:read-the-docs)
[Codes In Choas](https://codesinchaos.wordpress.com/2012/09/09/curvecp-1/)

### Differences from CurveCP

* TCP instead of UDP
* Atomic messages instead of streams
* No additional availability guarantees
* Not NAT compatible
* No IP roaming.

### Build

`ecurvecp` depends on `enacl` which depends on `libsodium`. Make sure to install `libsodium` before continuing.

```
$ brew install libsodium
```

With `libsodium` installed we can build:

```
$ ./rebar3 compile
```
