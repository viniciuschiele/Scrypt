# Scrypt.NET

[![Build Status](https://travis-ci.org/viniciuschiele/Scrypt.svg)](https://travis-ci.org/viniciuschiele/Scrypt)

scrypt is a password hash algorithm created by [Tarsnap](http://www.tarsnap.com/scrypt.html) in 2012 that allow us to protect passwords stored on databases against brute force attacks.

This .NET implementation of scrypt is a port of [original implementation in C](http://www.tarsnap.com/scrypt.html), which generates the same hash as the original implementation does. This implementation is fast but not as fast as original one because the original one is written in C and it uses SIMD instructions.

If you would like to know further about hashing algorithms and how to protect passwords I really recommend you to read that article [Password Hashing](https://crackstation.net/hashing-security.htm).

## Requirements

.NET 2.0 or .NET Core


## Examples

Generating a new hash for a password:

```csharp

ScryptEncoder encoder = new ScryptEncoder();

string hashsedPassword = encoder.Encode("mypassword");
```

Comparing a password against a hashed password:

```csharp
ScryptEncoder encoder = new ScryptEncoder();

bool areEquals = encoder.Compare("mypassword", hashedPassword);
```

The recommended parameters for interactive logins as of 2009 are iterationCount=16384, blockSize=8, threadCount=1, those are the default values.
They should be increased as memory latency and CPU parallelism increases.

It is compatible with .NET Core and it works perfectly in Linux and OSX using [mono](http://www.mono-project.com) or the .NET Core, I'm not sure about mobile phones but I believe that it should work as well. 

## Install

Install via NuGet: `Install-Package Scrypt.NET`


## Feedback

Please use the [Issues](https://github.com/viniciuschiele/scrypt/issues) for feature requests and troubleshooting usage.
