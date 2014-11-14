#Scrypt
scrypt is a password hash algorithm created by [Tarsnap](http://www.tarsnap.com/scrypt.html) in 2012 that allow us to protect passwords stored on databases against brute force attacks.

This .NET implementation of scrypt is a port of [original implementation in C](http://www.tarsnap.com/scrypt.html), which generates the same hash as the original implementation does. This implementation is fast but not as fast as original one because the original one is written in C and it uses SIMD instructions.

If you would like to know further about hashing algorithms and how to protect passwords I really recommend you to read that article [Password Hashing](https://crackstation.net/hashing-security.htm).

##Examples
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

It works perfectly in Linux and OSX using [mono](http://www.mono-project.com), I'm not sure about mobile phones but I believe that it should work as well. 

##Install
Install via NuGet: Install-Package Aero.Scrypt

##Feedback
Please use the [Issues](https://github.com/aero-project/scrypt/issues) for feature requests and troubleshooting usage.