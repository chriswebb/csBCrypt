# csBCrypt

## Description 

csBCrypt is an implementation the OpenBSD Blowfish password hashing
algorithm, as described in "A Future-Adaptable Password Scheme" by Niels
Provos and David Mazieres: http://www.openbsd.org/papers/bcrypt-paper.ps

This system hashes passwords using a version of Bruce Schneier's
Blowfish block cipher with modifications designed to raise the cost of
off-line password cracking. The computation cost of the algorithm is
parameterised, so it can be increased as computers get faster.

## Testing

NUnit regression tests are available in TestBCrypt.cs

## References

A simple example that demonstrates most of the features:

```cs
// Hash a password for the first time
string hashed = BCrypt.CreateHash(password, BCrypt.GenerateSalt());

// GenerateSalt's log_rounds parameter determines the complexity
// the work factor is 2**log_rounds, and the default is 10
string hashed = BCrypt.CreateHash(password, BCrypt.GenerateSalt(12));

// Check that an unencrypted password matches one that has
// previously been hashed
if (BCrypt.VerifyPlaintext(candidate, hashed))
	Console.WriteLine("It matches");
else
	Console.WriteLine("It does not match");
```

## Contributing

Please report bugs to this repository as a new issue. 

To add a new feature:

1. Fork this repository.
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

## License

ISC/BSD License. See LICENSE file.

## Contributors

* Chris Webb - Ported jBCrypt to .Net
* Damien Miller <djm@mindrot.org> - Original jBCrypt

## Port Information


This repository is based off of version 0.4 of jBCrypt found here: http://www.mindrot.org/projects/jBCrypt/ 

I have also mirrored all versions of jBCrypt on a personal repository found here: https://github.com/chriswebb/jBCrypt/

BCrypt.Net is based off of the same repository, but was not used in the making of this port. So this is **not** a fork of BCrypt.Net. This is a standalone port of jBCrypt.
