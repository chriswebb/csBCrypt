csBCrypt is an implementation the OpenBSD Blowfish password hashing
algorithm, as described in "A Future-Adaptable Password Scheme" by Niels
Provos and David Mazieres: http://www.openbsd.org/papers/bcrypt-paper.ps

This system hashes passwords using a version of Bruce Schneier's
Blowfish block cipher with modifications designed to raise the cost of
off-line password cracking. The computation cost of the algorithm is
parameterised, so it can be increased as computers get faster.

NUnit regression tests are available in in TestBCrypt.cs

csBCrypt is licensed under a ISC/BSD licence. See the LICENSE file for details.

Please report bugs to Chris Webb. Please check the
TODO file first, in case your problem is something I already know about
(please send patches!)

A simple example that demonstrates most of the features:

	// Hash a password for the first time
	String hashed = BCrypt.CreateHash(password, BCrypt.GenerateSalt());

	// gensalt's log_rounds parameter determines the complexity
	// the work factor is 2**log_rounds, and the default is 10
	String hashed = BCrypt.CreateHash(password, BCrypt.GenerateSalt(12));

	// Check that an unencrypted password matches one that has
	// previously been hashed
	if (BCrypt.VerifyPlaintext(candidate, hashed))
		Console.Out.WriteLine("It matches");
	else
		Console.Out.WriteLine("It does not match");

This repository is based off of jBCrypt found here: http://www.mindrot.org/projects/jBCrypt/
