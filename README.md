#PasswordHash

Component to hash passwords and verify them again later.
This was hacked together to work in ColdFusion 9 and the basis
for this can be found [here](https://crackstation.net/hashing-security.htm).

The algorithm, iterations, and salt are all stored together with the hash
to make it backwards compatible. The iterations and algorithm can be
changed and will apply to all new passwords but the verify will still work
with previously hashed passwords.

For extra security, the compare of hashes is done with an XOR that
will go through all bytes to ensure that the entire strings are compared and
that the amount of time it takes to compare is consistent.
