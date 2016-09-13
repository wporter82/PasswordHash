component
	{

	/**
	* Initialize the token generator.
	*/
	public any function init() {

		// NOTE: The SHA1PRNG is not the default in all implementations of the JVM. As
		// such, we're defining the algorithm explicitly to keep this code consistent.
		generator = createObject( "java", "java.security.SecureRandom" )
			.getInstance(
				javaCast( "string", "SHA1PRNG" ),
				javaCast( "string", "SUN" )
			);

		// Now that we've initialized the random generator, we have to generate a random
		// byte of data. This will ensure that the random generator is self-seeded using
		// a shared seed generator.
		// --
		// CAUTION: Since the underlying seed generator reads from sources of entropy,
		// this may hang until enough entropy has been collected. This is another good
		// reason to do it during initialization time rather than at first-use time.
		generator.nextBytes( charsetDecode( " ", "utf-8" ) );

		// I hold the future date at which time the generator should be reseeded in order
		// to keep it unpredictable.
		// --
		// NOTE: This doesn't affect the randomness of the values. But, the thinking
		// is that the longer the generator is producing values using the same seed,
		// the more likely an attacker is to be able to determine the original seed by
		// passively observing generated values.
		reseedAt = getNextReseedAt();

		return( this );

	}

	/**
	* Generate "cryptographically strong" random token strings that are based on the
	* given number of random bytes. The random bytes are subsequently encoded using a
	* base64url character-set so that they are URL-safe and can be used in a variety of
	* contexts. And, since base65url is a case-sensitive schema, the tokens will
	* naturally be case-sensitive.
	*
	* @byteCount The number of random bytes used to generate the token.
	*/
	public string function nextToken( numeric byteCount = 32 ) {

		// Check to see if the generator needs to be reseeded (using a double-check
		// locking approach to reduce the bottleneck).
		if ( now() >= reseedAt ) {

			// Synchronize the reseeding.
			lock
				name = "TokenGenerator.reseedCheck"
				type = "exclusive"
				timeout = 1
				throwOnTimeout = false
				{

				// Perform double-check - generator may have already been reseeded by
				// a parallel request.
				if ( now() >= reseedAt ) {

					reseedAt = getNextReseedAt();

					// NOTE: Once the generator was seeded internally, this re-seeding
					// will only ever "add to" the existing seed. As such, this is still
					// building on top of the original randomness and calling this, on
					// interval, this will never reduce randomness.
					generator.setSeed( generator.generateSeed( javaCast( "int", 32 ) ) );
				}

			} // END: Lock.

		}

		// Create the byte buffer into which the random bytes will be written. Since
		// there's no "correct" way to generate a byte array in ColdFusion, we can
		// generate a string of the desired length and then decode it into bytes.
		var byteBuffer = charsetDecode( repeatString( " ", byteCount ), "utf-8" );

		generator.nextBytes( byteBuffer );

		return( encodeBytes( byteBuffer ) );

	}

	/**
	* Encode the given byte array using the base64url character-set.
	*
	* @bytes The byte array being encoded.
	*/
	private string function encodeBytes( required binary bytes ) {

		var token = binaryEncode( bytes, "base64" );

		// Replace the characters that are not allowed in the base64url format. The
		// characters [+, /, =] are removed for URL-based base64 values because they
		// have significant meaning in the context of URL paths and query-strings.
		token = replace( token, "+", "-", "all" );
		token = replace( token, "/", "_", "all" );
		token = replace( token, "=", "", "all" );

		return( token );

	}


	/**
	* Calculate the next date of reseeding.
	*/
	private date function getNextReseedAt() {

		return( dateAdd( "h", 1, now() ) );

	}

}
