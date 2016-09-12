component {

	HASH_ALGORITHM = "sha-512";
	HASH_ITERATIONS = "1000";

	// Changing these will break previously hashed passwords
	HASH_SECTIONS = "4";
	HASH_ALGORITHM_INDEX = "1";
	HASH_ITERATION_INDEX = "2";
	HASH_SALT_INDEX = "3";
	HASH_INDEX = "4";

	function init() {
		return this;
	}

	// Create a hash that can be stored instead of the plaintext password
	string function create_hash(required string password) {
		// Get salt to add to the password
		var hash_salt = Hash(GenerateSecretKey("AES"), HASH_ALGORITHM);

		// Hash the password using the salt and then hash it HASH_ITERATIONS more times
		var hashed_password = Hash(password & hash_salt, HASH_ALGORITHM);
		for(var i = 0; i <= HASH_ITERATIONS; i++) {
			hashed_password = Hash(hashed_password & hash_salt, HASH_ALGORITHM);
		}

		// Create a string with the salt, hashed password, and other info needed to compare
		var return_string = HASH_ALGORITHM & ":" & HASH_ITERATIONS & ":" & hash_salt & ":" & hashed_password;

		return return_string;
	}

	// Function takes the given password and the hashed one and compares them
	boolean function validate_password(required string password, required string correct_hash) {
		// Split the password into the parts we need to compare it
		var params = ListToArray(correct_hash, ":");

		// Make sure all the parts we need are here
		if(ArrayLen(params) < HASH_SECTIONS) {
			return false;
		}

		// Hash the password so we can compare it to the already hashed one
		var hashed_password = Hash(password & params[HASH_SALT_INDEX], params[HASH_ALGORITHM_INDEX]);
		for(var i = 0; i <= params[HASH_ITERATION_INDEX]; i++) {
			hashed_password = Hash(hashed_password & params[HASH_SALT_INDEX], params[HASH_ALGORITHM_INDEX]);
		}

		// Compare the hashed password with the stored one using bitwise xor
		if(slow_equals(hashed_password, params[HASH_INDEX]) == 0) {
			return true;
		} else {
			return false;
		}
	}

	// Compares 2 strings in length-constant time to prevent time-based password cracking
	private numeric function slow_equals(required string val_1, required string val_2) {
		var diff = bitXor(Len(val_1), Len(val_2));
		var i = 0;

		do {
			diff = bitXor(diff, (bitXor(asc(Mid(val_1, i+1, 1)), asc(Mid(val_2, i+1, 1)))));
			i++;
		} while ((i < Len(val_1)) and (i < Len(val_2)));

		return diff;
	}

}
