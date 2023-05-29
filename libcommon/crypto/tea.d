module libcommon.crypto.tea;

// The Tiny Encryption Algorithm, relatively secure and simple block cipher
// https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
// Operates on two uint a 64 bit blocks and uses a 128 bit key

// encryption and decryption are used to handle conversion to the correct format
string TEAencrypt(const string key, const string values) pure
in {
  assert(key.length == 16); // requires a 128 bit key, without padding
}
do {
  import std.conv: to;

  const uint[4] conv_key = EncodeString(key);
  const uint[] conv_plain = EncodeString(values);

  uint[] output;

  for (int i = 0; i < conv_plain.length; i += 2)
    output ~= TEAencode(conv_key, to!(uint[2])(conv_plain[i .. i+2]));

  string output_string = DecodeString(output);

  debug {
    import std.stdio: writeln;
    writeln("TEA Encryption test: ", output_string);
    writeln("TEA Encryption blocks: ", output.length/2);
  }

  return output_string;
}

string TEAdecrypt(const string key, const string values) pure {
  import std.conv: to;

  const uint[4] conv_key = EncodeString(key);
  const uint[] conv_cipher = EncodeString(values);

  uint[] output;

  for (int i = 0; i < conv_cipher.length; i += 2)
    output ~= TEAdecode(conv_key, to!(uint[2])(conv_cipher[i .. i+2]));

  string output_string = DecodeString(output);

  debug {
    import std.stdio: writeln;
    writeln("TEA Decryption test: ", output_string);
    writeln("TEA Decryption blocks: ", output.length/2);
  }

  return output_string;
}

unittest {
  immutable auto test_strings = [
    "no pad!!",
    "This is a test!!!",
    "Much longer string to encode and decode",
    "symbol, test' / . , ! @ # $ % ^ & * ( ) [ ] { }",
    "@system functions may perform any operation legal from the perspective of the language, including inherently memory unsafe operations such as pointer casts or pointer arithmetic. However, compile-time known memory corrupting operations, such as indexing a static array out of bounds or returning a pointer to an expired stack frame, can still raise an error. @system functions may not be called directly from @safe functions.",
  ];

  immutable auto key = "This is a keysad";

  foreach(original; test_strings) {
    const auto cipher = TEAencrypt(key, original);
    const auto decoded = TEAdecrypt(key, cipher);
    assert(decoded == original);
  }
}

immutable auto chunk = 8;

// split the string into 8 byte chunks
uint[] EncodeString(const string val) pure
out(res) {
  assert(res.length % 2 == 0); // ensure the resulting encoding is a multiple of two
}
do {
  // string padding
  size_t paddingSize = chunk - (val.length % chunk);
  string paddedVal = val;

  if (paddingSize != chunk)
    foreach (i; 0 .. paddingSize)
      paddedVal ~= '\0';

  uint[] pairs;
  for (int i = 0; i < paddedVal.length; i += chunk/2) {
    // each char is a byte
    char[chunk/2] curVal = paddedVal[i .. i+(chunk/2)];
    uint pairVal = *cast(uint*) curVal;

    pairs ~= pairVal;
  }

  return pairs;
}

string DecodeString(const uint[] val) pure
in {
  assert(val.length % 2 == 0);
}
do {
  import std.array: replace;
  string convVal = "";

  foreach (uint segment; val)
    foreach(i; 0 .. chunk/2)
      convVal ~= cast(char) (segment >> i*chunk) & 0xFF;

  return convVal.replace(['\0'], "");
}

unittest {
  immutable auto test_strings = [
    "This is a test",
    "no pad!!",
    "Much longer string to encode and decode",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
  ];

  foreach(original; test_strings) {
    const auto encoded = EncodeString(original);
    const auto decoded = DecodeString(encoded);
    assert(decoded == original);
  }
}

immutable uint cycles = 32;
immutable uint delta = 0x9E3779B9; // key scheduling constant

// Does the TEA algorithm on the given uint values
uint[2] TEAencode(const uint[4] key, const uint[2] values) pure @nogc {
  uint sum = 0;

  uint[2] new_values = values;
  foreach (i; 0 .. cycles) {
    sum += delta;

    new_values[0] += ((new_values[1] << 4) + key[0])
      ^ (new_values[1] + sum) ^ ((new_values[1] >> 5) + key[1]);

    new_values[1] += ((new_values[0] << 4) + key[2])
      ^ (new_values[0] + sum) ^ ((new_values[0] >> 5) + key[3]);
  }

  return new_values;
}

uint[2] TEAdecode(const uint[4] key, const uint[2] values) pure @nogc {
  uint sum = (delta << 5) & 0xFFFFFFFF;

  uint[2] new_values = values;
  foreach (i; 0 .. cycles) {

    new_values[1] -= ((new_values[0] << 4) + key[2])
    ^ (new_values[0] + sum) ^ ((new_values[0] >> 5) + key[3]);

    new_values[0] -= ((new_values[1] << 4) + key[0])
      ^ (new_values[1] + sum) ^ ((new_values[1] >> 5) + key[1]);

    sum -= delta;
  }

  return new_values;
}

unittest {
  uint[4] key = [32, 123213, 4322346, 321841];
  uint[2] original = [2314123545, 1454354141];

  auto cipher = TEAencode(key, original);
  auto decoded = TEAdecode(key, cipher);

  assert(decoded == original);
}
