module libcommon.crypto.rc4;

// RC4, stream cipher with known vulnerabilities
// See https://en.wikipedia.org/wiki/RC4#Implementation

// swap is used a number of times
void swap(T)(ref T arr, int x, int y) @nogc {
  auto temp = arr[x];
  arr[x] = arr[y];
  arr[y] = temp;
}

// RC4 Keyscheduling Algorithm
// Initializs the state array
int[256] RC4KSA(const string key) pure
in {
  const size_t string_size = key.length * key[0].sizeof;
  assert(string_size >= 1);
  assert(string_size <= 256);
}
do {
  import std.conv: to;
  // convert key to int
  int[] key_arr;

  foreach (kc; key) {
    key_arr ~= to!int(kc);
  }

  int[256] state;
  foreach (int i; 0 .. 256)
    state[i] = i;

  int j = 0;

  foreach (int i; 0 .. 256) {
    j = (j + state[i] + key_arr[i % key_arr.length]) % 256;

    swap(state, i, j);
  }

  return state;
}

// RC4 RNG - Returns a generator
int[256] RC4PRGA(int[256] state, int len) pure {
  int[256] kstream;
  int i = 0;
  int j = 0;

  foreach (int index; 0 .. len) {
    i = (i + 1) % 256;
    j = (j + state[i]) % 256;

    swap(state, i, j);

    kstream[index] = state[(state[i] + state[j]) % 256];
  }

  return kstream;
}

string RC4crypt(const string key, const string values) pure {
  import std.conv: to;
  import std.format: format;

  auto kstream = RC4PRGA(RC4KSA(key), to!int(values.length));

  // XOR and get the hex
  string cipher = "";
  foreach (int i; 0 .. to!int(values.length)) {
    cipher ~= format("%02X", values[i] ^ kstream[i]);
  }

  debug {
    import std.stdio: writeln;

    writeln("RC4 (De/En)cryption test: ", cipher);
  }

  return cipher;
}

string RC4encrypt(const string key, const string values) pure {
  return RC4crypt(key, values);
}

string RC4decrypt(const string key, const string cipher) pure {
  import std.conv: to;

  auto hexToString = (string hex) {
    string converted = "";
    for (int i = 0; i < hex.length; i += 2) {
      string hexP = hex[i .. i + 2];
      int decVal = hexP.to!int(16);
      converted ~= to!char(decVal);
    }

    return converted;
  };

  auto ret = RC4crypt(key, hexToString(cipher));

  auto converted = hexToString(ret);

  debug {
    import std.stdio: writeln;
    writeln("RC4 Decrypted Result: ", converted);
  }

  return converted;
}

unittest {
  // ensure encryption -> decryption works
  import std.format: format;

  // test vectors from Wiki
  const string[3] keys = ["Key", "Wiki", "Secret"];
  const string[3] plaintexts = ["Plaintext", "pedia", "Attack at dawn"];
  const string[3] ciphers = ["BBF316E8D940AF0AD3", "1021BF0420", "45A01F645FC35B383552544B9BF5"];

  foreach (i; 0 .. 3) {

    const auto key = keys[i];
    const auto original = plaintexts[i];

    const cipher = RC4encrypt(key, original);
    const decrypted = RC4decrypt(key, cipher);

    assert(cipher == ciphers[i]);
    assert(decrypted == original);
  }
}
