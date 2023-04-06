<h1>Tsunagu Key Generator</h1>


This program generates Tsunagu keys using the BIP32, BIP39 standards. It allows you to generate a master key from a mnemonic, generate child keys from a master key, and generate public addresses from a public key.

<h3>Dependencies</h3>

The program uses the following external packages:

    github.com/tyler-smith/go-bip32: to generate the master key and child keys.
    github.com/tyler-smith/go-bip39: to generate the mnemonic.
    golang.org/x/crypto/ripemd160: to generate the public key hash.

<h2>Usage</h2>
<h3>Generate a Key</h3>

To generate a key with a passphrase, call the Generatewithpassphrase function, passing the passphrase as a string parameter. The function returns a Key structure containing the child key and public address.

Note: if you pass "" empty string than it will create seed without passphrase.

Example:

key := Generatewithpassphrase("passphrase")

<h3>Generate a Key from a Mnemonic and Index</h3>

To generate a key from a mnemonic and an index, call the GenerateWithIndex function, passing the mnemonic and index as parameters. The function returns a Key structure containing the child key and public address.

Note : In the event that the index entered is greater than 10, an error message shall be returned.

Example:

key, err := GenerateWithIndex("mnemonic", 0)

<h3>Generate a Key from a Master Key and Index</h3>

To generate a key from a master key and an index, call the Generatefromkey function, passing the master key and index as parameters. The function returns a Key structure containing the child key and public address.

Note : In the event that the index entered is greater than 10, an error message shall be returned.
Example:
```go
    key, err := Generatefromkey(masterkey, 0)
```

<h3>Other Functions</h3>

The program also includes the following additional functions:

    EncodeToString: to convert a byte-formatted key to a string.
    EncodeToByte: to convert a string-formatted key to a byte.
    Error: to handle errors throughout the program.

<h3>Public key Hash Function</h3>

The pubkeyhash function generates the public key hash and returns the public key hash and public address using the pubkeyaddress function. The public address is generated by converting the hash into a Base58 string.
