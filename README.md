Bitcoin Key Generator

This program generates Bitcoin keys using the BIP32, BIP39, and BIP44 standards. It allows you to generate a master key from a mnemonic, generate child keys from a master key, and generate public addresses from a public key.
Dependencies

The program uses the following external packages:

    github.com/tyler-smith/go-bip32: to generate the master key and child keys.
    github.com/tyler-smith/go-bip39: to generate the mnemonic.
    golang.org/x/crypto/ripemd160: to generate the public key hash.

Usage
Generate a Key with Passphrase

To generate a key with a passphrase, call the Generatewithpassphrase function, passing the passphrase as a string parameter. The function returns a Key structure containing the child key and public address.

go

key := Generatewithpassphrase("passphrase")

Generate a Key from a Mnemonic and Index

To generate a key from a mnemonic and an index, call the GenerateWithIndex function, passing the mnemonic and index as parameters. The function returns a Key structure containing the child key and public address.

go

key, err := GenerateWithIndex("mnemonic", 0)

Generate a Key from a Master Key and Index

To generate a key from a master key and an index, call the Generatefromkey function, passing the master key and index as parameters. The function returns a Key structure containing the child key and public address.

go

key, err := Generatefromkey(masterkey, 0)

Other Functions

The program also includes the following additional functions:

    EncodeToString: to convert a byte-formatted key to a string.
    EncodeToByte: to convert a string-formatted key to a byte.
    Error: to handle errors throughout the program.

Custom Errors

Custom errors are generated using the Customerrors structure. It includes a message and code to identify the error. These errors are used to handle situations where the index entered is greater than 10.
Public Key Hash and Public Address

The pubkeyhash function generates the public key hash and returns the public key hash and public address using the pubkeyaddress function. The public address is generated by converting the hash into a Base58 string.