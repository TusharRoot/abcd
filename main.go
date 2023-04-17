package abcd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/ripemd160"
)

/* This structure will be returned when the key pair is generated. */
type Key struct {
	Childkey    *bip32.Key // struct with the following fields: privatekey,chaincode,key,version,childNumber,depth,isPrivatekey(boolen value),fingerprint
	Childpubkey *bip32.Key
	Pubaddress  string //public address
}

/* Customerrors are generated using this structure.*/
type Customerrors struct {
	Message string // Error message
	Code    int    // Error Code
}

/*
This function generates a cryptographic key that can be returned to the user with or without a passphrase.
if you pass "" empty string than it will create seed without passphrase.
*/
func Generatewithpassphrase(passphrase string) (Key, string) {
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	seed := bip39.NewSeed(mnemonic, passphrase)
	masterkey, err := bip32.NewMasterKey(seed)
	Error(err)
	childkey, err := masterkey.NewChildKey(0)
	Error(err)
	childpub := childkey.PublicKey()
	_, pubaddress := Pubkeyhash(childpub.Key)
	//Return a private key structure and its corresponding public address
	return Key{childkey, childpub, pubaddress}, mnemonic
}

/* This function is used to implement customized errors and return error messages and codes. */
func (e Customerrors) Error() string {
	return e.Message + " Error Code:" + strconv.Itoa(e.Code)
}

/*
	The purpose of this function is to generate a key using a mnemonic.

In the event that the index entered is greater than 10, an error message shall be returned.
*/
func GenerateWithIndex(mnemonic string, index uint32, passphrase string) (Key, error) {
	if index > 10 {
		return Key{}, Customerrors{"Index Must be less than 10", 10}
	} else {
		fmt.Println("Your Mnemonic:->", mnemonic)
		seed := bip39.NewSeed(mnemonic, passphrase)
		masterkey, err := bip32.NewMasterKey(seed)
		Error(err)
		return Generatefromkey(masterkey, index)
	}
}

/*
This function creates a key from another key using the bip32.Key structure.
If the index is greater than 10, an error message will be returned.
*/
func Generatefromkey(masterkey *bip32.Key, index uint32) (Key, error) {
	if index > 10 {
		return Key{}, Customerrors{"Index Must be less than ", 1005}
	} else {
		childkey, err := masterkey.NewChildKey(index)
		Error(err)
		childpub := childkey.PublicKey()
		_, pubaddress := Pubkeyhash(childpub.Key)
		//Return ChildPublic Address and Child Public Key
		return Key{childkey, pubaddress}, nil
	}
}

/*
	This Function generate Publickeyhash which is used to generate publicaddress.

and return publickeyhash and publicaddress.
*/
func Pubkeyhash(key []byte) (string, string) {
	versionByte := byte(0x00)
	shahash := sha256.Sum256(key)
	hasher := ripemd160.New()
	hasher.Write(shahash[:])
	hashBytes := hasher.Sum(nil)
	//(hashString)= publichash from publickey
	hashString := fmt.Sprintf("%x", hashBytes)
	versionedHash := append([]byte{versionByte}, hashBytes...)
	// return pubkeyhash and publicaddress.
	return hashString, pubkeyaddress(versionedHash)
}

/* PublicKeyHash is a function that is called by the publickeyhash function and will return the pubkeyaddress.*/
func pubkeyaddress(versionedHash []byte) string {
	checksum := checksum(versionedHash)
	fullHash := append(checksum, versionedHash...)
	pubaddress := "TS" + bip32.BitcoinBase58Encoding.EncodeToString(fullHash)
	//publickey address from the publickey hash
	return pubaddress
}

/* This function is used to generate checksum from Publickey.*/
func checksum(payload []byte) []byte {
	//generate hash from versionhash (combination of version number, hash of public key )
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	//return first four bytes as checkcum
	return secondHash[:4]
}

/* This function is used to convert byte formated Key into string */
func EncodeToString(key []byte) string {
	return hex.EncodeToString(key)
}

/* This function is used to convert string formated Key into byte */
func EncodeToByte(s string) []byte {
	return []byte(s)
}

/* This function is used to return an error. and used every where when there is chance of error occurence */
func Error(e error) {
	if e != nil {
		panic(e)
	}
}
