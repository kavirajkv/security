//ECDSA is digital signature algorithm which uses eliptic curve to generate key pairs

//Working of Digital signature algorithm
//1. Sender generates a key pair (public and private key)
//2. then he creates a hash of the message using SHA256/any hashing algorithm
//3. then sender encrypts the hash using his private key to create a signature
//4. receiver receives the actual message along with the public key and signature
//5. receiver decrypts using public key and gets the hash
//6. receiver create his own hash of the message using the same hashing algorithm
//7. if the hashes match then the signature is valid

//Note:
//Here converting all the byte array to string for easy data exchange in APIs

package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// To generate key value pairs using ed25519
func GenerateKeypair() (string, string, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	//converting byte array to string
	publickey := hex.EncodeToString(public[:])
	privatekey := hex.EncodeToString(private[:])

	return publickey, privatekey, nil
}

// To create digital signature
func Digitalsign(privatekey string, digest string) (string,error) {
	//converting string arguments to byte array
	key, err := hex.DecodeString(privatekey)
	if err!=nil{
		return "",err
	}
	message_digest, err:= hex.DecodeString(digest)
	if err!=nil{
		return "",err
	}

	digisign := ed25519.Sign(key, message_digest)
	digitalsign := hex.EncodeToString(digisign) //converting digital sign to string

	return digitalsign,nil
}

// Verify digital signature
func Verifysign(publickey string, digest string, sign string) (bool,error) {
	//convert strings to byte array
	public_key,err := hex.DecodeString(publickey)
	if err!=nil{
		return false,err
	}

	if len(public_key)<32 || len(public_key)>32{
		err:=errors.New("Wrong key size")
		return false,err
	}

	message_digest, err:= hex.DecodeString(digest)
	if err!=nil{
		return false,err
	}

	digitalsign, err := hex.DecodeString(sign)
	if err!=nil{
		return false,err
	}

	verify := ed25519.Verify(public_key, message_digest, digitalsign)
	return verify,nil
}
