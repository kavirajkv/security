//Eliptic curve diffie helman key exchange algorithm uses eliptic curve to generate keys which is used to created shared key by exchanging public keys

//Steps:
//Here AES256 algorithm is used for encryption
//sender and receiver creates a key pair using eliptic curve
//sender uses his private key and receivers public key to create a shared key
//sender uses the shared key and nonce to encrypt the data
//receiver who receives the encrypted data along with sender's public key and nonce
//Receiver uses his private key and sender's public key to create a shared key
//receiver decrypts the message using the shared key

package exchange

import (
	"crypto/ecdh"
	"crypto/rand"
)

// to generate keypairs(public and private)
func GenerateKeypair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	curve := ecdh.P256()

	privatekey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	publickey := privatekey.PublicKey()

	return privatekey, publickey, nil
}

func GenerateSharedkey(private *ecdh.PrivateKey, public *ecdh.PublicKey) ([]byte, error) {
	sharedkey, err := private.ECDH(public)
	if err != nil {
		return nil, err
	}
	return sharedkey, nil
}

///////////////////////////
// to test//

	// senderpri,senderpub,err:=exchange.GenerateKeypair()
	// receiverpri,receiverpub,err:=exchange.GenerateKeypair()

	// sendershared,_:=exchange.GenerateSharedkey(senderpri,receiverpub)
	// receivershared,_:=exchange.GenerateSharedkey(receiverpri,senderpub)


	// cipher, nonce, err := encrypt.AESencrypt(sendershared, "hello world")
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Println(string(cipher))
	// fmt.Println("----")
	// // fmt.Println(nonce)

	// text := encrypt.AESdecrypt(receivershared, cipher, nonce)

	// fmt.Println(string(text))
/////////////////////////////////////
