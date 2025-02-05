//AES is introduced to overcome the security issues from DES
// DES and AES both are symmetric key algorithms and also these are block ciphers

//Steps for encryption and decyption

//Encyption:
//1.create a random key using rand of size 16/32 (16 for AES-128, 32 for AES-256) bytes
//2.convert the plaintext into byte array
//3.create a new AES cipher block
//4.create a GCM mode of that block (GCM mode is recommended for both integrety and authenticity)
//5.create a nonce (this nonce can be useful to prevent from replay i.e new cipher at each time)(it should be 12 bytes -recommended)
//6. create a cypher text by sealing them

//Decryption
//1.Use ciphertext, nonce ,key to decrypt
//2.create a new AES cipher block
//3.create a GCM mode of that block
//4.get plain text using gcm open using cipher, key,nonce

package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

//to create random key
func GenerateKey()([]byte,error){
	x:=make([]byte,32)
	_,err:=rand.Read(x)
	if err!=nil{
		return nil,err
	}
	return x,nil
}

//AES encryption
func AESencrypt(key []byte,plaintext string)([]byte,[]byte,error){
	text:=[]byte(plaintext)

	aes,_:=aes.NewCipher(key)

	aesgcm,_:=cipher.NewGCM(aes)

	nonce:=make([]byte,aesgcm.NonceSize())
	_,err:=rand.Read(nonce)
	if err!=nil{
		return nil,nil,err
	}

	ciphertext:=aesgcm.Seal(nil,nonce,text,nil)

	return ciphertext,nonce,nil
}

//AES decryption
func AESdecrypt(key []byte, ciphertext []byte,nonce []byte)([]byte){
	aes,_:=aes.NewCipher(key)

	aesgcm,_:=cipher.NewGCM(aes)

	text,_:=aesgcm.Open(nil,nonce,ciphertext,nil)

	return text

}