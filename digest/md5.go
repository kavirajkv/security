// this is a algorithm to create a message digest which can be used to find authenticity of a content 
// this digest can be used to store sensitive data which should not to be saved as same (ex: password)
// this will give 128 bit hash value

package digest

import (
	"crypto/md5"
	"encoding/hex"
)

func Digest(data string) string{
	toconvert:=[]byte(data)
	encrypted:=md5.Sum(toconvert)
	return hex.EncodeToString(encrypted[:])
}

func CheckDigest(digest string,data string) bool{
	tocheck:=Digest(data)
	if (digest==tocheck){
		return true
	} else{
		return false
	}
}