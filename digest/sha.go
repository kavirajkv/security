//to overcome security issues in md5, sha1, sha128, sha256, sha512 has been introduced
// sha256 produces digest of size 256 bits


package digest

import (
	"crypto/sha256"
	"encoding/hex"
)



func ShaDigest(data string) string{
	toconvert:=[]byte(data)
	encrypted:=sha256.Sum256(toconvert)
	return hex.EncodeToString(encrypted[:])
}

func ShaCheck(digest string,data string) bool{
	tocheck:=ShaDigest(data)
	if (digest==tocheck){
		return true
	} else{
		return false
	}

}