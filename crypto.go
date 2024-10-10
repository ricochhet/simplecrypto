package simplecrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"strings"
)

const (
	CipherTag    = "<CipherKey>"
	Base64_16Len = 24
)

var DlfKey = []byte{ //nolint:gochecknoglobals // wontfix
	65, 50, 114, 45, 208, 130, 239, 176, 220, 100, 87, 197, 118, 104, 202, 9,
}

var IV = make([]byte, 16) //nolint:gochecknoglobals,mnd // wontfix

var (
	errDlfFileNotFound   = errors.New("error: DLF file not found")
	errCipherTagNotFound = errors.New("error: Cipher tag not found")
	errInvalidBase64Key  = errors.New("error: invalid base64 key")
	errInvalidIVSize     = errors.New("error: invalid IV size")
	errInvalidBufferSize = errors.New("error: invalid buffer size")
)

func NewHash(filePath string, hash hash.Hash) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}

	defer file.Close()

	_, err = io.Copy(hash, file)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func AESEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize] //nolint:varnamelen // wontfix

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func AESDecrypt(key []byte, iv []byte, buf []byte) ([]byte, error) { //nolint:varnamelen // wontfix
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize {
		return nil, err
	}

	if len(buf) < aes.BlockSize {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(buf, buf)

	return buf, nil
}

func AESDecryptBase64(keyBase64 string, iv []byte, buf []byte) error { //nolint:varnamelen // wontfix
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return errInvalidBase64Key
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	if len(iv) != aes.BlockSize {
		return errInvalidIVSize
	}

	if len(buf) < aes.BlockSize {
		return errInvalidBufferSize
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(buf, buf)

	return nil
}

func DecryptDLF(data []byte) ([]byte, error) {
	decrypted, err := AESDecrypt(DlfKey, data[0x41:], []byte{0})
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

func GetDLFAuto(contentID string) ([]byte, error) {
	paths := []string{
		contentID + ".dlf",
		contentID + "_cached.dlf",
	}

	for _, path := range paths {
		data, err := readFile(path)
		if err == nil {
			return DecryptDLF(data)
		}
	}

	return nil, errDlfFileNotFound
}

func DecodeCipherTag(dlf []byte) ([]byte, error) {
	stringData := string(dlf)
	pos := strings.Index(stringData, CipherTag)

	if pos == -1 {
		return nil, errCipherTagNotFound
	}

	pos += len(CipherTag)
	base64Data := stringData[pos : pos+Base64_16Len]

	decoded, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, err
	}

	if len(decoded) > 16 { //nolint:mnd // wontfix
		decoded = decoded[:16]
	}

	return decoded, nil
}

func GetOoaHash(data []byte) []byte {
	if len(data) < 0x3E { //nolint:mnd // wontfix
		return nil
	}

	return data[0x2A:0x3E]
}

func readFile(filename string) ([]byte, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return file, nil
}
