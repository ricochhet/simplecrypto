package simplecrypto

import (
	"crypto/md5"  //nolint:gosec // wontfix
	"crypto/sha1" //nolint:gosec // wontfix
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"hash/crc32"
	"hash/crc64"

	"github.com/ricochhet/murmurhash3"
	"github.com/ricochhet/readwrite"
)

var errHashNotEqual = errors.New("file hash is not equal to specified hash")

func Validate(filePath, fileHash string, hash hash.Hash) error {
	hashA, err := NewHash(filePath, hash)
	if err != nil {
		return err
	}

	if hashA != fileHash {
		return errHashNotEqual
	}

	return nil
}

func NewMD5(filePath string) (string, error) {
	s, err := NewHash(filePath, md5.New()) //nolint:gosec // wontfix
	if err != nil {
		return "", err
	}

	return s, nil
}

func NewSHA1(filePath string) (string, error) {
	s, err := NewHash(filePath, sha1.New()) //nolint:gosec // wontfix
	if err != nil {
		return "", err
	}

	return s, nil
}

func NewSHA256(filePath string) (string, error) {
	s, err := NewHash(filePath, sha256.New())
	if err != nil {
		return "", err
	}

	return s, nil
}

func NewSHA512(filePath string) (string, error) {
	s, err := NewHash(filePath, sha512.New())
	if err != nil {
		return "", err
	}

	return s, nil
}

func NewCRC32(filePath string) (string, error) {
	s, err := NewHash(filePath, crc32.New(crc32.IEEETable))
	if err != nil {
		return "", err
	}

	return s, nil
}

func NewCRC64(filePath string) (string, error) {
	s, err := NewHash(filePath, crc64.New(crc64.MakeTable(crc32.IEEE)))
	if err != nil {
		return "", err
	}

	return s, nil
}

func Murmur3X64_128Hash(seed int, str string) uint64 {
	hashBytes := murmurhash3.NewX64_128(seed)
	hashBytes.Write(readwrite.Utf8ToUtf16(str))

	return binary.LittleEndian.Uint64(hashBytes.Sum(nil))
}

func Murmur3X86_32Hash(seed int, str string) uint32 {
	hashBytes := murmurhash3.NewX86_32(seed)
	hashBytes.Write(readwrite.Utf8ToUtf16(str))

	return binary.LittleEndian.Uint32(hashBytes.Sum(nil))
}

func Murmur3X86_128Hash(seed int, str string) uint32 {
	hashBytes := murmurhash3.NewX86_128(seed)
	hashBytes.Write(readwrite.Utf8ToUtf16(str))

	return binary.LittleEndian.Uint32(hashBytes.Sum(nil))
}
