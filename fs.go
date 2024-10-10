package simplecrypto

import (
	"crypto/md5" //nolint:gosec // wontfix
	"os"
	"path/filepath"
)

type DiffData struct {
	Hashes DiffHashData
	Local  DiffLocalData
}

type DiffHashData struct {
	File  string
	PathA string
	PathB string
	HashA string
	HashB string
}

type DiffLocalData struct {
	Path    string
	ExistsA string
	ExistsB string
}

func HashDirectory(folder string) (map[string]string, error) {
	fileHashes := make(map[string]string)

	err := filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			relativePath, _ := filepath.Rel(folder, path)

			hash, err := NewHash(path, md5.New()) //nolint:gosec // wontfix
			if err != nil {
				return err
			}

			fileHashes[relativePath] = hash
		}

		return nil
	})

	return fileHashes, err
}

func DiffDirectory(fileHashesA, fileHashesB map[string]string, folderA, folderB string) []DiffData {
	var diff []DiffData

	for pathA, hashA := range fileHashesA {
		if hashB, exists := fileHashesB[pathA]; !exists {
			diff = append(diff, DiffData{
				DiffHashData{}, //nolint:exhaustruct // wontfix
				DiffLocalData{
					Path:    pathA,
					ExistsA: folderA,
					ExistsB: folderB,
				},
			})
		} else if hashA != hashB {
			diff = append(diff, DiffData{
				DiffHashData{
					File:  pathA,
					PathA: folderA,
					PathB: folderB,
					HashA: hashA,
					HashB: hashB,
				}, DiffLocalData{}, //nolint:exhaustruct // wontfix
			})
		}
	}

	for pathB := range fileHashesB {
		if _, exists := fileHashesA[pathB]; !exists {
			diff = append(diff, DiffData{
				DiffHashData{}, //nolint:exhaustruct // wontfix
				DiffLocalData{
					Path:    pathB,
					ExistsA: folderB,
					ExistsB: folderA,
				},
			})
		}
	}

	return diff
}
