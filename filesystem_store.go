package wallet

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

const dataFileExtension string = ".id"
const extensionLength = 3

type FileSystemStore struct {
	path string
}

// NewFileSystemWallet creates an instance of a wallet, held on the filesystem.
//  Parameters:
// 	path specifies where on the filesystem to store the wallet.
//  Returns:
// 	A Wallet object.
func NewFileSystemStore(path string) (*FileSystemStore, error) {
	cleanPath := filepath.Clean(path)
	err := os.MkdirAll(cleanPath, os.ModePerm)
	if err != nil {
		return nil, err
	}

	store := &FileSystemStore{cleanPath}
	return store, nil
}

// Put an identity into the wallet.
func (fsw *FileSystemStore) Put(label string, content []byte) error {
	pathname := filepath.Join(fsw.path, label) + dataFileExtension

	f, err := os.OpenFile(filepath.Clean(pathname), os.O_RDWR|os.O_CREATE, 0600)

	if err != nil {
		return err
	}

	if _, err := f.Write(content); err != nil {
		_ = f.Close() // ignore error; Write error takes precedence
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	return nil
}

// Get an identity from the wallet.
func (fsw *FileSystemStore) Get(label string) ([]byte, error) {
	pathname := filepath.Join(fsw.path, label) + dataFileExtension

	return ioutil.ReadFile(filepath.Clean(pathname))
}

// Remove an identity from the wallet. If the identity does not exist, this method does nothing.
func (fsw *FileSystemStore) Remove(label string) error {
	pathname := filepath.Join(fsw.path, label) + dataFileExtension
	_ = os.Remove(filepath.Clean(pathname))
	return nil
}

// Exists tests the existence of an identity in the wallet.
func (fsw *FileSystemStore) Exists(label string) bool {
	pathname := filepath.Join(fsw.path, label) + dataFileExtension

	_, err := os.Stat(filepath.Clean(pathname))
	return err == nil
}

// List all of the labels in the wallet.
func (fsw *FileSystemStore) List() ([]string, error) {
	files, err := ioutil.ReadDir(fsw.path)

	if err != nil {
		return nil, err
	}

	var labels []string
	for _, file := range files {
		name := file.Name()
		if filepath.Ext(name) == dataFileExtension {
			labels = append(labels, name[:len(name)-extensionLength])
		}
	}

	return labels, nil
}
