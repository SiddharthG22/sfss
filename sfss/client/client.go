package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	_ "bytes"
	"encoding/json"
	"fmt"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		Name      string
		Professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).

type FileRef struct { // reference to an encrypted metadata
	MetaUUID    uuid.UUID
	MetaEncKey  []byte
	MetaHMACKey []byte
	Shared      bool
}

type User struct {
	Username  string
	PubKey    userlib.PKEEncKey
	PrivKey   userlib.PKEDecKey
	SignKey   userlib.DSSignKey
	VerKey    userlib.DSVerifyKey
	BaseKey   []byte
	UserFiles map[string]FileRef
	// UserFiles UserFiles
	// UserFiles map[string]UUIDTuple // To Do: map file name to UUID tuple -> come back to this
}

type UserFiles struct {
	FileMap map[string]FileRef
}

type FileNode struct { // file itself - chunk of file data
	Content []byte
	Next    *uuid.UUID
	// FileMetadataAddr uuid.UUID
}

type FileMetadata struct {
	Filename        string
	Owner           string
	FileNodeEncKey  []byte    // for enc/decrypting file
	FileNodeHMACKey []byte    // for verifying integrity of file
	Head            uuid.UUID // pointer to a file node struct (points to the actual file itself)
	Tail            uuid.UUID
	SharedWith      map[string][]User //strings MAPPED to User structs
	SharedBy        map[string][]string
}

type InvRef struct { // reference to an encrypted invitiation
	InvUUID    uuid.UUID
	InvEncKey  []byte
	InvHMACKey []byte
}

type Invitation struct {
	Sender    string //the guy sending the file
	Recipient string
	FileUUID  FileRef
	EncKey    []byte
	HMACKey   []byte
	Shared    bool
}

// type AppendedFileMetadata struct {
// 	Owner         string
// 	EncryptionKey []byte
// 	HMACKey       []byte
// 	ContentPtr    FileNode
// 	SharedWith    map[string]string // map username to access UUID
// }
// type OriginalFileMetadata struct {
// 	Filename      string
// 	Owner         string
// 	EncryptionKey []byte
// 	HMACKey       []byte
// 	ContentPtr    FileNode
// 	Latest        uuid.UUID
// 	Appends       []uuid.UUID
// 	SharedWith    map[string]string // map username to access UUID (the UUID that user generastes when sharing file)
// 	RevokedAccess map[string]string // map username to access UUID to prevent malicious
// 	// To Do: map it to the user struct
// }

// START WRITING CODE HERE

// generates base key using Argon2Key
func deriveBaseKey(password string, salt []byte) (bk []byte, err error) {
	baseKey := userlib.Argon2Key([]byte(password), salt, 16) // use it later
	return baseKey, nil
}

// deterministically derives keys for encryption/HMAC through base key
func deriveKeys(baseKey []byte) (encKey []byte, hmacKey []byte, err error) {
	encKey, err = userlib.HashKDF(baseKey, []byte("encryption-key"))
	if err != nil {
		return nil, nil, err
	}
	hmacKey, err = userlib.HashKDF(baseKey, []byte("hmac-key"))
	if err != nil {
		return nil, nil, err
	}
	return encKey[:16], hmacKey[:16], nil
}

func HmacDecrypt(obj []byte, symKey []byte, hmacKey []byte) (dec []byte, err error) {
	const hmacLength = 64 // line 293: store userUUID, ciphertext, followed by 64 byte HMAC
	storedCiphertext := obj[:len(obj)-hmacLength]
	storedHMAC := obj[len(obj)-hmacLength:]
	computedHMAC, err := userlib.HMACEval(hmacKey, storedCiphertext)
	if err != nil || !userlib.HMACEqual(computedHMAC, storedHMAC) {
		return nil, errors.New("HMACs do not match one another")
	}
	decryptedUser := userlib.SymDec(symKey, storedCiphertext)
	return decryptedUser, nil
}

func EncryptHmac(marshaledObj []byte, symKey []byte, hmacKey []byte) (contents []byte, err error) {
	iv := userlib.RandomBytes(16)
	ciphertext := userlib.SymEnc(symKey, iv, marshaledObj)
	hmac, err := userlib.HMACEval(hmacKey, ciphertext)
	if err != nil {
		return nil, err
	}
	return append(ciphertext, hmac...), nil // encrypt-then-MAC
}

func GetCiphertext(obj []byte) (cipher []byte) {
	const hmacLength = 64
	ciphertext := obj[:len(obj)-hmacLength]
	return ciphertext
}

func GetHMAC(obj []byte) (HMAC []byte) {
	const hmacLength = 64
	hmac := obj[len(obj)-hmacLength:]
	return hmac
}

func (userdata *User) VerifyDecrypt(verKey userlib.PublicKeyType, rsaCipher []byte, aesCipher []byte, signature []byte) (invRef []byte, err error) {
	hybridCipher := append(rsaCipher, aesCipher...)
	err = userlib.DSVerify(verKey, hybridCipher, signature)
	if err != nil {
		return nil, errors.New("unable to verify signature on invitiation")
	}
	invRefSymDec, err := userlib.PKEDec(userdata.PrivKey, rsaCipher)
	if err != nil {
		return nil, errors.New("unable to decrypt invitation")
	}
	decryptedInvRef := userlib.SymDec(invRefSymDec, aesCipher)
	return decryptedInvRef, nil
}

// NOTE: The following methods have toy (insecure!) implementations.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	if len(username) == 0 {
		return nil, errors.New("username is not long enough")
	}
	if len(password) == 0 {
		return nil, errors.New("password is not long enough")
	}

	// retrieve UIUD
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + "user"))[:16])
	if err != nil {
		return nil, err
		// panic("UUID creation failed")
	}
	_, exists := userlib.DatastoreGet(userUUID)
	// userlib.DebugMsg("Does user exist %v", exists)
	if exists {
		return nil, errors.New("user already exists")
	}

	// random salt for Argon2Key + generate UUID for salt
	// salt := userlib.Hash([]byte(username + "userSalt" + password))[:16]
	salt := userlib.RandomBytes(16)
	saltUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + "userSalt" + password))[:16])
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(saltUUID, salt) // saltUUID = uuid.UUID, salt = []byte

	storedSalt, ok := userlib.DatastoreGet(saltUUID)
	if !ok {
		return nil, errors.New("salt not found")
	}

	baseKey, err := deriveBaseKey(password, storedSalt)
	if err != nil {
		return nil, errors.New("error deriving base key")
	}
	encryptionKey, hmacKey, err := deriveKeys(baseKey)
	if err != nil {
		return nil, err
	}

	// RSA public and private keys for encryption and decryption
	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	signatureKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	// userlib.DebugMsg("getting %s's public key of type: %T \n", username, publicKey)

	// create user struct
	userdata.Username = username
	userdata.PubKey = publicKey
	// userlib.DebugMsg("getting user's public key of type: %T", publicKey.(userlib.PKEEncKey))
	userdata.PrivKey = privateKey
	userdata.BaseKey = baseKey
	userdata.SignKey = signatureKey
	userdata.VerKey = verifyKey
	userdata.UserFiles = make(map[string]FileRef) // initialize an empty map

	userFilesUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + "userfiles"))[:16])
	if err != nil {
		return nil, err
	}
	userFilesBytes, err := json.Marshal(userdata.UserFiles)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(userFilesUUID, userFilesBytes)

	// marshal + encrypt user struct
	marshaledUserData, err := json.Marshal(userdata) // converts/serializes struct into byte array - necessary for encrypting it
	if err != nil {
		return nil, err
	}
	userContents, err := EncryptHmac(marshaledUserData, encryptionKey, hmacKey)
	if err != nil {
		return nil, errors.New("failure during encryption or HMAC calculation")
	}

	_, ok = userlib.KeystoreGet(string(userlib.Hash([]byte(username + "public-key"))))
	if !ok {
		err = userlib.KeystoreSet(string(userlib.Hash([]byte(username+"public-key"))), userdata.PubKey)
		if err != nil {
			return nil, errors.New("failed to save %s's public key due to " + username + err.Error())
		}
	}
	_, ok = userlib.KeystoreGet(string(userlib.Hash([]byte(username + "verify-key"))))
	if !ok {
		err = userlib.KeystoreSet(string(userlib.Hash([]byte(username+"verify-key"))), userdata.VerKey)
		if err != nil {
			return nil, errors.New("failed to save %s's verification key due to " + username + err.Error())
		}
	}

	// userlib.DebugMsg("saving user's public key of type: %T", userdata.PubKey)
	userlib.KeystoreSet(string(userlib.Hash([]byte(username+"public-key"))), userdata.PubKey)
	userlib.KeystoreSet(string(userlib.Hash([]byte(username+"verify-key"))), userdata.VerKey)

	userlib.DatastoreSet(userUUID, userContents)
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// NEW CODE
	var userdata User
	userdataptr = &userdata

	if len(username) == 0 || len(password) == 0 {
		return nil, errors.New("username or password are not long enough")
	}
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + "user"))[:16])
	if err != nil {
		return nil, errors.New("user already exists")
	}
	user, exists := userlib.DatastoreGet(userUUID)
	if !exists {
		return nil, errors.New("user does not exist")
	}
	saltUUIDBytes, err := uuid.FromBytes(userlib.Hash([]byte(username + "userSalt" + password))[:16])
	if err != nil {
		return nil, err
	}
	storedSalt, ok := userlib.DatastoreGet(saltUUIDBytes)
	if !ok {
		return nil, errors.New("salt was not found")
	}
	baseKey, err := deriveBaseKey(password, storedSalt)
	if err != nil {
		return nil, errors.New("error deriving base key")
	}
	encryptionKey, hmacKey, err := deriveKeys(baseKey)
	if err != nil {
		return nil, err
	}
	decryptedUser, err := HmacDecrypt(user, encryptionKey, hmacKey)
	if err != nil {
		return nil, errors.New("failure during HMAC checking or decryption")
	}
	unmarshaledUser := json.Unmarshal(decryptedUser, userdataptr)
	if unmarshaledUser != nil {
		return nil, errors.New("could not retrieve user")
	}

	_, ok = userlib.KeystoreGet(string(userlib.Hash([]byte(username + "public-key"))))
	if !ok {
		err = userlib.KeystoreSet(string(userlib.Hash([]byte(username+"public-key"))), userdata.PubKey)
		if err != nil {
			return nil, err
		}
	}
	_, ok = userlib.KeystoreGet(string(userlib.Hash([]byte(username + "verify-key"))))
	if !ok {
		err = userlib.KeystoreSet(string(userlib.Hash([]byte(username+"verify-key"))), userdata.VerKey)
		if err != nil {
			return nil, err
		}
	}

	// persist UserFiles
	userFilesUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + "userfiles"))[:16])
	if err != nil {
		return nil, err
	}
	userFilesBytes, exists := userlib.DatastoreGet(userFilesUUID)
	if exists {
		err := json.Unmarshal(userFilesBytes, &userdata.UserFiles)
		if err != nil {
			return nil, errors.New("could not load userfiles")
		}
	} else {
		userdata.UserFiles = make(map[string]FileRef)
	}
	// persist UserFiles

	userdata.BaseKey = baseKey
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// NEW CODE
	if len(filename) == 0 {
		return errors.New("invalid filename")
	}
	if content == nil {
		return errors.New("content must not be emtpy")
	}

	// check for persistence
	userFilesUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "userfiles"))[:16])
	if err != nil {
		return err
	}
	userFilesBytes, ok := userlib.DatastoreGet(userFilesUUID)
	if ok {
		err := json.Unmarshal(userFilesBytes, &userdata.UserFiles)
		if err != nil {
			return err
		}
	}
	// check for persistence

	metaRef, exists := userdata.UserFiles[filename]
	// if file exists, decrypt it, iterate through the chain of files, and delete it
	if exists {
		metaBytes, ok := userlib.DatastoreGet(metaRef.MetaUUID)
		if ok {
			metaPlaintext, err := HmacDecrypt(metaBytes, metaRef.MetaEncKey, metaRef.MetaHMACKey)
			if err != nil {
				return errors.New("failure during HMAC checking or decryption")
			}
			var currMeta FileMetadata
			err = json.Unmarshal(metaPlaintext, &currMeta)
			curr := currMeta.Head
			if err == nil {
				for curr != uuid.Nil {
					fileContentChunk, ok := userlib.DatastoreGet(curr)
					if !ok {
						return errors.New("failed to retrieve or verify old chunk")
					}
					plaintext, _ := HmacDecrypt(fileContentChunk, currMeta.FileNodeEncKey, currMeta.FileNodeHMACKey)
					var file FileNode
					err = json.Unmarshal(plaintext, &file)
					if err != nil {
						return err
					}
					// extract .Next of current decrypted file node
					next := uuid.Nil
					if file.Next != nil {
						next = *file.Next
					}
					// Office Hours Question: do we need the below
					userlib.DatastoreDelete(curr)
					curr = next
				}
				// Office Hours Question
				//override so we should delete
				userlib.DatastoreDelete(metaRef.MetaUUID)
			}
		}
	}
	// create new file
	newFile := FileNode{
		Content: content,
		Next:    nil,
		// FileMetadataAddr: newMetaUUID,
	}
	fileEncKey, fileHmacKey, err := deriveKeys(userlib.RandomBytes(16))
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(newFile)
	if err != nil {
		return err
	}
	newFileUUID := uuid.New()
	newFileContents, _ := EncryptHmac(contentBytes, fileEncKey, fileHmacKey)
	userlib.DatastoreSet(newFileUUID, newFileContents)

	newFileMeta := FileMetadata{
		Filename:        filename,
		Owner:           userdata.Username,
		FileNodeEncKey:  fileEncKey,
		FileNodeHMACKey: fileHmacKey,
		Head:            newFileUUID,
		Tail:            newFileUUID,
		SharedWith:      make(map[string][]User),
		SharedBy:        make(map[string][]string),
	}
	metaEncKey, metaHmacKey, err := deriveKeys(userlib.RandomBytes(16))
	if err != nil {
		return err
	}
	metaBytes, err := json.Marshal(newFileMeta)
	if err != nil {
		return err
	}
	newMetaUUID := uuid.New()
	newMetaContents, _ := EncryptHmac(metaBytes, metaEncKey, metaHmacKey)
	userlib.DatastoreSet(newMetaUUID, newMetaContents)

	userdata.UserFiles[filename] = FileRef{
		MetaUUID:    newMetaUUID,
		MetaEncKey:  metaEncKey,
		MetaHMACKey: metaHmacKey,
		Shared:      false,
	}

	// persist UserFiles
	// userFilesUUID, err = uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "userfiles"))[:16])
	// if err != nil {
	// 	return err
	// }
	userFilesBytes, err = json.Marshal(userdata.UserFiles)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(userFilesUUID, userFilesBytes)
	// persist UserFiles

	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "user"))[:16])
	if err != nil {
		return err
	}
	userEncKey, userHmacKey, _ := deriveKeys(userdata.BaseKey)
	userBytes, _ := json.Marshal(userdata)
	updatedUserContents, _ := EncryptHmac(userBytes, userEncKey, userHmacKey)
	userlib.DatastoreSet(userUUID, updatedUserContents)

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	if len(filename) == 0 {
		return errors.New("invalid file name")
	}
	if content == nil {
		return errors.New("content must not be empty")
	}
	// check for persistence
	userFilesUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "userfiles"))[:16])
	if err != nil {
		return err
	}
	userFilesBytes, ok := userlib.DatastoreGet(userFilesUUID)
	if ok {
		err := json.Unmarshal(userFilesBytes, &userdata.UserFiles)
		if err != nil {
			return err
		}
	}
	// check for persistence

	// check if file exists
	metaRef, exists := userdata.UserFiles[filename]
	if !exists {
		return errors.New("file not found")
	}
	// retrieve the file
	metaBytes, ok := userlib.DatastoreGet(metaRef.MetaUUID)
	if !ok {
		return errors.New("error retrieving metadata")
	}
	metaPlaintext, _ := HmacDecrypt(metaBytes, metaRef.MetaEncKey, metaRef.MetaHMACKey)
	var oldMeta FileMetadata
	err = json.Unmarshal(metaPlaintext, &oldMeta)
	if err != nil {
		return errors.New("error unmarshaling metadata")
	}

	tailUUID := oldMeta.Tail
	tailDataBytes, ok := userlib.DatastoreGet(tailUUID)
	if !ok {
		return errors.New("error retrieving tail node")
	}
	tailPlaintext, _ := HmacDecrypt(tailDataBytes, oldMeta.FileNodeEncKey, oldMeta.FileNodeHMACKey)
	var currentLastFile FileNode
	err = json.Unmarshal(tailPlaintext, &currentLastFile)
	if err != nil {
		return err
	}

	AppendedFile := FileNode{
		Content: content,
		Next:    nil,
	}
	contentBytes, err := json.Marshal(AppendedFile)
	if err != nil {
		return err
	}
	appendedFileUUID := uuid.New()
	appendedFileContents, _ := EncryptHmac(contentBytes, oldMeta.FileNodeEncKey, oldMeta.FileNodeHMACKey)
	userlib.DatastoreSet(appendedFileUUID, appendedFileContents)

	// set the current tail node's Next to be the newly appended file
	currentLastFile.Next = &appendedFileUUID
	currentLastFileBytes, _ := json.Marshal(currentLastFile)
	fileContents, _ := EncryptHmac(currentLastFileBytes, oldMeta.FileNodeEncKey, oldMeta.FileNodeHMACKey)
	userlib.DatastoreSet(tailUUID, fileContents)

	// here we update the metadata's Tail to be the newly appended file
	oldMeta.Tail = appendedFileUUID
	newMetaTailBytes, _ := json.Marshal(oldMeta)
	metaContents, _ := EncryptHmac(newMetaTailBytes, metaRef.MetaEncKey, metaRef.MetaHMACKey)
	userlib.DatastoreSet(metaRef.MetaUUID, metaContents)

	// userlib.DatastoreSet(metaUUID, newMetaTailBytes)
	return nil

	//OFFICE HOURS: do we need to marshall encrupt and hmac here again???
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	if len(filename) == 0 {
		return nil, errors.New("invalid filename length")
	}
	// check for persistence
	userFilesUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "userfiles"))[:16])
	if err != nil {
		return nil, err
	}
	userFilesBytes, ok := userlib.DatastoreGet(userFilesUUID)
	if ok {
		var persistedUserFiles map[string]FileRef
		err = json.Unmarshal(userFilesBytes, &persistedUserFiles)
		if err != nil {
			return nil, err
		}
		userdata.UserFiles = persistedUserFiles
	}
	userlib.DebugMsg("User %s UserFiles UUID after reloading: %v", userdata.Username, userFilesUUID)

	metaRef, exists := userdata.UserFiles[filename]
	if !exists {
		return nil, errors.New("file does not exist")
	}
	metaBytes, ok := userlib.DatastoreGet(metaRef.MetaUUID)
	if !ok {
		return nil, errors.New("could not retrieve metadata")
	}
	metaPlaintext, _ := HmacDecrypt(metaBytes, metaRef.MetaEncKey, metaRef.MetaHMACKey)
	var metadata FileMetadata
	err = json.Unmarshal(metaPlaintext, &metadata)
	if err != nil {
		return nil, err
	}
	curr := metadata.Head
	for curr != uuid.Nil {
		fileNodeBytes, ok := userlib.DatastoreGet(curr)
		if !ok {
			return nil, errors.New("could not retrieve file node")
		}
		plaintext, _ := HmacDecrypt(fileNodeBytes, metadata.FileNodeEncKey, metadata.FileNodeHMACKey)
		var file FileNode
		err = json.Unmarshal(plaintext, &file)
		if err != nil {
			return nil, err
		}
		// userlib.DatastoreDelete(curr)
		// content = bytes.Join([][]byte{content, file.Content}, nil)
		content = append(content, file.Content...)
		if file.Next != nil {
			curr = *file.Next
		} else {
			break
		}
	}
	return content, err
}

// This function returns a UUID, which we’ll call an invitation Datastore pointer.
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	if len(filename) == 0 {
		return uuid.Nil, errors.New("invalid file name")
	}
	if len(recipientUsername) == 0 {
		return uuid.Nil, errors.New("invalid recipient username")
	}

	// check for persistence
	userFilesUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "userfiles"))[:16])
	if err != nil {
		return uuid.Nil, err
	}
	userFilesBytes, ok := userlib.DatastoreGet(userFilesUUID)
	if ok {
		// var persistedUserFiles map[string]FileRef
		err = json.Unmarshal(userFilesBytes, &userdata.UserFiles)
		if err != nil {
			return uuid.Nil, err
		}
		// userdata.UserFiles = persistedUserFiles
	}
	// check for persistence

	metaRef, exists := userdata.UserFiles[filename]
	if !exists {
		return uuid.Nil, errors.New("file not found")
	}
	recipientPubKey, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(recipientUsername + "public-key"))))
	if !ok {
		return uuid.Nil, errors.New("invalid recipient")
	}
	metaBytes, ok := userlib.DatastoreGet(metaRef.MetaUUID)
	if !ok {
		return uuid.Nil, errors.New("could not retrieve metadata")
	}
	// check integrity of metadata
	_, err = HmacDecrypt(metaBytes, metaRef.MetaEncKey, metaRef.MetaHMACKey)
	if err != nil {
		return uuid.Nil, errors.New("integrity check failed")
	}
	inv := Invitation{
		Sender:    userdata.Username,
		Recipient: recipientUsername,
		FileUUID:  metaRef,
		EncKey:    metaRef.MetaEncKey,
		HMACKey:   metaRef.MetaHMACKey,
		Shared:    true,
	}
	invBytes, err := json.Marshal(inv)
	if err != nil {
		return uuid.Nil, errors.New("failed to marshal invitation")
	}
	// invEncKey, invHmacKey, err := deriveKeys(userdata.BaseKey)
	invEncKey, invHmacKey, err := deriveKeys(userlib.RandomBytes(16))
	if err != nil {
		return uuid.Nil, err
	}
	// invCiphertext := userlib.SymEnc(invEncKey, userlib.RandomBytes(16), invBytes)
	// invHMAC, _ := userlib.HMACEval(invHmacKey, invCiphertext)
	invUUID := uuid.New()
	invContent, _ := EncryptHmac(invBytes, invEncKey, invHmacKey)
	userlib.DatastoreSet(invUUID, invContent)

	// reference to encrypted invitiation - can use invEncKey to encrypt/decrypt original invitaition, HMAC for integirty checking
	invRef := InvRef{
		InvUUID:    invUUID,
		InvEncKey:  invEncKey,
		InvHMACKey: invHmacKey,
	}
	invRefBytes, err := json.Marshal(invRef)
	if err != nil {
		return uuid.Nil, errors.New("failed to marshal invitation")
	}
	// encrypt with recipient public key
	// userlib.DebugMsg("\n %s's pk: %v", recipientUsername, recipientPubKey)

	invRefSymEnc := userlib.RandomBytes(16)
	iv := userlib.RandomBytes(16)
	invRefHybridCiphertext := userlib.SymEnc(invRefSymEnc, iv, invRefBytes)
	invRefCiphertext, err := userlib.PKEEnc(recipientPubKey, invRefSymEnc)
	// userlib.DebugMsg("marshaled inv: %v", invRefBytes)
	// userlib.DebugMsg("inv ref ciphertext: %v", invRefCiphertext)
	if err != nil {
		return uuid.Nil, errors.New("failed to encrypt invitation")
	}
	hybridEnc := append(invRefCiphertext, invRefHybridCiphertext...)
	// sign ciphertext with sender's sign key
	invRefSignature, err := userlib.DSSign(userdata.SignKey, hybridEnc)
	if err != nil {
		return uuid.Nil, errors.New("failed to create digital signature for invitation")
	}
	invRefContent := append(hybridEnc, invRefSignature...)
	invitationPtr = uuid.New()
	userlib.DatastoreSet(invitationPtr, invRefContent)
	return invitationPtr, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	if len(filename) == 0 {
		return errors.New("invalid filename")
	}
	if len(senderUsername) == 0 {
		return errors.New("invalid sender username")
	}
	_, ok := userdata.UserFiles[filename]
	if ok {
		return errors.New("file already in %s's file space" + userdata.Username)
	}
	invRefBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invalid invitation")
	}
	// const hmacLength = 64
	const rsaLength = 256
	const signatureLength = 256
	invRsaCipher := invRefBytes[:rsaLength]
	invAesCipher := invRefBytes[rsaLength : len(invRefBytes)-signatureLength]
	invSignature := invRefBytes[len(invRefBytes)-signatureLength:]
	// verify sender is valid
	senderVerKey, ok := userlib.KeystoreGet(string(userlib.Hash([]byte(senderUsername + "verify-key"))))
	if !ok {
		return errors.New("invalid sender")
	}
	// hybridDec := append(invRsaCipher, invAesCipher...)
	// err := userlib.DSVerify(senderVerKey, hybridDec, invSignature)
	// if err != nil {
	// 	return errors.New("invalid signature on invitiation")
	// }
	// invRefSymDec, err := userlib.PKEDec(userdata.PrivKey, invRsaCipher)
	// if err != nil {
	// 	return errors.New("unable to decrypt invitation")
	// }
	// decryptedInvRef := userlib.SymDec(invRefSymDec, invAesCipher)
	decryptedInvRef, _ := userdata.VerifyDecrypt(senderVerKey, invRsaCipher, invAesCipher, invSignature)
	var invRef InvRef
	err := json.Unmarshal(decryptedInvRef, &invRef)
	if err != nil {
		return errors.New("unable to unmarshal invitiation")
	}
	// userlib.DebugMsg("Invitiation UUID is: %v", invRef.InvUUID)

	invBytes, ok := userlib.DatastoreGet(invRef.InvUUID)
	if !ok {
		return errors.New("could not find invitation with a UUID of %s" + invRef.InvUUID.String())
	}
	decryptedInv, _ := HmacDecrypt(invBytes, invRef.InvEncKey, invRef.InvHMACKey)
	var inv Invitation
	err = json.Unmarshal(decryptedInv, &inv)
	if err != nil {
		return errors.New("unable to unmarshal invitiation")
	}

	// accepting invitiation -> get metadata, decrypt metadata to get file, add file to userfiles
	if inv.Sender != senderUsername {
		return errors.New("wrong sender")
	}
	if inv.Recipient != userdata.Username {
		return errors.New("wrong recipient")
	}

	userFilesUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "userfiles"))[:16])
	if err != nil {
		return err
	}
	userFilesBytes, ok := userlib.DatastoreGet(userFilesUUID)
	if ok {
		err = json.Unmarshal(userFilesBytes, &userdata.UserFiles)
		if err != nil {
			return err
		}
	}

	// add ref to file to recipient's UserFiles
	userdata.UserFiles[filename] = inv.FileUUID

	userFilesBytes, err = json.Marshal(userdata.UserFiles)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(userFilesUUID, userFilesBytes)

	metaBytes, ok := userlib.DatastoreGet(inv.FileUUID.MetaUUID)
	if !ok {
		return errors.New("invalid invitation")
	}
	metaPlaintext, _ := HmacDecrypt(metaBytes, inv.EncKey, inv.HMACKey)
	var metadata FileMetadata
	err = json.Unmarshal(metaPlaintext, &metadata)
	if err != nil {
		return errors.New("error unmarshaling metadata")
	}

	if metadata.SharedBy == nil {
		metadata.SharedBy = make(map[string][]string)
	}
	metadata.SharedBy[senderUsername] = append(metadata.SharedBy[senderUsername], userdata.Username) //To Do DO WE NEED ...s HERE
	// SharedBy represents who shared the current file with whom - key = sharee, value = sharer (not necessarily owner)

	if metadata.SharedWith == nil {
		metadata.SharedWith = make(map[string][]User)
	}
	metadata.SharedWith[senderUsername] = append(metadata.SharedWith[senderUsername], *userdata)

	// reencrypt metadata
	updatedMetadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	updatedMetadataContents, _ := EncryptHmac(updatedMetadataBytes, inv.EncKey, inv.HMACKey)
	userlib.DatastoreSet(inv.FileUUID.MetaUUID, updatedMetadataContents)

	// delete invitation
	userlib.DatastoreDelete(invRef.InvUUID)
	return err
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	if len(filename) == 0 {
		return errors.New("invalid filename")
	}
	if len(recipientUsername) == 0 {
		return errors.New("invalid recipient username")
	}
	// check for persistence
	userFilesUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "userfiles"))[:16])
	if err != nil {
		return err
	}
	userFilesBytes, ok := userlib.DatastoreGet(userFilesUUID)
	if ok {
		err := json.Unmarshal(userFilesBytes, &userdata.UserFiles)
		if err != nil {
			return err
		}
	}
	// check for persistence

	metaRef, exists := userdata.UserFiles[filename]
	if !exists {
		return errors.New("user does not have access to this file anyway")
	}

	metaBytes, ok := userlib.DatastoreGet(metaRef.MetaUUID)
	if !ok {
		return errors.New("unable to extract metadata")
	}

	metaPlaintext, _ := HmacDecrypt(metaBytes, metaRef.MetaEncKey, metaRef.MetaHMACKey)
	var metadata FileMetadata
	err = json.Unmarshal(metaPlaintext, &metadata)
	if err != nil {
		return err
	}

	if metadata.Owner != userdata.Username { //person who revokes access must be the owner
		return errors.New("only owner of file can modify access priviledges")
	}

	wasShared := false
	var updatedList []User
	for _, user := range metadata.SharedWith[userdata.Username] {
		if user.Username == recipientUsername {
			wasShared = true
			continue
		}
		updatedList = append(updatedList, user)
	}
	if !wasShared {
		return errors.New("file was never shared with %s" + recipientUsername)
	}
	metadata.SharedWith[userdata.Username] = updatedList

	// DFS-based approach to revoking users that were given access permissions by revokedUser
	revoked := make(map[string]bool) //username : boolean of whether they've been revoked or not
	var removeSharedUsers func(user string)
	removeSharedUsers = func(user string) {
		// check if revokedUser has shared file with anyone else
		if revoked[user] {
			return
		}
		revoked[user] = true                             // mark user as revoked
		sharedUsers, exists := metadata.SharedWith[user] //a list of users (user structs) sharedUsers has shared with
		if !exists {
			return
		}
		for _, user := range sharedUsers {
			removeSharedUsers(user.Username)
		}
	}
	removeSharedUsers(recipientUsername)

	for user := range revoked {
		// MISSING: remove file from UserFile map so that they can't access it using an alias (bobFile)
		revokedUserFileUUID, _ := uuid.FromBytes(userlib.Hash([]byte(user + "userfiles"))[:16])
		// userlib.DebugMsg("User %s UserFiles UUID: %v", user, revokedUserFileUUID)
		revokedUserFileBytes, exists := userlib.DatastoreGet(revokedUserFileUUID)
		if exists {
			var revokedUserFiles map[string]FileRef
			_ = json.Unmarshal(revokedUserFileBytes, &revokedUserFiles)
			// userlib.DebugMsg("Revoked user files for %s: %+v", user, revokedUserFiles)
			for fileName, ref := range revokedUserFiles {
				if ref.MetaUUID == metaRef.MetaUUID { // files with different aliases stil have same metadata UUIDs
					delete(revokedUserFiles, fileName)
				}
			}
			// userlib.DebugMsg("Revoked user files for %s: %+v", user, revokedUserFiles)
			updatedRevokedUserFiles, _ := json.Marshal(revokedUserFiles)
			userlib.DatastoreSet(revokedUserFileUUID, updatedRevokedUserFiles)
		}
		delete(metadata.SharedWith, user)
		delete(metadata.SharedBy, user)
	}

	curr := metadata.Head
	newHead := uuid.Nil
	newTail := uuid.Nil
	var prevUUID *uuid.UUID
	// var fileNodes []uuid.UUID
	// var contents [][]byte

	// IDEA: iterate through file node chain, decrypt, update file sharing permissions, reencrypt with new keys, store under new UUIDs
	newFileEncKey, newFileHMACKey, err := deriveKeys(userlib.RandomBytes(16))
	if err != nil {
		return err
	}
	for curr != uuid.Nil {
		// 1. Decrypt file node
		fileNodeBytes, ok := userlib.DatastoreGet(curr)
		if !ok {
			return errors.New("unable to retrieve file node")
		}
		fileNodePlaintext, _ := HmacDecrypt(fileNodeBytes, metadata.FileNodeEncKey, metadata.FileNodeHMACKey)
		var fileNode FileNode
		err = json.Unmarshal(fileNodePlaintext, &fileNode)
		if err != nil {
			return errors.New("unable to unmarshal plaintext")
		}
		// do some stuff here
		newFileUUID := uuid.New()
		if prevUUID != nil {
			prevNodeBytes, _ := userlib.DatastoreGet(*prevUUID)                // retrieve previous node
			prevNodeCipher := GetCiphertext(prevNodeBytes)                     // recover ciphertext of previous node
			prevNodePlaintext := userlib.SymDec(newFileEncKey, prevNodeCipher) // recover hmac of previous node

			var prevNode FileNode
			json.Unmarshal(prevNodePlaintext, &prevNode) // unmarshal previous node
			prevNode.Next = &newFileUUID                 // update previous node's next pointer to be the newly generated UUID
			updatedPrevNode, _ := json.Marshal(prevNode)
			updatedPrevNodeContents, _ := EncryptHmac(updatedPrevNode, newFileEncKey, newFileHMACKey)
			userlib.DatastoreSet(*prevUUID, updatedPrevNodeContents)
		}
		contentBytes, _ := json.Marshal(fileNode)
		newFileContents, _ := EncryptHmac(contentBytes, newFileEncKey, newFileHMACKey)
		userlib.DatastoreSet(newFileUUID, newFileContents)
		// update file pointers
		if newHead == uuid.Nil {
			newHead = newFileUUID
		}
		newTail = newFileUUID
		prevUUID = &newFileUUID
		if fileNode.Next != nil {
			curr = *fileNode.Next
		} else {
			break
		}
	}
	// create new UUID/keys
	metadata.FileNodeEncKey = newFileEncKey
	metadata.FileNodeHMACKey = newFileHMACKey
	metadata.Head = newHead
	metadata.Tail = newTail

	newMetaEncKey, newMetaHmacKey, _ := deriveKeys(userlib.RandomBytes(16))
	metaBytes, err = json.Marshal(metadata)
	if err != nil {
		return err
	}
	newMetaUUID := uuid.New()
	newMetaContents, _ := EncryptHmac(metaBytes, newMetaEncKey, newMetaHmacKey)
	userlib.DatastoreSet(newMetaUUID, newMetaContents)

	userdata.UserFiles[filename] = FileRef{
		MetaUUID:    newMetaUUID,
		MetaEncKey:  newMetaEncKey,
		MetaHMACKey: newMetaHmacKey,
		Shared:      false,
	}
	// persist UserFiles
	userFilesBytes, err = json.Marshal(userdata.UserFiles)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(userFilesUUID, userFilesBytes)
	// persist UserFiles

	//communicate with all NON REVOKED USERS; nonRevokedUser is a string name; this is how Golang does for each loop??
	for _, nonRevokedUsers := range metadata.SharedWith { // loop over values of map (a bunch of lists of user structs)
		// distribute new keys to non-revoked users; update their UserFiles directly?
		for _, user := range nonRevokedUsers { // loop over each list of user structs
			NRUUID, _ := uuid.FromBytes(userlib.Hash([]byte(user.Username + "userfiles"))[:16])
			NRUserFileBytes, _ := userlib.DatastoreGet(NRUUID)
			var NRUserFiles map[string]FileRef
			_ = json.Unmarshal(NRUserFileBytes, &NRUserFiles)
			NRUserFiles[filename] = FileRef{
				MetaUUID:    newMetaUUID,
				MetaEncKey:  newMetaEncKey,
				MetaHMACKey: newMetaHmacKey,
				Shared:      true,
			}
			updatedNRUserFiles, _ := json.Marshal(NRUserFiles)
			userlib.DatastoreSet(NRUUID, updatedNRUserFiles)
		}
	}
	return err
}
