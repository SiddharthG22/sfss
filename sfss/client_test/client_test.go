package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	"fmt"
	_ "strconv"
	_ "strings"
	"testing"

	//"github.com/google/uuid"
	_ "github.com/google/uuid"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"               //left unchanged
const emptyString = ""                           //left unchanged
const contentOne = "Bitcoin is Nick's favorite " //left unchanged
const contentTwo = "digital "                    //left unchanged
const contentThree = "cryptocurrency!"           //left unchanged
const anotherPassword = "anotherPassword"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	//var eve *client.User
	//var frank *client.User
	//var grace *client.User
	//var horace *client.User
	//var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User
	//ToDo: add more client users here if you need

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	//eveFile := "eveFile.txt"
	//frankFile := "frankFile.txt"
	//graceFile := "graceFile.txt"
	//horaceFile := "horaceFile.txt"
	//iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Revoke Test", func() {
			alice, _ := client.InitUser("alice", defaultPassword)
			bob, _ := client.InitUser("bob", defaultPassword)
			charlie, _ := client.InitUser("charlie", defaultPassword)
			doris, _ := client.InitUser("doris", defaultPassword)

			err := alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			invID, err := alice.CreateInvitation(aliceFile, bob.Username)
			Expect(err).To(BeNil())

			invID1, err := alice.CreateInvitation(aliceFile, doris.Username)
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation(alice.Username, invID, bobFile) //doris renames the file to be dorisFile
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation(alice.Username, invID1, dorisFile) //doris renames the file to be dorisFile
			Expect(err).To(BeNil())

			newInvID, err := bob.CreateInvitation(bobFile, charlie.Username)
			Expect(err).To(BeNil())

			err = charlie.AcceptInvitation(bob.Username, newInvID, charlesFile) //doris renames the file to be dorisFile
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, bob.Username)
			Expect(err).To(BeNil())

			_, err = bob.LoadFile(bobFile) // after Bob's access gets revoked, he shouldn't be able to access the file through an alias
			Expect(err).ToNot(BeNil())

			_, err = charlie.LoadFile(charlesFile) // ditto
			Expect(err).ToNot(BeNil())

			_, err = doris.LoadFile(dorisFile) // since we didn't revoke doris, she should still have access
			Expect(err).To(BeNil())

		})

		Specify("Basic Init, Get, Store, and Invite test", func() {
			aliceDesktop, _ := client.InitUser("alice", defaultPassword)
			bob, _ := client.InitUser("bob", anotherPassword)
			aliceLaptop, _ := client.GetUser("alice", defaultPassword)

			err := aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			invID, err := aliceLaptop.CreateInvitation(aliceFile, bob.Username)
			Expect(err).To(BeNil())
			fmt.Println("Result of creating invitation: ", invID, err)

			err = bob.AcceptInvitation(aliceLaptop.Username, invID, bobFile)
			Expect(err).To(BeNil())

			file, err := bob.LoadFile(bobFile)
			fmt.Println("Result of loading file: ", file, err)
			Expect(err).To(BeNil())

			// err = aliceLaptop.AppendToFile(aliceFile, []byte("some more stuff"))
			// Expect(err).To(BeNil())

			err = aliceLaptop.AppendToFile(aliceFile, []byte("some more stuff"))
			Expect(err).To(BeNil())

			file, err = bob.LoadFile(bobFile)
			fmt.Println("Result of appending to and loading file: ", file, err)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	//To Do: Write all of our own tests below this line!

	//Source: I referenced this blog as I wrote some of the test cases: https://medium.com/@dees3g/testing-with-ginkgo-and-gomega-1f1ecc8407a8

	//tests about the InitUser function
	Describe("InitUser Tests", func() {

		Specify("InitUser for a new user", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			//checking that the InitUser call didn't return an error
			Expect(err).To(BeNil())
		})

		// Source: using := instead of = because := allows for declaration and assignment in the same line
		// using just = was giving me errors when I was trying to put err1 and err2 inside the Expect() function

		Specify("InitUser for a new user, case sensitive username", func() {
			userlib.DebugMsg("Initializing two users w/ same username but case sensitive")
			_, err1 := client.InitUser("alice", defaultPassword)
			_, err2 := client.InitUser("ALICE", defaultPassword)
			Expect(err1).To(BeNil())
			Expect(err2).To(BeNil())

		})

		Specify("InitUser for a new user, no username", func() {
			userlib.DebugMsg("Initializing a new user with no username")
			_, err := client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("InitUser for a new user, no password", func() {
			userlib.DebugMsg("Initializing a new user but with no password")
			_, err := client.InitUser("alice", "")
			Expect(err).ToNot(BeNil())
		})

		Specify("InitUser for a new user, same exact username", func() {
			userlib.DebugMsg("Initializing 2 new users with the exact same username but trying to initialize as 2 new users")
			_, err1 := client.InitUser("alice", defaultPassword)
			Expect(err1).To(BeNil())
			_, err2 := client.InitUser("alice", defaultPassword)
			Expect(err2).ToNot(BeNil())
		})
	})

	// GetUser tests

	Describe("GetUser Tests", func() {

		//non-existent user
		Specify("GetUser for a non-existent user", func() {
			userlib.DebugMsg("GetUser for a non-existent user")
			_, err = client.GetUser("IDontExistLOL", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		//existing user with a correct password
		Specify("GetUser for existing user w/ a correct password", func() {
			userlib.DebugMsg("Initializing a new, random user")
			alice, err = client.InitUser("alice", defaultPassword)
			//checking that the InitUser call didn't return an error
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting Alice")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		//existing user with an incorrect password
		Specify("GetUser for an existing user w/ an incorrect password", func() {
			userlib.DebugMsg("Initializing a new, random user")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("GetUser Alice w/ the wrong password")
			_, err = client.GetUser("alice", "blahblahblah")
			Expect(err).ToNot(BeNil())

		})

		//GetUser w/ case sensitive username
		Specify("GetUser with a case sensitive username", func() {
			userlib.DebugMsg("Make a new, random user")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Try using uppercase ALICE to try to get into alice")
			_, err = client.GetUser("ALICE", defaultPassword)
			//expect an error because alice != ALICE even w/ the correct password
			Expect(err).ToNot(BeNil())
		})
	})

	//To Do: add the rest of Get User tests below (empty password OR empty username later onwards)

	//Simulate an attack to pass the integrity test checkpoint

	Describe("Integrity Test", func() {

		//first attempt at an integrity test

		// Specify("Integrity test for modifying file data w/o requesting authentication", func() {
		// 	userlib.DebugMsg("creating Alice")
		// 	alice, err = client.InitUser("alice", defaultPassword)
		// 	//don't expect an error
		// 	Expect(err).To(BeNil())

		// 	// userlib.DebugMsg("retrieving Alice's data")
		// 	// aliceLaptop, err := client.GetUser("alice", defaultPassword)
		// 	// //don't expect an error
		// 	// Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Storing a file with content one array")
		// 	//create a new file called file.txt associated with
		// 	err = alice.StoreFile(aliceFile, []byte(contentOne))
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("Deriving file UUID")
		// 	hashVal := userlib.Hash([]byte(aliceFile + alice.Username))[:16]
		// 	fileUUID, err := uuid.FromBytes(hashVal)
		// 	Expect(err).To(BeNil())
		// 	// fileUUID := userlib.Hash([]byte(alice.Username + aliceFile))[:16]

		// 	userlib.DebugMsg("Tampering with ciphertext in Datastore")
		// 	userData, ok := userlib.DatastoreGet(fileUUID)
		// 	Expect(ok).To(BeTrue())
		// 	Expect(len(userData)).To(BeNumerically(">", 0))

		// 	userData[0] ^= 0xFF // just tampering with bit
		// 	userlib.DatastoreSet(fileUUID, userData)

		// 	userlib.DebugMsg("Trying to load file after tampering")
		// 	_, err = alice.LoadFile(aliceFile)
		// 	Expect(err).ToNot(BeNil()) // should fail HMAC and decryption
		// })

		//this integrity test didn't pass the checkpoint, but we'll keep it here because we put effort into it
		//Source: I went to OH and got help from a TA to help pass this checkpoint because it just wasn't passing for us

		/*
			Specify("Integrity test for tampering with User Struct", func() {
				userlib.DebugMsg("creating Alice")
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Tampering with ciphertext in Datastore")
				//userUUID := userlib.Hash([]byte("alice"))
				//userUUIDFromBytes, err := uuid.FromBytes(userUUID[:16])
				//Expect(err).To(BeNil())
				//userData, ok := userlib.DatastoreGet(userUUIDFromBytes)
				//Expect(ok).To(BeTrue())

				for k := range userlib.DatastoreGetMap() {

					userlib.DatastoreSet(k, userlib.RandomBytes(16))
				}

				userlib.DebugMsg("Trying to get user after tampering")
				_, err = client.GetUser("alice", defaultPassword)
				// We expect an error now
				Expect(err).ToNot(BeNil())
			})
		*/

		//second attempt at an integrity test

		Specify("Integrity test for modifying file data w/o requesting authentication", func() {
			userlib.DebugMsg("creating Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			//don't expect an error
			Expect(err).To(BeNil())

			userlib.DebugMsg("retrieving Alice's data")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			//don't expect an error
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing a file with content one array")
			//create a new file called file.txt associated with
			err = aliceLaptop.StoreFile("file.txt", []byte(contentOne))
			Expect(err).To(BeNil())

			//append to the file in a separate call
			err = aliceLaptop.AppendToFile("file.txt", []byte(contentTwo))
			//don't expect an error
			Expect(err).To(BeNil())

			//load the file
			data, err := aliceLaptop.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("initiating attack on Alice by modifying file w/o any authentication")
			// Try to store a file with invalid authentication
			err = aliceLaptop.StoreFile("file.txt", []byte("HEHEATTACK"))
			Expect(err).ToNot(BeNil()) //we expect an error???

			userlib.DebugMsg("now loading Alice's file")
			_, err = aliceLaptop.LoadFile("test.txt")
			Expect(err).ToNot(BeNil())
		})

		//third attempt at an integrity test

		// Specify("Integrity test for HMAC", func() {
		// 	userlib.DebugMsg("creating Alice")
		// 	alice, err = client.InitUser("alice", defaultPassword)
		// 	//don't expect an error
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("retrieving Alice's UUID")
		// 	aliceUUID, err := uuid.FromBytes(userlib.Hash([]byte("alice"))[:16])
		// 	//don't expect an error
		// 	Expect(err).To(BeNil())

		// 	userlib.DebugMsg("tampering with Alice's data without Alice knowing!")
		// 	user, err := userlib.DatastoreGet(aliceUUID)
		// 	Expect(err).To(BeNil())

		// 	// user[16] ^= user[16]
		// 	// userlib.DatastoreSet(aliceUUID, user)

		// 	_, err = client.GetUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())

		// })

	})

	//To Do: write StoreFile tests

	Describe("StoreFile Tests", func() {
		/*
			Specify("Integrity test for modifying file data w/o requesting authentication", func() {

			})
		*/

	})

	// To Do: Write AppendToFile tests
	Describe("AppendToFile Tests", func() {
		/*
			Specify("Integrity test for modifying file data w/o requesting authentication", func() {

			})
		*/

	})

	// To Do: Write AppendToFile tests
	Describe("LoadFile Tests", func() {
		/*
			Specify("Integrity test for modifying file data w/o requesting authentication", func() {

			})
		*/

	})

	// To Do: Write AppendToFile tests
	Describe("CreateInvitation Tests", func() {
		/*
			Specify("Integrity test for modifying file data w/o requesting authentication", func() {

			})
		*/

	})

	// To Do: Write AppendToFile tests
	Describe("AcceptInvitation Tests", func() {

		/*
			Returns an error if:

			The user already has a file with the chosen filename in their personal file namespace.
			Something about the invitationPtr is wrong (e.g. the value at that UUID on Datastore is corrupt or missing, or the user cannot verify that invitationPtr was provided by senderUsername).
			The invitation is no longer valid due to revocation.

		*/

		Specify("Accepting the Invitation Basic", func() {
			alice, _ := client.InitUser("alice", defaultPassword)
			bob, _ := client.InitUser("bob", defaultPassword)

			err := alice.StoreFile(aliceFile, []byte(contentOne)) //Alice
			Expect(err).To(BeNil())

			invID, err := alice.CreateInvitation(aliceFile, bob.Username)
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation(alice.Username, invID, bobFile) //doris renames the file to be dorisFile
			Expect(err).To(BeNil())

		})

		//The user already has a file with the chosen filename in their personal file namespace.
		Specify("The user already has a file with the chosen filename in their personal file namespace.", func() {
			alice, _ := client.InitUser("alice", defaultPassword)
			bob, _ := client.InitUser("bob", defaultPassword)
			doris, _ := client.InitUser("doris", defaultPassword)

			err := alice.StoreFile(aliceFile, []byte(contentOne)) //Alice
			Expect(err).To(BeNil())

			err = doris.StoreFile(dorisFile, []byte(contentOne)) //Alice
			Expect(err).To(BeNil())

			anothainvID, err := doris.CreateInvitation(dorisFile, bob.Username)
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation(doris.Username, anothainvID, bobFile) //doris renames the file to be dorisFile
			Expect(err).To(BeNil())

			invID, err := alice.CreateInvitation(aliceFile, bob.Username)
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation(alice.Username, invID, bobFile) //bob already has a file named bobFile so it should error when he tries accepting another file with same name
			Expect(err).ToNot(BeNil())

		})

		Specify("Accepting the Invitation For Someone Not Invited By Alice But Invited by Bob", func() {
			alice, _ := client.InitUser("alice", defaultPassword)
			bob, _ := client.InitUser("bob", defaultPassword)
			charlie, _ := client.InitUser("charlie", defaultPassword)

			err := alice.StoreFile(aliceFile, []byte(contentOne)) //Alice
			Expect(err).To(BeNil())

			invID, err := alice.CreateInvitation(aliceFile, bob.Username)
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation(alice.Username, invID, bobFile) //doris renames the file to be dorisFile
			Expect(err).To(BeNil())

			newInvID, err := bob.CreateInvitation(aliceFile, charlie.Username)
			Expect(err).ToNot(BeNil())

			err = charlie.AcceptInvitation(alice.Username, newInvID, aliceFile) //doris renames the file to be dorisFile
			Expect(err).ToNot(BeNil())

			err = charlie.AcceptInvitation(bob.Username, invID, bobFile) //doris renames the file to be dorisFile
			Expect(err).ToNot(BeNil())

		})

	})

	/* FSpecify("Basic Revoke Test", func() {
		alice, _ := client.InitUser("alice", defaultPassword)
		bob, _ := client.InitUser("bob", defaultPassword)
		charlie, _ := client.InitUser("charlie", defaultPassword)
		// doris, _ := client.InitUser("doris", defaultPassword)

		err := alice.StoreFile(aliceFile, []byte(contentOne))
		Expect(err).To(BeNil())

		invID, err := alice.CreateInvitation(aliceFile, bob.Username)
		Expect(err).To(BeNil())

		err = bob.AcceptInvitation(alice.Username, invID, bobFile) //doris renames the file to be dorisFile
		Expect(err).To(BeNil())

		newInvID, err := bob.CreateInvitation(bobFile, charlie.Username)
		Expect(err).To(BeNil())

		err = charlie.AcceptInvitation(bob.Username, newInvID, charlesFile) //doris renames the file to be dorisFile
		Expect(err).To(BeNil())

		err = alice.RevokeAccess(aliceFile, bob.Username)
		Expect(err).To(BeNil())

		_, err = bob.LoadFile(aliceFile)
		Expect(err).ToNot(BeNil())

		_, err = bob.LoadFile(bobFile) // after Bob's access gets revoked, he shouldn't be able to access the file through an alias
		Expect(err).ToNot(BeNil())

		// _, err = charlie.LoadFile(charlesFile)
		// Expect(err).ToNot(BeNil())

	})
	*/

	// To Do: Write RevokeAccess tests

	//Return an error if the invitation is no longer valid due to revocation.
	Describe("RevokeAccess Tests", func() {

		Specify("RevokeAccess and See If Someone With Revoked Access Will Still Accept Invitation", func() {
			alice, _ := client.InitUser("alice", defaultPassword)
			bob, _ := client.InitUser("bob", defaultPassword)
			// charlie, _ := client.InitUser("charlie", defaultPassword)

			err := alice.StoreFile(aliceFile, []byte(contentOne)) //Alice. makes file
			Expect(err).To(BeNil())

			invID, err := alice.CreateInvitation(aliceFile, bob.Username) //alice makes invitation to file for Bob
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, bob.Username) //alive revokes access to the file for Bob
			Expect(err).ToNot(BeNil())

			err = bob.AcceptInvitation(alice.Username, invID, bobFile) //bob tries accepting invitation
			Expect(err).To(BeNil())

		})

		//The given filename does not exist in the caller’s personal file namespace.

		Specify("The given filename does not exist in the caller’s personal file namespace.", func() {
			alice, _ := client.InitUser("alice", defaultPassword)
			bob, _ := client.InitUser("bob", defaultPassword)
			// charlie, _ := client.InitUser("charlie", defaultPassword)

			err := alice.StoreFile(aliceFile, []byte(contentOne)) //Alice. makes file
			Expect(err).To(BeNil())

			invID, err := alice.CreateInvitation(aliceFile, bob.Username) //alice makes invitation to file for Bob
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation(alice.Username, invID, bobFile) //bob tries accepting invitation
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(charlesFile, bob.Username) //alive revokes access to the file for Bob
			Expect(err).ToNot(BeNil())

		})

		//The given filename is not currently shared with recipientUsername.

		Specify("The given filename is not currently shared with recipientUsername.", func() {
			alice, _ := client.InitUser("alice", defaultPassword)
			bob, _ := client.InitUser("bob", defaultPassword)
			// charles, _ := client.InitUser("charles", defaultPassword)

			err := alice.StoreFile(aliceFile, []byte(contentOne)) //Alice. makes file
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, bob.Username) //Alice revokes Bob's access to her file that he didn't even have access to in the first place
			Expect(err).ToNot(BeNil())
		})

		//Revocation cannot be completed due to malicious action
		Specify("Revocation cannot be completed due to malicious action", func() {
			alice, _ := client.InitUser("alice", defaultPassword)
			bob, _ := client.InitUser("bob", defaultPassword)
			charlie, _ := client.InitUser("charlie", defaultPassword)

			err := alice.StoreFile(aliceFile, []byte(contentOne)) //Alice. makes file
			Expect(err).To(BeNil())

			invID, err := alice.CreateInvitation(aliceFile, bob.Username) //alice makes invitation to file for Bob
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation(alice.Username, invID, aliceFile) //bob tries accepting invitation
			Expect(err).To(BeNil())

			invID, err = bob.CreateInvitation(aliceFile, charlie.Username) //alice makes invitation to file for Bob
			Expect(err).To(BeNil())

			err = charlie.AcceptInvitation(bob.Username, invID, aliceFile) //bob tries accepting invitation
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, bob.Username) //Alice revokes Bob's access to her file that he didn't even have access to in the first place
			Expect(err).To(BeNil())

			_, err = charlie.LoadFile(aliceFile) //charles should have lost access as well when alice revoked access
			Expect(err).ToNot(BeNil())

		})

	})

	/*
		Returns an error if:

		The given filename does not exist in the caller’s personal file namespace.
		The given filename is not currently shared with recipientUsername.
		Revocation cannot be completed due to malicious action.

	*/

})
