package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"log"
	"os"
	// "io"
	"io/ioutil"
	"strings"
	"errors"
	// "flag"
	"strconv"
	"time"
	"crypto/sha256"

)

// IdentityData holds identity data for ssb
type IdentityData struct {
	Curve      string `json:"curve"`
	Public     string `json:"public"`
	Private    string `json:"private"`
	ID         string `json:"id"`
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// SignedMessage is a signed message
type SignedMessage struct {
	Previous  json.RawMessage `json:"previous"`
	Author    string          `json:"author"`
	Sequence  int             `json:"sequence"`
	Timestamp int64           `json:"timestamp"`
	Hash      string          `json:"hash"`
	Content   json.RawMessage `json:"content"`
	Signature string          `json:"signature"`
	// Validated bool
}

// Message is a signed message
type Message struct {
	// Previous  string          `json:"previous"`
	Previous  json.RawMessage `json:"previous"`
	Author    string          `json:"author"`
	Sequence  int             `json:"sequence"`
	Timestamp int64           `json:"timestamp"`
	Hash      string          `json:"hash"`
	Content   json.RawMessage `json:"content"`
}

// Post is a post
type Post struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

var (
	message   string
	localFeed string
	localID   IdentityData
)

func main() {

	configCheck("./data")
	message = os.Args[1]

	if message != "" {

		fmt.Printf("Writing message: %s\n", message)
		writeMessage(message)

	}

}

func writeMessage(message string) {
	seq := 0
	files, err := ioutil.ReadDir(localFeed)
	check(err, "error reading feed directory: "+localFeed)
	for _, file := range files {
		if strings.Contains(file.Name(), ".json") {
			seq++
		}
	}
	prev := seq
	seq++
	previousID := []byte("null")
	if prev > 0 {
		previousID, err = getMessageID(localFeed + "/" + strconv.Itoa(prev) + ".json")
    	check(err, "error getting message id: "+localFeed + "/" + strconv.Itoa(prev) + ".json")
	}
	filename := localFeed + "/" + strconv.Itoa(seq) + ".json"
	post := Post{
		Type: "post",
		Text: message,
	}
	content, err := json.MarshalIndent(post, "", "  ")
	new := Message{
		Previous:  previousID,
		Author:    localID.ID,
		Sequence:  seq,
		Timestamp: time.Now().UnixNano() / 1000000,
		Hash:      "sha256",
		Content:   content,
	}

	msg, err := json.MarshalIndent(new, "", "  ")
	check(err, "error indenting json")

	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(localID.PrivateKey, msg)) + ".sig.ed25519"

	signedMessage := SignedMessage{
		Previous:  new.Previous,
		Author:    new.Author,
		Sequence:  new.Sequence,
		Timestamp: new.Timestamp,
		Hash:      new.Hash,
		Content:   content,
		Signature: signature,
	}

	signedMsg, err := json.MarshalIndent(signedMessage, "", "  ")
	check(err, "error indenting json")
	// fmt.Printf("DEBUG: Signed message: %v\n", string(signedMsg))

	err = ioutil.WriteFile(filename, signedMsg, 0644)
	check(err, "error writing to feed: "+filename)

}

func getMessageID(path string) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		check(err, "Message not found: "+path)
	} else if _, err := os.Stat(path); err == nil {
		msg, err := ioutil.ReadFile(path)
	    check(err, "reading file: "+path)
		hash := sha256.Sum256(msg)
		msgID := "%" + base64.StdEncoding.EncodeToString(hash[:]) + ".sha256"
		// fmt.Printf("DEBUG: MessageID: %v\n", msgID)
		return []byte(msgID), nil
	} else {
		check(errors.New("error reading file"), "getMessageID, path: "+path)
	}
	return []byte(""), errors.New("error reading file")
}

func configCheck(configDir string) {
	feedDir := configDir + "/feed"
	if _, err := os.Stat(feedDir); os.IsNotExist(err) {
		err = os.MkdirAll(feedDir, os.ModePerm)
		check(err, "configCheck: making directory: "+feedDir)
	}
	identity := loadIdentity(configDir + "/identity.json")
	// idFeed := b64f(strings.Split(identity.Public, ".")[0])
	idFeed := b64f(identity.Public)
	if _, err := os.Stat(feedDir + "/" + idFeed); os.IsNotExist(err) {
		err = os.MkdirAll(feedDir+"/"+idFeed, os.ModePerm)
		check(err, "configCheck: making directory: "+feedDir+"/"+idFeed)
	}
	localFeed = feedDir + "/" + idFeed
}

func loadIdentity(filename string) IdentityData {

	identity := IdentityData{}

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		fmt.Printf("Identity file does not exist, generating a new one: %s\n", filename)
		// fmt.Println("Keep this file safe, and do not share the private key.")
		ed25519PublicKey, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
		check(err, "error generating ed25519 pair")

		identity.PrivateKey = ed25519PrivateKey
		identity.PublicKey = ed25519PublicKey
		identity.Curve = "ed25519"
		identity.Public = base64.StdEncoding.EncodeToString(ed25519PublicKey[:]) + ".ed25519"
		identity.Private = base64.StdEncoding.EncodeToString(ed25519PrivateKey[:]) + ".ed25519"
		identity.ID = "@" + identity.Public
		fmt.Printf("Your new Public Identity: %s\n", identity.ID)

		data, err := json.MarshalIndent(identity, "", "  ")
		check(err, "error indenting json")
		err = ioutil.WriteFile(filename, data, 0644)
		check(err, "error writing identity file: "+filename)

	} else if _, err := os.Stat(filename); err == nil {
		// fmt.Printf("Loading identity file: %s\n", filename)
		file, err := os.Open(filename)
		check(err, "error opening identity file: "+filename)
		defer file.Close()

		err = json.NewDecoder(file).Decode(&identity)
		check(err, "error decoding identity file: "+filename)
		fmt.Printf("Found identity: %s\n", identity.ID)
		identity.PrivateKey, err = base64.StdEncoding.DecodeString(strings.Split(identity.Private, ".")[0])
		check(err, "error decoding identity private key: "+filename)
		identity.PublicKey, err = base64.StdEncoding.DecodeString(strings.Split(identity.Public, ".")[0])
		check(err, "error decoding identity public key: "+filename)
	}
	localID = identity
	return identity
}

func b64f(s string) string {
	// https://tools.ietf.org/html/rfc3548#page-6
	if strings.Contains(s, "/") || strings.Contains(s, "+") {
		return strings.NewReplacer(
			"/", "_",
			"+", "-",
		).Replace(s)
	} else if strings.Contains(s, "_") || strings.Contains(s, "-") {
		return strings.NewReplacer(
			"_", "/",
			"-", "+",
		).Replace(s)
	} else {
		// fmt.Printf("Warning: base64 decode fault: %s" + s)
		return s
	}
}

// check .
func check(err error, msg string) {
	if err != nil {
		log.Panicf(msg+` : Error : 
###
%v
###
`, err)
	}
}
