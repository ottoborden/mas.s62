// Problem set 01: Hash based signatures.

// A lot of this lab is set up and templated for you to get used to
// what may be an unfamiliar language (Go).  Go is syntactically
// similar to C / C++ in many ways, including comments.

// In this pset, you need to build a hash based signature system.  We'll use sha256
// as our hash function, and Lamport's simple signature design.

// Currently this compiles but doesn't do much.  You need to implement parts which
// say "your code here".  It also could be useful to make your own functions or
// methods on existing structs, espectially in the forge.go file.

// If you run `go test` and everything passes, you're all set.

// There's probably some way to get it to pass the tests without making an actual
// functioning signature scheme, but I think that would be harder than just doing
// it the right way :)

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

func main() {

	// Define your message
	textString := "1"
	fmt.Printf("%s\n", textString)

	// convert message into a block
	m := GetMessageFromString(textString)
	fmt.Printf("%x\n", m[:])

	// generate keys
	sec, pub, err := GenerateKey()
	if err != nil {
		panic(err)
	}

	// print pubkey.
	fmt.Printf("pub:\n%s\n", pub.ToHex())

	// sign message
	sig1 := Sign(m, sec)
	fmt.Printf("sig1:\n%s\n", sig1.ToHex())

	// verify signature
	worked := Verify(m, pub, sig1)

	// done
	fmt.Printf("Verify worked? %v\n", worked)

	// Forge signature
	msgString, sig, err := Forge()
	if err != nil {
		panic(err)
	}

	fmt.Printf("forged msg: %s sig: %s\n", msgString, sig.ToHex())

	return
}

// Signature systems have 3 functions: GenerateKey(), Sign(), and Verify().
// We'll also define the data types: SecretKey, PublicKey, Message, Signature.

// --- Types

// A block of data is always 32 bytes long; we're using sha256 and this
// is the size of both the output (defined by the hash function) and our inputs
type Block [32]byte

// --- Methods on the Block type

// ToHex returns a hex encoded string of the block data, with no newlines.
func (self Block) ToHex() string {
	return fmt.Sprintf("%064x", self[:])
}

// Hash returns the sha256 hash of the block.
func (self Block) Hash() Block {
	return sha256.Sum256(self[:])
}

// IsPreimage returns true if the block is a preimage of the argument.
// For example, if Y = hash(X), then X.IsPreimage(Y) will return true,
// and Y.IsPreimage(X) will return false.
func (self Block) IsPreimage(arg Block) bool {
	return self.Hash() == arg
}

// BlockFromByteSlice returns a block from a variable length byte slice.
// Watch out!  Silently ignores potential errors like the slice being too
// long or too short!
func BlockFromByteSlice(by []byte) Block {
	var bl Block
	copy(bl[:], by)
	return bl
}

type SecretKey struct {
	ZeroPre [256]Block
	OnePre  [256]Block
}

type PublicKey struct {
	ZeroHash [256]Block
	OneHash  [256]Block
}

// --- Methods on PublicKey type

// ToHex gives a hex string for a PublicKey. no newline at the end
func (self PublicKey) ToHex() string {
	// format is zerohash 0...255, onehash 0...255
	var s string
	for _, zero := range self.ZeroHash {
		s += zero.ToHex()
	}
	for _, one := range self.OneHash {
		s += one.ToHex()
	}
	return s
}

// HexToPubkey takes a string from PublicKey.ToHex() and turns it into a pubkey
// will return an error if there are non hex characters or if the lenght is wrong.
func HexToPubkey(s string) (PublicKey, error) {
	var p PublicKey

	expectedLength := 256 * 2 * 64 // 256 blocks long, 2 rows, 64 hex char per block

	// first, make sure hex string is of correct length
	if len(s) != expectedLength {
		return p, fmt.Errorf(
			"Pubkey string %d characters, expect %d", expectedLength, expectedLength)
	}

	// decode from hex to a byte slice
	bts, err := hex.DecodeString(s)
	if err != nil {
		return p, err
	}
	// we already checked the length of the hex string so don't need to re-check
	buf := bytes.NewBuffer(bts)

	for i, _ := range p.ZeroHash {
		p.ZeroHash[i] = BlockFromByteSlice(buf.Next(32))
	}
	for i, _ := range p.OneHash {
		p.OneHash[i] = BlockFromByteSlice(buf.Next(32))
	}

	return p, nil
}

// A signature consists of 32 blocks.  It's a selective reveal of the private
// key, according to the bits of the message.
type Signature struct {
	Preimage [256]Block
}

// ToHex returns a hex string of a signature
func (self Signature) ToHex() string {
	var s string
	for _, b := range self.Preimage {
		s += b.ToHex()
	}

	return s
}

// HexToSignature is the same idea as HexToPubkey, but half as big.  Format is just
// every block of the signature in sequence.
func HexToSignature(s string) (Signature, error) {
	var sig Signature

	expectedLength := 256 * 64 // 256 blocks long, 1 row, 64 hex char per block

	// first, make sure hex string is of correct length
	if len(s) != expectedLength {
		return sig, fmt.Errorf(
			"Pubkey string %d characters, expect %d", expectedLength, expectedLength)
	}

	// decode from hex to a byte slice
	bts, err := hex.DecodeString(s)
	if err != nil {
		return sig, err
	}
	// we already checked the length of the hex string so don't need to re-check
	buf := bytes.NewBuffer(bts)

	for i, _ := range sig.Preimage {
		sig.Preimage[i] = BlockFromByteSlice(buf.Next(32))
	}
	return sig, nil
}

// A message to be signed is just a block.
type Message Block

// GetMessageFromString returns a Message which is the hash of the given string.
func GetMessageFromString(s string) Message {
	return sha256.Sum256([]byte(s))
}

func MessageToStringBitRepresentation(msg Message) string {
	msgHash := Block(msg).Hash()
	var bitStr string
	for i, _ := range msgHash {
		s := strconv.FormatInt(int64(msgHash[i]), 2)

		// ensure len(bitStr) is always 256
		if len(s) < 8 {
			numZeros := 8 - len(s)
			for j := 0; j < numZeros; j++ {
				bitStr += "0"
			}
		}
		bitStr += s
	}
	// fmt.Printf("%s is %d long\n\n", bitStr, len(bitStr))
	return bitStr
}

// --- Functions

// GenerateKey takes no arguments, and returns a keypair and potentially an
// error.  It gets randomness from the OS via crypto/rand
// This can return an error if there is a problem with reading random bytes
func GenerateKey() (SecretKey, PublicKey, error) {
	// initialize SecretKey variable 'sec'.  Starts with all 00 bytes.
	var sec SecretKey
	var pub PublicKey

	// To create the private key Alice uses the random number generator to produce 256 pairs of random numbers (2×256 numbers in total), each number being 256 bits in size, that is, a total of 2×256×256 bits = 128 Kibit in total. This is her private key and she will store it away in a secure place for later use.
	for i, _ := range sec.ZeroPre {
		result, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
		wbuf := new(bytes.Buffer)
		err := binary.Write(wbuf, binary.LittleEndian, result.Int64())
		if err != nil {
			fmt.Println("binary.Write failed:", err)
		}
		bits := wbuf.Bytes()
		sec.ZeroPre[i] = BlockFromByteSlice(bits[:4])
		sec.OnePre[i] = BlockFromByteSlice(bits[4:])
	}

	// To create the public key she hashes each of the 512 random numbers in the private key, thus creating 512 hashes, each 256 bits in size. (Also 128 Kbits in total.) These 512 numbers form her public key, which she will share with the world.
	for i, _ := range sec.ZeroPre {
		pub.ZeroHash[i] = sec.ZeroPre[i].Hash()
		pub.OneHash[i] = sec.OnePre[i].Hash()
	}

	return sec, pub, nil
}

// Sign takes a message and secret key, and returns a signature.
func Sign(msg Message, sec SecretKey) Signature {
	var sig Signature

	// Later Alice wants to sign a message. First she hashes the message to a 256-bit hash sum. Then, for each bit in the hash, based on the value of the bit, she picks one number from the corresponding pairs of numbers that make up her private key (i.e., if the bit is 0, the first number is chosen, and if the bit is 1, the second is chosen). This produces a sequence of 256 numbers. As each number is itself 256 bits long the total size of her signature will be 256×256 bits = 64 KiB. These (originally randomly picked) numbers are her signature and she publishes them along with the message.
	bitStr := MessageToStringBitRepresentation(msg)

	// this can fail if len(bitStr) is not 256
	for i, v := range bitStr {
		if strings.Compare(string(v), "0") == 0 {
			sig.Preimage[i] = sec.ZeroPre[i]
		} else {
			sig.Preimage[i] = sec.OnePre[i]
		}
	}

	return sig
}

// Verify takes a message, public key and signature, and returns a boolean
// describing the validity of the signature.
func Verify(msg Message, pub PublicKey, sig Signature) bool {

	// Then Bob wants to verify Alice's signature of the message. He also hashes the message to get a 256-bit hash sum. Then he uses the bits in the hash sum to pick out 256 of the hashes in Alice's public key. He picks the hashes in the same manner that Alice picked the random numbers for the signature. That is, if the first bit of the message hash is a 0, he picks the first hash in the first pair, and so on.
	verificationBlocks := [256]Block{}

	bitStr := MessageToStringBitRepresentation(msg)

	for i, v := range bitStr {
		if strings.Compare(string(v), "0") == 0 {
			verificationBlocks[i] = pub.ZeroHash[i]
		} else {
			verificationBlocks[i] = pub.OneHash[i]
		}
	}

	// Then Bob hashes each of the 256 random numbers in Alice's signature. This gives him 256 hashes. If these 256 hashes exactly match the 256 hashes he just picked from Alice's public key then the signature is ok. If not, then the signature is wrong.
	verificationHashes := [256]Block{}

	for i, v := range sig.Preimage {
		verificationHashes[i] = v.Hash()
	}

	for i, _ := range verificationHashes {
		if strings.Compare(verificationBlocks[i].ToHex(), verificationHashes[i].ToHex()) != 0 {
			return false
		}
	}

	return true
}
