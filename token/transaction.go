package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"scrit/keydir"

	"golang.org/x/crypto/ed25519"
)

var (
	randomSource = rand.Reader
)

type ParamFactory interface {
	FetchServerParam(signer ed25519.PublicKey) error         // Called to check if unused server params are availeble, or fetch if necessary.
	GetServerParam(signer ed25519.PublicKey) ([]byte, error) // Called to get an unused server param for that signer.
}

type KeyRing interface {
	FetchPrivateKey(publicKey []byte) error                  // Test if private key is available.
	PrivateKey(publicKey []byte) (ed25519.PrivateKey, error) // Return private key for given public key
}

type BinaryOutput struct {
	Value                   int    // Value of output token, currency is defined by input
	BlindSignatureRequest   []byte // Our own blinding parameters
	ServerBlindingParameter []byte // Server's blinding parameter
}

type BinaryTransaction struct {
	InputTokens     [][]byte       // Token,without signatures
	Outputs         []BinaryOutput // Outputs
	TokenSignatures [][]byte       // Serialized signatures in order of InputTokens
	OwnerSignatures [][]byte       // Signatures for spend control, in order of tokens
}

func (self *BinaryTransaction) Marshal() ([]byte, error) {
	return asn1.Marshal(*self)
}

func (self *BinaryTransaction) Unmarshal(d []byte) (*BinaryTransaction, error) {
	r := new(BinaryTransaction)
	_, err := asn1.Unmarshal(d, r)
	if err != nil {
		return nil, err
	}
	return r, nil
}

type TransactionExpect struct {
	LocalBlindParams [][]byte
}

type Transaction struct {
	inputTokens  []TokenWithSignatures
	outputValues []keydir.Value
	outputTokens []Token
	currency     keydir.Currency
	inputValue   keydir.Value

	keyRing      KeyRing
	paramFactory ParamFactory
	issuers      []ed25519.PublicKey

	tokenListHash         []byte
	inputTokensSerialized [][]byte
	inputTokensHashes     [][]byte
	outputTokenHashes     [][]byte
}

// NewTransaction prepares a new transaction, it requires a keyring and a parameter factory.
// issuers is the list of all issuers to correspond with.
func NewTransaction(keyRing KeyRing, paramFactory ParamFactory, issuers []ed25519.PublicKey) *Transaction {
	return &Transaction{
		keyRing:      keyRing,
		paramFactory: paramFactory,
		issuers:      issuers,
	}
}

// GetBalance returns the remaining difference between input and output.
func (self *Transaction) GetBalance() keydir.Value {
	return self.inputValue
}

// Balance an output token to zero the transaction.
func (self *Transaction) Balance(outputToken *Token) bool {
	if self.inputValue == 0 {
		return false
	}
	self.AddOutput(self.inputValue, outputToken)
	return true
}

// AddOutput adds a transaction output. Must be called after AddInput.
func (self *Transaction) AddOutput(value keydir.Value, outputToken *Token) error {
	if self.inputValue < value {
		return ErrMissingValue
	}
	self.inputValue = self.inputValue - value
	self.outputValues = append(self.outputValues, value)
	self.outputTokens = append(self.outputTokens, *outputToken)
	return nil
}

// AddInput adds a transaction input. Must be called first.
func (self *Transaction) AddInput(inputToken *TokenWithSignatures) error {
	if !inputToken.verified {
		return ErrNotVerified
	}
	if len(inputToken.issuers) == 0 {
		return ErrUnSigned
	}
	if self.currency == "" {
		self.currency = inputToken.currency
	}
	if self.currency != inputToken.currency {
		return ErrMixedValues
	}
	self.inputValue = self.inputValue + inputToken.value
	self.inputTokens = append(self.inputTokens, *inputToken)
	return nil
}

func (self *Transaction) fetchParams(issuer ed25519.PublicKey) error {
	for i := 0; i < len(self.outputTokens); i++ {
		if err := self.paramFactory.FetchServerParam(issuer); err != nil {
			return nil
		}
	}
	return nil
}

func (self *Transaction) Transact() ([]IssuerTransaction, error) {
	transactions := make([]IssuerTransaction, 0, len(self.issuers))
	// Test for required signature keys
	for _, token := range self.inputTokens {
		pubkey := token.Signer()
		if pubkey != nil {
			if err := self.keyRing.FetchPrivateKey(pubkey); err != nil {
				return nil, err
			}
		}
	}
	// Serialize InputTokens and generate hash.
	err := self.preCalculateLocal()
	if err != nil {
		return nil, err
	}
	// Test for serverParameters
	for _, issuer := range self.issuers {
		if err := self.fetchParams(issuer); err != nil {
			return nil, err
		}
	}
	for _, issuer := range self.issuers {
		transaction, err := self.transactionFor(issuer)
		if err != nil {
			return nil, err
		}
		transactions = append(transactions, *transaction)
	}
	return transactions, nil
}

func calculateTokenHash(tokenList []TokenWithSignatures) (inputTokensSerialized, inputTokensHashes [][]byte, tokenListHash []byte, err error) {
	for _, t := range tokenList {
		d, err := t.Token.Marshal()
		if err != nil {
			return nil, nil, nil, err
		}
		inputTokensSerialized = append(inputTokensSerialized, d)
		h := sha256.Sum256(d)
		inputTokensHashes = append(inputTokensHashes, h[:])
	}
	ser, err := asn1.Marshal(inputTokensHashes)
	if err != nil {
		return nil, nil, nil, err
	}
	tokenListHashT := sha256.Sum256(ser)
	tokenListHash = tokenListHashT[:]
	return
}

func (self *Transaction) preCalculateLocal() error {
	var err error
	self.inputTokensSerialized, self.inputTokensHashes, self.tokenListHash, err = calculateTokenHash(self.inputTokens)
	if err != nil {
		return err
	}
	for _, t := range self.outputTokens {
		h, err := t.SHA256()
		if err != nil {
			return err
		}
		self.outputTokenHashes = append(self.outputTokenHashes, h[:])

	}
	return nil
}

func calcHMAC(a, b []byte) []byte {
	h := hmac.New(sha256.New, a)
	h.Write(b)
	return h.Sum(nil)
}
