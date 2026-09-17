package msg

import (
	"bytes"
	"errors"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightningnetwork/lnd/tlv"
	"github.com/roasbeef/layertree/tree"
)

// TLV types for Voucher (spec 7.5, 9.6).
const (
	TypeVoucherMerkleRoot tlv.Type = 0
	TypeVoucherSourceLeaf tlv.Type = 1
	TypeVoucherClaimLeaf  tlv.Type = 2
	TypeVoucherSig        tlv.Type = 3
)

// Voucher is an off-chain eviction voucher (spec 7.5, 9.6): the source
// leaf's owner signs H_voucher(m || source_leaf || claim_leaf), authorizing
// claim_leaf to later stand in for source_leaf's exit path.
type Voucher struct {
	// MerkleRoot is m, the tree root hash committed into the voucher
	// message.
	MerkleRoot [32]byte

	// SourceLeaf is the leaf whose owner_key signs the voucher.
	SourceLeaf tree.Leaf

	// ClaimLeaf is the leaf the voucher authorizes to claim in
	// SourceLeaf's place.
	ClaimLeaf tree.Leaf

	// Sig is the BIP-340 Schnorr signature over Msg(), by
	// SourceLeaf.OwnerKey.
	Sig [64]byte
}

// Msg returns H_voucher(m || source_leaf || claim_leaf), the message
// SourceLeaf.OwnerKey signs (spec 7.5).
func (v *Voucher) Msg() [32]byte {
	return tree.VoucherMsg(v.MerkleRoot, &v.SourceLeaf, &v.ClaimLeaf)
}

// Sign signs the voucher with priv, which must own SourceLeaf.OwnerKey.
func (v *Voucher) Sign(priv *btcec.PrivateKey) error {
	xOnly := schnorr.SerializePubKey(priv.PubKey())
	if !bytes.Equal(xOnly, v.SourceLeaf.OwnerKey[:]) {
		return errors.New("msg: signing key does not match the " +
			"source leaf's owner key")
	}

	msg := v.Msg()
	sig, err := schnorr.Sign(priv, msg[:])
	if err != nil {
		return err
	}
	copy(v.Sig[:], sig.Serialize())

	return nil
}

// Verify checks Sig against SourceLeaf.OwnerKey over Msg() (spec 7.5).
func (v *Voucher) Verify() bool {
	pub, err := schnorr.ParsePubKey(v.SourceLeaf.OwnerKey[:])
	if err != nil {
		return false
	}

	sig, err := schnorr.ParseSignature(v.Sig[:])
	if err != nil {
		return false
	}

	msg := v.Msg()
	return sig.Verify(msg[:], pub)
}

// voucherRecords returns the TLV records for the voucher's fields, bound to
// the passed backing variables.
func voucherRecords(
	merkleRoot *[32]byte,
	source, claim *tree.Leaf,
	sig *[64]byte,
) []tlv.Record {

	return []tlv.Record{
		tlv.MakePrimitiveRecord(TypeVoucherMerkleRoot, merkleRoot),
		leafRecord(TypeVoucherSourceLeaf, source),
		leafRecord(TypeVoucherClaimLeaf, claim),
		tlv.MakePrimitiveRecord(TypeVoucherSig, sig),
	}
}

// Encode serializes the voucher as a TLV stream.
func (v *Voucher) Encode(w io.Writer) error {
	merkleRoot, sig := v.MerkleRoot, v.Sig

	stream, err := tlv.NewStream(voucherRecords(
		&merkleRoot, &v.SourceLeaf, &v.ClaimLeaf, &sig,
	)...)
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// Decode deserializes a voucher from a TLV stream produced by Encode.
func (v *Voucher) Decode(r io.Reader) error {
	var (
		merkleRoot [32]byte
		sig        [64]byte
	)

	stream, err := tlv.NewStream(voucherRecords(
		&merkleRoot, &v.SourceLeaf, &v.ClaimLeaf, &sig,
	)...)
	if err != nil {
		return err
	}
	if err := stream.Decode(r); err != nil {
		return err
	}

	v.MerkleRoot = merkleRoot
	v.Sig = sig

	return nil
}
