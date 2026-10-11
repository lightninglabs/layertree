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
	TypeVoucherTreeID     tlv.Type = 0
	TypeVoucherSourceLeaf tlv.Type = 1
	TypeVoucherClaimLeaf  tlv.Type = 2
	TypeVoucherSig        tlv.Type = 3
)

// Voucher is an off-chain voucher (spec 7.5, 9.6): the source leaf's owner
// signs H_voucher(tree_id || body(source_leaf) || claim_leaf), authorizing
// anyone holding it to carve claim_leaf out of source_leaf with CLAIM. It is
// the tuple (tree_id, source_leaf, claim_leaf, voucher_sig) of 9.6. The
// message binds the source leaf without its amount, so the voucher stays
// redeemable after an amount-only REWRITE_h top-up of the source; the
// SourceLeaf carried here is the leaf as the issuer saw it, and a redeemer
// presents the leaf as it stands in the tree.
type Voucher struct {
	// TreeID is the tree's tree_id (spec 6.2), the value its CLAIM scripts
	// carry; a recipient checks it against the published creation
	// parameters (9.6).
	TreeID [32]byte

	// SourceLeaf is the leaf whose owner_key signs the voucher.
	SourceLeaf tree.Leaf

	// ClaimLeaf is the leaf the voucher authorizes to claim in
	// SourceLeaf's place.
	ClaimLeaf tree.Leaf

	// Sig is the BIP-340 Schnorr signature over Msg(), by
	// SourceLeaf.OwnerKey.
	Sig [64]byte
}

// Msg returns H_voucher(tree_id || body(source_leaf) || claim_leaf), the
// message SourceLeaf.OwnerKey signs (spec 7.5).
func (v *Voucher) Msg() [32]byte {
	return tree.VoucherMsg(v.TreeID, &v.SourceLeaf, &v.ClaimLeaf)
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

// Verify checks Sig against SourceLeaf.OwnerKey over Msg() (spec 7.5). The
// message is built over the voucher's own TreeID, so a voucher issued for
// another tree verifies true here: a caller MUST also compare TreeID with
// the tree's tree_id (TreeState.Options.TreeID), as txn.BuildClaim does by
// verifying the signature over the tree's own value instead.
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
	treeID *[32]byte,
	source, claim *tree.Leaf,
	sig *[64]byte,
) []tlv.Record {

	return []tlv.Record{
		tlv.MakePrimitiveRecord(TypeVoucherTreeID, treeID),
		leafRecord(TypeVoucherSourceLeaf, source),
		leafRecord(TypeVoucherClaimLeaf, claim),
		tlv.MakePrimitiveRecord(TypeVoucherSig, sig),
	}
}

// Encode serializes the voucher as a TLV stream.
func (v *Voucher) Encode(w io.Writer) error {
	treeID, sig := v.TreeID, v.Sig

	stream, err := tlv.NewStream(voucherRecords(
		&treeID, &v.SourceLeaf, &v.ClaimLeaf, &sig,
	)...)
	if err != nil {
		return err
	}

	return stream.Encode(w)
}

// Decode deserializes a voucher from a TLV stream produced by Encode. It
// reads at most maxVoucherLen bytes of r.
func (v *Voucher) Decode(r io.Reader) error {
	var (
		treeID [32]byte
		sig    [64]byte
	)

	err := decodeLimited(r, maxVoucherLen, voucherRecords(
		&treeID, &v.SourceLeaf, &v.ClaimLeaf, &sig,
	))
	if err != nil {
		return err
	}

	v.TreeID = treeID
	v.Sig = sig

	return nil
}
