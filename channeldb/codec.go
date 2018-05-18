package channeldb

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrlnd/lnwire"
	"github.com/decred/dcrlnd/shachain"
)

// outPointSize is the size of a serialized outpoint on disk.
const outPointSize = 36

// writeOutpoint writes an outpoint to the passed writer using the minimal
// amount of bytes possible.
func writeOutpoint(w io.Writer, o *wire.OutPoint) error {
	if _, err := w.Write(o.Hash[:]); err != nil {
		return err
	}
	if err := binary.Write(w, byteOrder, o.Index); err != nil {
		return err
	}

	return nil
}

// readOutpoint reads an outpoint from the passed reader that was previously
// written using the writeOutpoint struct.
func readOutpoint(r io.Reader, o *wire.OutPoint) error {
	if _, err := io.ReadFull(r, o.Hash[:]); err != nil {
		return err
	}
	if err := binary.Read(r, byteOrder, &o.Index); err != nil {
		return err
	}

	return nil
}

// writeElement is a one-stop shop to write the big endian representation of
// any element which is to be serialized for storage on disk. The passed
// io.Writer should be backed by an appropriately sized byte slice, or be able
// to dynamically expand to accommodate additional data.
func writeElement(w io.Writer, element interface{}) error {
	switch e := element.(type) {
	case ChannelType:
		if err := binary.Write(w, byteOrder, e); err != nil {
			return err
		}

	case chainhash.Hash:
		if _, err := w.Write(e[:]); err != nil {
			return err
		}

	case wire.OutPoint:
		return writeOutpoint(w, &e)

	case lnwire.ShortChannelID:
		if err := binary.Write(w, byteOrder, e.ToUint64()); err != nil {
			return err
		}

	case uint64:
		if err := binary.Write(w, byteOrder, e); err != nil {
			return err
		}

	case uint32:
		if err := binary.Write(w, byteOrder, e); err != nil {
			return err
		}

	case int32:
		if err := binary.Write(w, byteOrder, e); err != nil {
			return err
		}

	case uint16:
		if err := binary.Write(w, byteOrder, e); err != nil {
			return err
		}

	case bool:
		if err := binary.Write(w, byteOrder, e); err != nil {
			return err
		}

	case dcrutil.Amount:
		if err := binary.Write(w, byteOrder, uint64(e)); err != nil {
			return err
		}

	case lnwire.MilliSatoshi:
		if err := binary.Write(w, byteOrder, uint64(e)); err != nil {
			return err
		}

	case *secp256k1.PublicKey:
		b := e.SerializeCompressed()
		if _, err := w.Write(b); err != nil {
			return err
		}

	case shachain.Producer:
		return e.Encode(w)

	case shachain.Store:
		return e.Encode(w)

	case *wire.MsgTx:
		return e.Serialize(w)

	case [32]byte:
		if _, err := w.Write(e[:]); err != nil {
			return err
		}

	case []byte:
		if err := wire.WriteVarBytes(w, 0, e); err != nil {
			return err
		}

	case lnwire.Message:
		if _, err := lnwire.WriteMessage(w, e, 0); err != nil {
			return err
		}

	case ClosureType:
		if err := binary.Write(w, byteOrder, e); err != nil {
			return err
		}
	case lnwire.FundingFlag:
		if err := binary.Write(w, byteOrder, e); err != nil {
			return err
		}

	default:
		return fmt.Errorf("Unknown type in writeElement: %T", e)
	}

	return nil
}

// writeElements is writes each element in the elements slice to the passed
// io.Writer using writeElement.
func writeElements(w io.Writer, elements ...interface{}) error {
	for _, element := range elements {
		err := writeElement(w, element)
		if err != nil {
			return err
		}
	}
	return nil
}

// readElement is a one-stop utility function to deserialize any datastructure
// encoded using the serialization format of the database.
func readElement(r io.Reader, element interface{}) error {
	switch e := element.(type) {
	case *ChannelType:
		if err := binary.Read(r, byteOrder, e); err != nil {
			return err
		}

	case *chainhash.Hash:
		if _, err := io.ReadFull(r, e[:]); err != nil {
			return err
		}

	case *wire.OutPoint:
		return readOutpoint(r, e)

	case *lnwire.ShortChannelID:
		var a uint64
		if err := binary.Read(r, byteOrder, &a); err != nil {
			return err
		}
		*e = lnwire.NewShortChanIDFromInt(a)

	case *uint64:
		if err := binary.Read(r, byteOrder, e); err != nil {
			return err
		}

	case *uint32:
		if err := binary.Read(r, byteOrder, e); err != nil {
			return err
		}

	case *int32:
		if err := binary.Read(r, byteOrder, e); err != nil {
			return err
		}

	case *uint16:
		if err := binary.Read(r, byteOrder, e); err != nil {
			return err
		}

	case *bool:
		if err := binary.Read(r, byteOrder, e); err != nil {
			return err
		}

	case *dcrutil.Amount:
		var a uint64
		if err := binary.Read(r, byteOrder, &a); err != nil {
			return err
		}

		*e = dcrutil.Amount(a)

	case *lnwire.MilliSatoshi:
		var a uint64
		if err := binary.Read(r, byteOrder, &a); err != nil {
			return err
		}

		*e = lnwire.MilliSatoshi(a)

	case **secp256k1.PublicKey:
		var b [secp256k1.PubKeyBytesLenCompressed]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return err
		}

		pubKey, err := secp256k1.ParsePubKey(b[:])
		if err != nil {
			return err
		}
		*e = pubKey

	case *shachain.Producer:
		var root [32]byte
		if _, err := io.ReadFull(r, root[:]); err != nil {
			return err
		}

		// TODO(roasbeef): remove
		producer, err := shachain.NewRevocationProducerFromBytes(root[:])
		if err != nil {
			return err
		}

		*e = producer

	case *shachain.Store:
		store, err := shachain.NewRevocationStoreFromBytes(r)
		if err != nil {
			return err
		}

		*e = store

	case **wire.MsgTx:
		tx := wire.NewMsgTx()
		if err := tx.Deserialize(r); err != nil {
			return err
		}

		*e = tx

	case *[32]byte:
		if _, err := io.ReadFull(r, e[:]); err != nil {
			return err
		}

	case *[]byte:
		bytes, err := wire.ReadVarBytes(r, 0, 66000, "[]byte")
		if err != nil {
			return err
		}

		*e = bytes

	case *lnwire.Message:
		msg, err := lnwire.ReadMessage(r, 0)
		if err != nil {
			return err
		}

		*e = msg

	case *ClosureType:
		if err := binary.Read(r, byteOrder, e); err != nil {
			return err
		}
	case *lnwire.FundingFlag:
		if err := binary.Read(r, byteOrder, e); err != nil {
			return err
		}

	default:
		return fmt.Errorf("Unknown type in readElement: %T", e)
	}

	return nil
}

// readElements deserializes a variable number of elements into the passed
// io.Reader, with each element being deserialized according to the readElement
// function.
func readElements(r io.Reader, elements ...interface{}) error {
	for _, element := range elements {
		err := readElement(r, element)
		if err != nil {
			return err
		}
	}
	return nil
}
