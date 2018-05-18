package lnwire

import (
	"fmt"

	"github.com/decred/dcrd/dcrutil"
)

// mSatScale is a value that's used to scale satoshis to milli-satoshis, and
// the other way around.
const mSatScale int64 = 1000

// MilliSatoshi are the native unit of the Lightning Network. A milli-satoshi
// is simply 1/1000th of a satoshi. There are 1000 milli-satoshis in a single
// satoshi. Within the network, all HTLC payments are denominated in
// milli-satoshis. As milli-satoshis aren't deliverable on the native
// blockchain, before settling to broadcasting, the values are rounded down to
// the nearest satoshi.
type MilliSatoshi int64

// NewMSatFromSatoshis creates a new MilliSatoshi instance from a target amount
// of satoshis.
func NewMSatFromSatoshis(sat dcrutil.Amount) MilliSatoshi {
	return MilliSatoshi(int64(sat) * mSatScale)
}

// TODO(davec): ToCoin...
// ToBTC converts the target MilliSatoshi amount to its corresponding value
// when expressed in BTC.
func (m MilliSatoshi) ToBTC() float64 {
	sat := m.ToSatoshis()
	return sat.ToCoin()
}

// ToSatoshis converts the target MilliSatoshi amount to satoshis. Simply, this
// sheds a factor of 1000 from the mSAT amount in order to convert it to SAT.
func (m MilliSatoshi) ToSatoshis() dcrutil.Amount {
	return dcrutil.Amount(int64(m) / mSatScale)
}

// String returns the string representation of the mSAT amount.
func (m MilliSatoshi) String() string {
	return fmt.Sprintf("%v mSAT", int64(m))
}
