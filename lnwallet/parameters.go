package lnwallet

import (
	"github.com/decred/dcrd/dcrutil"
	//"github.com/decred/dcrwallet/wallet/txrules" // TODO(davec): Uncomment when ported
)

// DefaultDustLimit is used to calculate the dust HTLC amount which will be
// send to other node during funding process.
func DefaultDustLimit() dcrutil.Amount {
	// TODO(davec): Correct size, implement txrules function, and use
	// p2sh size, not p2wsh.
	//return txrules.GetDustThreshold(P2WSHSize, txrules.DefaultRelayFeePerKb)
	return 248
}
