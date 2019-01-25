package dcrwallet

import (
	"path/filepath"
	"time"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrlnd/lnwallet"
	"github.com/decred/dcrwallet/chain"

	//"github.com/decred/dcrlnd/lnwallet" // TODO(decred): Finish

	// This is required to register bdb as a valid walletdb driver. In the
	// init function of the package, it registers itself. The import is used
	// to activate the side effects w/o actually binding the package name to
	// a file-level variable.
	"github.com/decred/dcrwallet/wallet"
	_ "github.com/decred/dcrwallet/wallet/drivers/bdb"
)

var (
	lnwalletHomeDir = dcrutil.AppDataDir("lnwallet", false)
	defaultDataDir  = lnwalletHomeDir

	defaultLogFilename = "lnwallet.log"
	defaultLogDirname  = "logs"
	defaultLogDir      = filepath.Join(lnwalletHomeDir, defaultLogDirname)

	dcrdHomeDir        = dcrutil.AppDataDir("dcrd", false)
	dcrdHomedirCAFile  = filepath.Join(dcrdHomeDir, "rpc.cert")
	defaultRPCKeyFile  = filepath.Join(lnwalletHomeDir, "rpc.key")
	defaultRPCCertFile = filepath.Join(lnwalletHomeDir, "rpc.cert")

	// defaultPubPassphrase is the default public wallet passphrase which is
	// used when the user indicates they do not want additional protection
	// provided by having all public data in the wallet encrypted by a
	// passphrase only known to them.
	defaultPubPassphrase = []byte("public")

	defaultAllowHighFees = false

	walletDbName = "lnwallet.db"
)

// Config is a struct which houses configuration parameters which modify the
// instance of DcrWallet generated by the New() function.
type Config struct {
	// DataDir is the name of the directory where the wallet's persistent
	// state should be stored.
	DataDir string

	// LogDir is the name of the directory which should be used to store
	// generated log files.
	LogDir string

	// PrivatePass is the private password to the underlying dcrwallet
	// instance. Without this, the wallet cannot be decrypted and operated.
	PrivatePass []byte

	// PublicPass is the optional public password to dcrwallet. This is
	// optionally used to encrypt public material such as public keys and
	// scripts.
	PublicPass []byte

	// HdSeed is an optional seed to feed into the wallet. If this is
	// unspecified, a new seed will be generated.
	HdSeed []byte

	// Birthday specifies the time at which this wallet was initially
	// created. It is used to bound rescans for used addresses.
	Birthday time.Time

	// FeeEstimator is an instance of the fee estimator interface which
	// will be used by the wallet to dynamically set transaction fees when
	// crafting transactions.
	FeeEstimator lnwallet.FeeEstimator

	// RecoveryWindow specifies the address look-ahead for which to scan
	// when restoring a wallet. The recovery window will apply to all
	// default BIP44 derivation paths.
	RecoveryWindow uint32

	// ChainSource is an rpc client that is able to connect to a running
	// instance of dcrd.
	//
	// TODO(matheusd): possibly use a NetworkBackend instead of rpcclient in
	// order to be able to connect directly to the network via SPV.
	ChainSource *chain.RPCClient

	// FeeEstimator is an instance of the fee estimator interface which
	// will be used by the wallet to dynamically set transaction fees when
	// crafting transactions.
	//FeeEstimator lnwallet.FeeEstimator // TODO(decred): Uncomment

	// NetParams is the net parameters for the target chain.
	NetParams *chaincfg.Params

	// Wallet is an unlocked wallet instance that is set if the
	// UnlockerService has already opened and unlocked the wallet. If this
	// is nil, then a wallet might have just been created or is simply not
	// encrypted at all, in which case it should be attempted to be loaded
	// normally when creating the DcrWallet.
	Wallet *wallet.Wallet
}

// NetworkDir returns the directory name of a network directory to hold wallet
// files.
func NetworkDir(dataDir string, chainParams *chaincfg.Params) string {
	netname := chainParams.Name
	switch chainParams.Net {
	case 0x48e7a065: // testnet2
		netname = "testnet2"
	case wire.TestNet3:
		netname = "testnet3"
	}
	return filepath.Join(dataDir, netname)
}
