package dcrdnotify

import (
	"fmt"

	"github.com/decred/dcrd/rpcclient"
	"github.com/decred/dcrlnd/chainntnfs"
)

// createNewNotifier creates a new instance of the ChainNotifier interface
// implemented by DcrdNotifier.
func createNewNotifier(args ...interface{}) (chainntnfs.ChainNotifier, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("incorrect number of arguments to .New(...), "+
			"expected 1, instead passed %v", len(args))
	}

	config, ok := args[0].(*rpcclient.ConnConfig)
	if !ok {
		return nil, fmt.Errorf("first argument to dcrdnotifier.New is " +
			"incorrect, expected a *rpcclient.ConnConfig")
	}

	return New(config)
}

// init registers a driver for the DcrdNotifier concrete implementation of the
// chainntnfs.ChainNotifier interface.
func init() {
	// Register the driver.
	notifier := &chainntnfs.NotifierDriver{
		NotifierType: notifierType,
		New:          createNewNotifier,
	}

	if err := chainntnfs.RegisterNotifier(notifier); err != nil {
		panic(fmt.Sprintf("failed to register notifier driver '%s': %v",
			notifierType, err))
	}
}
