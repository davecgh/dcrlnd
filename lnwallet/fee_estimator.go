package lnwallet

import (
	"context"

	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/rpcclient"
)

// FeeEstimator provides the ability to estimate on-chain transaction fees for
// various combinations of transaction sizes and desired confirmation time
// (measured by number of blocks).
type FeeEstimator interface {
	// EstimateFeePerByte takes in a target for the number of blocks until
	// an initial confirmation and returns the estimated fee expressed in
	// atoms/byte.
	EstimateFeePerByte(numBlocks uint32) (dcrutil.Amount, error)

	// Start signals the FeeEstimator to start any processes or goroutines
	// it needs to perform its duty.
	Start() error

	// Stop stops any spawned goroutines and cleans up the resources used
	// by the fee estimator.
	Stop() error
}

// StaticFeeEstimator will return a static value for all fee calculation
// requests. It is designed to be replaced by a proper fee calculation
// implementation.
type StaticFeeEstimator struct {
	// FeeRate is the static fee rate in atoms-per-byte that will be
	// returned by this fee estimator. Queries for the fee rate in weight
	// units will be scaled accordingly.
	FeeRate dcrutil.Amount
}

// EstimateFeePerByte will return a static value for fee calculations.
//
// NOTE: This method is part of the FeeEstimator interface.
func (e StaticFeeEstimator) EstimateFeePerByte(numBlocks uint32) (dcrutil.Amount, error) {
	return e.FeeRate, nil
}

// Start signals the FeeEstimator to start any processes or goroutines
// it needs to perform its duty.
//
// NOTE: This method is part of the FeeEstimator interface.
func (e StaticFeeEstimator) Start() error {
	return nil
}

// Stop stops any spawned goroutines and cleans up the resources used
// by the fee estimator.
//
// NOTE: This method is part of the FeeEstimator interface.
func (e StaticFeeEstimator) Stop() error {
	return nil
}

// A compile-time assertion to ensure that StaticFeeEstimator implements the
// FeeEstimator interface.
var _ FeeEstimator = (*StaticFeeEstimator)(nil)

// DcrdFeeEstimator is an implementation of the FeeEstimator interface backed
// by the RPC interface of an active dcrd node. This implementation will proxy
// any fee estimation requests to dcrd's RPC interface.
type DcrdFeeEstimator struct {
	// fallBackFeeRate is the fall back fee rate in atoms per byte that
	// is returned if the fee estimator does not yet have enough data to
	// actually produce fee estimates.
	fallBackFeeRate dcrutil.Amount

	dcrdConn *rpcclient.Client
}

// NewDcrdFeeEstimator creates a new DcrdFeeEstimator given a fully populated
// rpc config that is able to successfully connect and authenticate with the
// dcrd node, and also a fall back fee rate. The fallback fee rate is used in
// the occasion that the estimator has insufficient data, or returns zero for a
// fee estimate.
func NewDcrdFeeEstimator(rpcConfig rpcclient.ConnConfig,
	fallBackFeeRate dcrutil.Amount) (*DcrdFeeEstimator, error) {

	rpcConfig.DisableConnectOnNew = true
	rpcConfig.DisableAutoReconnect = false
	chainConn, err := rpcclient.New(&rpcConfig, nil)
	if err != nil {
		return nil, err
	}

	return &DcrdFeeEstimator{
		fallBackFeeRate: fallBackFeeRate,
		dcrdConn:        chainConn,
	}, nil
}

// Start signals the FeeEstimator to start any processes or goroutines
// it needs to perform its duty.
//
// NOTE: This method is part of the FeeEstimator interface.
func (b *DcrdFeeEstimator) Start() error {
	ctx := context.Background()
	if err := b.dcrdConn.Connect(ctx, true); err != nil {
		return err
	}

	return nil
}

// Stop stops any spawned goroutines and cleans up the resources used
// by the fee estimator.
//
// NOTE: This method is part of the FeeEstimator interface.
func (b *DcrdFeeEstimator) Stop() error {
	b.dcrdConn.Shutdown()

	return nil
}

// EstimateFeePerByte takes in a target for the number of blocks until an
// initial confirmation and returns the estimated fee expressed in
// atoms/byte.
func (b *DcrdFeeEstimator) EstimateFeePerByte(numBlocks uint32) (dcrutil.Amount, error) {
	feeEstimate, err := b.fetchEstimatePerByte(numBlocks)
	switch {
	// If the estimator doesn't have enough data, or returns an error, then
	// to return a proper value, then we'll return the default fall back
	// fee rate.
	case err != nil:
		walletLog.Errorf("unable to query estimator: %v", err)
		fallthrough

	case feeEstimate == 0:
		return b.fallBackFeeRate, nil
	}

	return feeEstimate, nil
}

// fetchEstimate returns a fee estimate for a transaction be be confirmed in
// confTarget blocks. The estimate is returned in atoms/byte.
func (b *DcrdFeeEstimator) fetchEstimatePerByte(confTarget uint32) (dcrutil.Amount, error) {
	// TODO(davec): Implement fee estimation.
	// First, we'll fetch the estimate for our confirmation target.
	//	dcrPerKB, err := b.dcrdConn.EstimateFee(int64(confTarget))
	//	if err != nil {
	//		return 0, err
	//	}
	dcrPerKB := float64(0.001)

	// Next, we'll convert the returned value to atoms, as it's
	// currently returned in DCR.
	atomsPerKB, err := dcrutil.NewAmount(dcrPerKB)
	if err != nil {
		return 0, err
	}

	// The value returned is expressed in fees per KB, while we want
	// fee-per-byte, so we'll divide by 1024 to map to atoms-per-byte
	// before returning the estimate.
	atomsPerByte := atomsPerKB / 1024

	walletLog.Debugf("Returning %v atoms/byte for conf target of %v",
		int64(atomsPerByte), confTarget)

	return atomsPerByte, nil
}

// A compile-time assertion to ensure that DcrdFeeEstimator implements the
// FeeEstimator interface.
var _ FeeEstimator = (*DcrdFeeEstimator)(nil)
