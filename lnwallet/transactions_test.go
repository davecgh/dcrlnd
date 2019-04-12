package lnwallet

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrlnd/channeldb"
	"github.com/decred/dcrlnd/keychain"
	"github.com/decred/dcrlnd/lnwire"
	"github.com/decred/dcrlnd/shachain"
)

/**
* This file implements that different types of transactions used in the
* lightning protocol are created correctly. To do so, the tests use the test
* vectors defined in Appendix B & C of BOLT 03.
 */

// testContext contains the test parameters defined in Appendix B & C of the
// BOLT 03 spec.
type testContext struct {
	netParams *chaincfg.Params
	block1    *dcrutil.Block

	fundingInputPrivKey *secp256k1.PrivateKey
	localFundingPrivKey *secp256k1.PrivateKey
	localPaymentPrivKey *secp256k1.PrivateKey

	remoteFundingPubKey    *secp256k1.PublicKey
	localFundingPubKey     *secp256k1.PublicKey
	localRevocationPubKey  *secp256k1.PublicKey
	localPaymentPubKey     *secp256k1.PublicKey
	remotePaymentPubKey    *secp256k1.PublicKey
	localDelayPubKey       *secp256k1.PublicKey
	commitmentPoint        *secp256k1.PublicKey
	localPaymentBasePoint  *secp256k1.PublicKey
	remotePaymentBasePoint *secp256k1.PublicKey

	fundingChangeAddress dcrutil.Address
	fundingInputUtxo     *Utxo
	fundingInputTxOut    *wire.TxOut
	fundingTx            *dcrutil.Tx
	fundingOutpoint      wire.OutPoint
	shortChanID          lnwire.ShortChannelID

	htlcs []channeldb.HTLC

	localCsvDelay uint16
	fundingAmount dcrutil.Amount
	dustLimit     dcrutil.Amount
	FeePerKB      dcrutil.Amount
}

// htlcDesc is a description used to construct each HTLC in each test case.
type htlcDesc struct {
	index           int
	remoteSigHex    string
	resolutionTxHex string
}

// getHTLC constructs an HTLC based on a configured HTLC with auxiliary data
// such as the remote signature from the htlcDesc. The partially defined HTLCs
// originate from the BOLT 03 spec and are contained in the test context.
func (tc *testContext) getHTLC(index int, desc *htlcDesc) (channeldb.HTLC, error) {
	signature, err := hex.DecodeString(desc.remoteSigHex)
	if err != nil {
		return channeldb.HTLC{}, fmt.Errorf(
			"Failed to parse serialized signature: %v", err)
	}

	htlc := tc.htlcs[desc.index]
	return channeldb.HTLC{
		Signature:     signature,
		RHash:         htlc.RHash,
		RefundTimeout: htlc.RefundTimeout,
		Amt:           htlc.Amt,
		OutputIndex:   int32(index),
		Incoming:      htlc.Incoming,
	}, nil
}

// newTestContext populates a new testContext struct with the constant
// parameters defined in the BOLT 03 spec. This may return an error if any of
// the serialized parameters cannot be parsed.
func newTestContext() (tc *testContext, err error) {
	tc = new(testContext)

	const genesisHash = "2ced94b4ae95bba344cfa043268732d230649c640f92dce2d9518823d3057cb0"
	if tc.netParams, err = tc.createNetParams(genesisHash); err != nil {
		return
	}

	const block1Hex = "06000000b07c05d3238851d9e2dc920f649c6430d232872643a0cf44a3bb95aeb494ed2c841706fbd326fb3584ac6ed18f2899189c2d20bae5031932dd8a004300c2dabc000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000ffff7f20204e0000000000000100000073010000e94c485c01000000cf1e86eb445c26a0000000000000000000000000000000000000000000000000000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0300a0724e1809000000001976a9147e4765ae88ba9ad5c9e4715c484e90b34d358d5188ac00a0724e1809000000001976a91402fb1ac0137666d79165e13cecd403883615270788ac00a0724e1809000000001976a91469de627d3231b14228653dd09cba75eeb872754288ac00000000000000000100e057eb481b000000000000ffffffff0800002f646372642f00"
	if tc.block1, err = blockFromHex(block1Hex); err != nil {
		err = fmt.Errorf("Failed to parse serialized block: %v", err)
		return
	}

	// Key for decred's BlockOneLedgerRegNet address RsKrWb7Vny1jnzL1sDLgKTAteh9RZcRr5g6
	const fundingInputPrivKeyHex = "fd79250838efa1c142e182d012004c541df2668014cc1758027d70069b2ef474"
	tc.fundingInputPrivKey, err = privkeyFromHex(fundingInputPrivKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized privkey: %v", err)
		return
	}

	const localFundingPrivKeyHex = "30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749"
	tc.localFundingPrivKey, err = privkeyFromHex(localFundingPrivKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized privkey: %v", err)
		return
	}

	const localPaymentPrivKeyHex = "bb13b121cdc357cd2e608b0aea294afca36e2b34cf958e2e6451a2f274694491"
	tc.localPaymentPrivKey, err = privkeyFromHex(localPaymentPrivKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized privkey: %v", err)
		return
	}

	const localFundingPubKeyHex = "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb"
	tc.localFundingPubKey, err = pubkeyFromHex(localFundingPubKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	// Sanity check.
	if !tc.localFundingPrivKey.PubKey().IsEqual(tc.localFundingPubKey) {
		err = fmt.Errorf("Pubkey of localFundingPrivKey not the same as encoded")
		return
	}

	// Corresponding private key: 11796dc04db0bd5858cfd9aa109e0b8f83039dbf2080520ea6df906802feb06f
	const remoteFundingPubKeyHex = "037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd5"
	tc.remoteFundingPubKey, err = pubkeyFromHex(remoteFundingPubKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	const localRevocationPubKeyHex = "0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19"
	tc.localRevocationPubKey, err = pubkeyFromHex(localRevocationPubKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	const localPaymentPubKeyHex = "030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e7"
	tc.localPaymentPubKey, err = pubkeyFromHex(localPaymentPubKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	// Corresponding private key: a914caedc83de8579ddc703de39b99b47fcb806f2e6987
	const remotePaymentPubKeyHex = "034ac695f3269d836cd00072a088a9109d83609e6e69955bcf415acda0179b6ed9"
	tc.remotePaymentPubKey, err = pubkeyFromHex(remotePaymentPubKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	const localDelayPubKeyHex = "03fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c"
	tc.localDelayPubKey, err = pubkeyFromHex(localDelayPubKeyHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	const commitmentPointHex = "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486"
	tc.commitmentPoint, err = pubkeyFromHex(commitmentPointHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	const localPaymentBasePointHex = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
	tc.localPaymentBasePoint, err = pubkeyFromHex(localPaymentBasePointHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	const remotePaymentBasePointHex = "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991"
	tc.remotePaymentBasePoint, err = pubkeyFromHex(remotePaymentBasePointHex)
	if err != nil {
		err = fmt.Errorf("Failed to parse serialized pubkey: %v", err)
		return
	}

	const fundingChangeAddressStr = "Rs8LovBHZfZmC4ShUicmExNWaivPm5cBtNN"
	tc.fundingChangeAddress, err = dcrutil.DecodeAddress(
		fundingChangeAddressStr)
	if err != nil {
		err = fmt.Errorf("Failed to parse address: %v", err)
		return
	}

	tc.fundingInputUtxo, tc.fundingInputTxOut, err = tc.extractFundingInput()
	if err != nil {
		return
	}

	const fundingTxHex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0300a0724e1809000000001976a9147e4765ae88ba9ad5c9e4715c484e90b34d358d5188ac00a0724e1809000000001976a91402fb1ac0137666d79165e13cecd403883615270788ac00a0724e1809000000001976a91469de627d3231b14228653dd09cba75eeb872754288ac00000000000000000100e057eb481b000000000000ffffffff0800002f646372642f"
	if tc.fundingTx, err = txFromHex(fundingTxHex); err != nil {
		err = fmt.Errorf("Failed to parse serialized tx: %v", err)
		return
	}

	tc.fundingOutpoint = wire.OutPoint{
		Hash:  *tc.fundingTx.Hash(),
		Index: 0,
	}

	tc.shortChanID = lnwire.ShortChannelID{
		BlockHeight: 1,
		TxIndex:     0,
		TxPosition:  0,
	}

	htlcData := []struct {
		incoming bool
		amount   lnwire.MilliAtom
		expiry   uint32
		preimage string
	}{
		{
			incoming: true,
			amount:   1000000,
			expiry:   500,
			preimage: "0000000000000000000000000000000000000000000000000000000000000000",
		},
		{
			incoming: true,
			amount:   2000000,
			expiry:   501,
			preimage: "0101010101010101010101010101010101010101010101010101010101010101",
		},
		{
			incoming: false,
			amount:   2000000,
			expiry:   502,
			preimage: "0202020202020202020202020202020202020202020202020202020202020202",
		},
		{
			incoming: false,
			amount:   3000000,
			expiry:   503,
			preimage: "0303030303030303030303030303030303030303030303030303030303030303",
		},
		{
			incoming: true,
			amount:   4000000,
			expiry:   504,
			preimage: "0404040404040404040404040404040404040404040404040404040404040404",
		},
	}

	tc.htlcs = make([]channeldb.HTLC, len(htlcData))
	for i, htlc := range htlcData {
		preimage, decodeErr := hex.DecodeString(htlc.preimage)
		if decodeErr != nil {
			err = fmt.Errorf("Failed to decode HTLC preimage: %v", decodeErr)
			return
		}

		tc.htlcs[i].RHash = chainhash.HashH(preimage)
		tc.htlcs[i].Amt = htlc.amount
		tc.htlcs[i].RefundTimeout = htlc.expiry
		tc.htlcs[i].Incoming = htlc.incoming
	}

	tc.localCsvDelay = 144
	tc.fundingAmount = 10000000
	tc.dustLimit = 546
	tc.FeePerKB = 15000

	return
}

// createNetParams is used by newTestContext to construct new chain parameters
// as required by the BOLT 03 spec.
func (tc *testContext) createNetParams(genesisHashStr string) (*chaincfg.Params, error) {
	params := chaincfg.RegNetParams

	// Ensure regression net genesis block matches the one listed in BOLT spec.
	expectedGenesisHash, err := chainhash.NewHashFromStr(genesisHashStr)
	if err != nil {
		return nil, err
	}
	if !params.GenesisHash.IsEqual(expectedGenesisHash) {
		err = fmt.Errorf("Expected regression net genesis hash to be %s, "+
			"got %s", expectedGenesisHash, params.GenesisHash)
		return nil, err
	}

	return &params, nil
}

// extractFundingInput returns references to the transaction output of the
// coinbase transaction which is used to fund the channel in the test vectors.
func (tc *testContext) extractFundingInput() (*Utxo, *wire.TxOut, error) {
	expectedTxHashHex := "f94a4d807512f45842661cc7fdefebafd54cbc1338655bccd8e9821d06e402c4"
	expectedTxHash, err := chainhash.NewHashFromStr(expectedTxHashHex)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse transaction hash: %v", err)
	}

	tx, err := tc.block1.Tx(0)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get coinbase transaction from "+
			"block 1: %v", err)
	}
	txout := tx.MsgTx().TxOut[0]

	var expectedAmount int64 = 10000000000000
	if txout.Value != expectedAmount {
		return nil, nil, fmt.Errorf("Coinbase transaction output amount from "+
			"block 1 does not match expected output amount: "+
			"expected %v, got %v", expectedAmount, txout.Value)
	}
	if !tx.Hash().IsEqual(expectedTxHash) {
		return nil, nil, fmt.Errorf("Coinbase transaction hash from block 1 "+
			"does not match expected hash: expected %v, got %v", expectedTxHash,
			tx.Hash())
	}

	block1Utxo := Utxo{
		AddressType: PubKeyHash,
		Value:       dcrutil.Amount(txout.Value),
		OutPoint: wire.OutPoint{
			Hash:  *tx.Hash(),
			Index: 0,
		},
		PkScript: txout.PkScript,
	}
	return &block1Utxo, txout, nil
}

// TestCommitmentAndHTLCTransactions checks the test vectors specified in
// BOLT 03, Appendix C. This deterministically generates commitment and second
// level HTLC transactions and checks that they match the expected values.
func TestCommitmentAndHTLCTransactions(t *testing.T) {
	t.Parallel()

	tc, err := newTestContext()
	if err != nil {
		t.Fatal(err)
	}

	// Generate random some keys that don't actually matter but need to be set.
	var (
		identityKey         *secp256k1.PublicKey
		localDelayBasePoint *secp256k1.PublicKey
	)
	generateKeys := []**secp256k1.PublicKey{
		&identityKey,
		&localDelayBasePoint,
	}
	for _, keyRef := range generateKeys {
		privkey, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("Failed to generate new key: %v", err)
		}
		*keyRef = privkey.PubKey()
	}

	// Manually construct a new LightningChannel.
	channelState := channeldb.OpenChannel{
		ChanType:        channeldb.SingleFunder,
		ChainHash:       *tc.netParams.GenesisHash,
		FundingOutpoint: tc.fundingOutpoint,
		ShortChannelID:  tc.shortChanID,
		IsInitiator:     true,
		IdentityPub:     identityKey,
		LocalChanCfg: channeldb.ChannelConfig{
			ChannelConstraints: channeldb.ChannelConstraints{
				DustLimit:        tc.dustLimit,
				MaxPendingAmount: lnwire.NewMAtomsFromAtoms(tc.fundingAmount),
				MaxAcceptedHtlcs: MaxHTLCNumber,
			},
			CsvDelay: tc.localCsvDelay,
			MultiSigKey: keychain.KeyDescriptor{
				PubKey: tc.localFundingPubKey,
			},
			PaymentBasePoint: keychain.KeyDescriptor{
				PubKey: tc.localPaymentBasePoint,
			},
			HtlcBasePoint: keychain.KeyDescriptor{
				PubKey: tc.localPaymentBasePoint,
			},
			DelayBasePoint: keychain.KeyDescriptor{
				PubKey: localDelayBasePoint,
			},
		},
		RemoteChanCfg: channeldb.ChannelConfig{
			MultiSigKey: keychain.KeyDescriptor{
				PubKey: tc.remoteFundingPubKey,
			},
			PaymentBasePoint: keychain.KeyDescriptor{
				PubKey: tc.remotePaymentBasePoint,
			},
			HtlcBasePoint: keychain.KeyDescriptor{
				PubKey: tc.remotePaymentBasePoint,
			},
		},
		Capacity:           tc.fundingAmount,
		RevocationProducer: shachain.NewRevocationProducer(shachain.ShaHash(zeroHash)),
	}
	signer := &mockSigner{
		privkeys: []*secp256k1.PrivateKey{
			tc.localFundingPrivKey, tc.localPaymentPrivKey,
		},
		netParams: tc.netParams,
	}

	// Construct a LightningChannel manually because we don't have nor need all
	// of the dependencies.
	channel := LightningChannel{
		channelState:  &channelState,
		Signer:        signer,
		localChanCfg:  &channelState.LocalChanCfg,
		remoteChanCfg: &channelState.RemoteChanCfg,
		netParams:     tc.netParams,
	}
	err = channel.createSignDesc()
	if err != nil {
		t.Fatalf("Failed to generate channel sign descriptor: %v", err)
	}
	channel.createStateHintObfuscator()

	// The commitmentPoint is technically hidden in the spec, but we need it to
	// generate the correct tweak.
	tweak := SingleTweakBytes(tc.commitmentPoint, tc.localPaymentBasePoint)
	keys := &CommitmentKeyRing{
		CommitPoint:         tc.commitmentPoint,
		LocalCommitKeyTweak: tweak,
		LocalHtlcKeyTweak:   tweak,
		LocalHtlcKey:        tc.localPaymentPubKey,
		RemoteHtlcKey:       tc.remotePaymentPubKey,
		DelayKey:            tc.localDelayPubKey,
		NoDelayKey:          tc.remotePaymentPubKey,
		RevocationKey:       tc.localRevocationPubKey,
	}

	// testCases encode the raw test vectors specified in Appendix C of BOLT 03.
	// TODO(decred) The stored hex txs need to be reviewed and documented somewhere.
	testCases := []struct {
		commitment              channeldb.ChannelCommitment
		htlcDescs               []htlcDesc
		expectedCommitmentTxHex string
		remoteSigHex            string
	}{
		{ // 0
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  7000000000,
				RemoteBalance: 3000000000,
				FeePerKB:      15000,
			},
			htlcDescs:               []htlcDesc{},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8002c0c62d000000000000001976a914f682e6254058108032264237a8e62b4777400d4e88ac6cba6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd847304402204005c5116474be52f7f40192583d258e771727cf8a6f2f301bc53d7a12bfcd0b0220427ab29fc5807b938a3356f591e1f876ef65f18a2b713de1277f2156c5f3fe68014730440220774e8670eab7b7ded6e37fad1d3ce74ed8278b47a522ddd7a0f5de2aa74519aa02206f628efb5acb9242f6ee725ee3e14eb916f2c9294ff87f439575b1d79441891b01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "30440220774e8670eab7b7ded6e37fad1d3ce74ed8278b47a522ddd7a0f5de2aa74519aa02206f628efb5acb9242f6ee725ee3e14eb916f2c9294ff87f439575b1d79441891b",
		},
		{ // 1
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKB:      0,
			},
			htlcDescs: []htlcDesc{
				{ // 1,0
					index:           0,
					remoteSigHex:    "304402206a6e59f18764a5bf8d4fa45eebc591566689441229c918b480fb2af8cc6a4aeb02205248f273be447684b33e3c8d1d85a8e0ca9fa0bae9ae33f0527ada9c162919a6",
					resolutionTxHex: "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219700000000000000000001e8030000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402206a6e59f18764a5bf8d4fa45eebc591566689441229c918b480fb2af8cc6a4aeb02205248f273be447684b33e3c8d1d85a8e0ca9fa0bae9ae33f0527ada9c162919a60147304402207cb324fa0de88f452ffa9389678127ebcf4cabe1dd848b8e076c1a1962bf34720220116ed922b12311bd602d67e60d2529917f21c5b82f25ff6506c0f87886b4dfd5012000000000000000000000000000000000000000000000000000000000000000008a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac686800000000",
				},
				{ // 1,2
					index:           2,
					remoteSigHex:    "30450221009010439ca613d7e24f4ee82f3e2de2b02daa95cae7e63fb6255572d8bf3345ea02204e0fe4e5e21a513f6f67a18d4128487f2c69c7efaf4ddf6125e0040a84fbacd4",
					resolutionTxHex: "0200000001ba8a5940075cddfb4984716cb93d4363b9aa982cb556c11af1e23fff64e90c7a01000000000000000001d007000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f6010000000000000100000000000000000000000000000000fd19014830450221009010439ca613d7e24f4ee82f3e2de2b02daa95cae7e63fb6255572d8bf3345ea02204e0fe4e5e21a513f6f67a18d4128487f2c69c7efaf4ddf6125e0040a84fbacd401473044022070e41fd56597f83c25790d5aa65b30989625dc80bf6282363d9044977c02d32202202a21093548afa85b857390b1e32b0dbc922f9fd52aa32f3eafd45b2a486eb66201004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac6721034ac695f3269d836cd00072a088a9109d83609e6e69955bcf415acda0179b6ed97c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914dfd1c066155d9a82067f199d093e96903abee2ec88ac6868",
				},
				{ // 1,1
					index:           1,
					remoteSigHex:    "304402201b63ec807771baf4fdff523c644080de17f1da478989308ad13a58b51db91d360220568939d38c9ce295adba15665fa68f51d967e8ed14a007b751540a80b325f202",
					resolutionTxHex: "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219702000000000000000001d0070000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402201b63ec807771baf4fdff523c644080de17f1da478989308ad13a58b51db91d360220568939d38c9ce295adba15665fa68f51d967e8ed14a007b751540a80b325f20201483045022100def389deab09cee69eaa1ec14d9428770e45bcbe9feb46468ecf481371165c2f022015d2e3c46600b2ebba8dcc899768874cc6851fd1ecb3fffd15db1cc3de7e10da012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000",
				},
				{ // 1,3
					index:           3,
					remoteSigHex:    "3045022100c57ed8dc841261c08f3226942ab2b1b34b07cef0ee9bcc125124341fc36f96a402200889fc9c6edfeaa91b6508fec11fe15673e3e341d0a0a2114f00be1af38a4658",
					resolutionTxHex: "0200000001ba8a5940075cddfb4984716cb93d4363b9aa982cb556c11af1e23fff64e90c7a03000000000000000001b80b000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd1901483045022100c57ed8dc841261c08f3226942ab2b1b34b07cef0ee9bcc125124341fc36f96a402200889fc9c6edfeaa91b6508fec11fe15673e3e341d0a0a2114f00be1af38a4658014730440220152d749d3218469d13564d993b0623d5243e8d2417ca31061a589a6b3c60c7b60220209c47e905342455bb89a2f38ac9c2e6807f79632f35081341e2139aeb941edf01004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac6721034ac695f3269d836cd00072a088a9109d83609e6e69955bcf415acda0179b6ed97c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868",
				},
				{ // 1,4
					index:           4,
					remoteSigHex:    "304402207e0410e45454b0978a623f36a10626ef17b27d9ad44e2760f98cfa3efb37924f0220220bd8acd43ecaa916a80bd4f919c495a2c58982ce7c8625153f8596692a801d",
					resolutionTxHex: "020000000001018154ecccf11a5fb56c39654c4deb4d2296f83c69268280b94d021370c94e219704000000000000000001a00f0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402207e0410e45454b0978a623f36a10626ef17b27d9ad44e2760f98cfa3efb37924f0220220bd8acd43ecaa916a80bd4f919c495a2c58982ce7c8625153f8596692a801d014730440220549e80b4496803cbc4a1d09d46df50109f546d43fbbf86cd90b174b1484acd5402205f12a4f995cb9bded597eabfee195a285986aa6d93ae5bb72507ebc6a4e2349e012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8007e803000000000000000017a9140faf692a8f365e68f0666007225544132b84144687d007000000000000000017a9140a3842d32acc80c37dc7f1db7178b9296a82fcff87d007000000000000000017a9140fe4df1a510ea44f1549f89be7905711e7cbff6c87b80b000000000000000017a9140a06ff784e8fd539ec17caa27edbe3520289d2c787a00f000000000000000017a914c07cabde46d487782573d1f6790f7e8c8b353d6087c0c62d000000000000001976a914f682e6254058108032264237a8e62b4777400d4e88ace0a06a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffda483045022100e3114b7c982d551b43c51f9d04801cd3232b4b3947fd99d28e7be0d372c14d22022043f0a9225b6985132c753963b6cc8aa1e21d4bb9448e4d3a4af7c38022049c30014830450221008bf7db5a0f420b8d10e805e4264cd08582529268e610c548de7c918e78c972230220031cbd6174e6337bdc7f22c6de82d1636e073d6cb25814fc8420e03d8c6ab02e01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "30450221008bf7db5a0f420b8d10e805e4264cd08582529268e610c548de7c918e78c972230220031cbd6174e6337bdc7f22c6de82d1636e073d6cb25814fc8420e03d8c6ab02e",
		},
		{ // 2
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKB:      647,
			},
			htlcDescs: []htlcDesc{
				{ // 2,0
					index:           0,
					remoteSigHex:    "30440220385a5afe75632f50128cbb029ee95c80156b5b4744beddc729ad339c9ca432c802202ba5f48550cad3379ac75b9b4fedb86a35baa6947f16ba5037fb8b11ab343740",
					resolutionTxHex: "020000000001018323148ce2419f21ca3d6780053747715832e18ac780931a514b187768882bb60000000000000000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220385a5afe75632f50128cbb029ee95c80156b5b4744beddc729ad339c9ca432c802202ba5f48550cad3379ac75b9b4fedb86a35baa6947f16ba5037fb8b11ab3437400147304402205999590b8a79fa346e003a68fd40366397119b2b0cdf37b149968d6bc6fbcc4702202b1e1fb5ab7864931caed4e732c359e0fe3d86a548b557be2246efb1708d579a012000000000000000000000000000000000000000000000000000000000000000008a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac686800000000",
				},
				{ // 2,1
					index:           2,
					remoteSigHex:    "3045022100e96f299ee8e605687ef7348b6cf9295d4e9ef2e20fb2473c14cab44f311742cc022053a24341b0856f5c467e560ef7ed83e0aa689d47aedbc24a04fc2636c553e796",
					resolutionTxHex: "0200000001db809e7bcd6e6a41ed4a74cc6a746fb3aec7b89a3a581b3a1a30fee4562313c501000000000000000001d306000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f6010000000000000100000000000000000000000000000000fd1a01483045022100e96f299ee8e605687ef7348b6cf9295d4e9ef2e20fb2473c14cab44f311742cc022053a24341b0856f5c467e560ef7ed83e0aa689d47aedbc24a04fc2636c553e7960148304502210081407b282fc0979a669bdb98729c44fdeeabda8eb34d50cd4b5061b128b485f702206a26d87ef32b930a6ad0ddb67d9c6f9981abd9a25a0a143c8561fdde2746838b01004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac6721034ac695f3269d836cd00072a088a9109d83609e6e69955bcf415acda0179b6ed97c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914dfd1c066155d9a82067f199d093e96903abee2ec88ac6868",
				},
				{ // 2,2
					index:           1,
					remoteSigHex:    "304402206a401b29a0dff0d18ec903502c13d83e7ec019450113f4a7655a4ce40d1f65ba0220217723a084e727b6ca0cc8b6c69c014a7e4a01fcdcba3e3993f462a3c574d833",
					resolutionTxHex: "020000000001018323148ce2419f21ca3d6780053747715832e18ac780931a514b187768882bb6020000000000000000010a060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402206a401b29a0dff0d18ec903502c13d83e7ec019450113f4a7655a4ce40d1f65ba0220217723a084e727b6ca0cc8b6c69c014a7e4a01fcdcba3e3993f462a3c574d83301483045022100d50d067ca625d54e62df533a8f9291736678d0b86c28a61bb2a80cf42e702d6e02202373dde7e00218eacdafb9415fe0e1071beec1857d1af3c6a201a44cbc47c877012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000",
				},
				{ // 2,3
					index:           3,
					remoteSigHex:    "3045022100ce156403e4508f97b0bb429e92409351537f53cdc49fbe6866e1ba6906474721022064a789c1d5d066d851a589404fb4c0f09297b115ab5b6ab0fa1879d91d6b3ce1",
					resolutionTxHex: "0200000001db809e7bcd6e6a41ed4a74cc6a746fb3aec7b89a3a581b3a1a30fee4562313c503000000000000000001bb0a000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd1a01483045022100ce156403e4508f97b0bb429e92409351537f53cdc49fbe6866e1ba6906474721022064a789c1d5d066d851a589404fb4c0f09297b115ab5b6ab0fa1879d91d6b3ce1014830450221008d03e6c51f91fe775a219b66cda503c48a1216783529ed1fbcf72e32d554983702205c52ceb5d6f1a86a48bce0d2c82752d1327430aa86f999b2144f2e53ad75e67901004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac6721034ac695f3269d836cd00072a088a9109d83609e6e69955bcf415acda0179b6ed97c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868",
				},
				{ // 2,4
					index:           4,
					remoteSigHex:    "3045022100cc28030b59f0914f45b84caa983b6f8effa900c952310708c2b5b00781117022022027ba2ccdf94d03c6d48b327f183f6e28c8a214d089b9227f94ac4f85315274f0",
					resolutionTxHex: "020000000001018323148ce2419f21ca3d6780053747715832e18ac780931a514b187768882bb604000000000000000001da0d0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100cc28030b59f0914f45b84caa983b6f8effa900c952310708c2b5b00781117022022027ba2ccdf94d03c6d48b327f183f6e28c8a214d089b9227f94ac4f85315274f00147304402202d1a3c0d31200265d2a2def2753ead4959ae20b4083e19553acfffa5dfab60bf022020ede134149504e15b88ab261a066de49848411e15e70f9e6a5462aec2949f8f012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8007e803000000000000000017a9140faf692a8f365e68f0666007225544132b84144687d007000000000000000017a9140a3842d32acc80c37dc7f1db7178b9296a82fcff87d007000000000000000017a9140fe4df1a510ea44f1549f89be7905711e7cbff6c87b80b000000000000000017a9140a06ff784e8fd539ec17caa27edbe3520289d2c787a00f000000000000000017a914c07cabde46d487782573d1f6790f7e8c8b353d6087c0c62d000000000000001976a914f682e6254058108032264237a8e62b4777400d4e88ac879f6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd8463043021f5af8804f612594cea4f7fd86cc95d431c7765328c8c79f1bba278efb5b7e20022050024b0d17b15ad6502da373feb51c8d480d79b4c90a9aaa3a5e8862834338c801483045022100cda40aeb45493b95d5cd4d31271e440b1bbac9cba7caad8617657734a4a4dd4f02203db6ba502e6298753526a95fdb89ed175f2f6da647a0c1edfb36ae078a0ba5d001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "3045022100cda40aeb45493b95d5cd4d31271e440b1bbac9cba7caad8617657734a4a4dd4f02203db6ba502e6298753526a95fdb89ed175f2f6da647a0c1edfb36ae078a0ba5d0",
		},
		{ // 3
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKB:      648,
			},
			htlcDescs: []htlcDesc{
				{ // 3,0
					index:           2,
					remoteSigHex:    "30440220316a13956a8db65844ee241743c9c81b0227eda32232ad453bb3d90e4b942ec802200a251eabfd788859e5c9a0bc70e8738e5010c882cb55ce0420d44b6672e7109c",
					resolutionTxHex: "02000000019c5f29a38561fa36e3be8a8f36e84ba325fb4026db7dca88ba730798222e1f0600000000000000000001d206000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f6010000000000000100000000000000000000000000000000fd19014730440220316a13956a8db65844ee241743c9c81b0227eda32232ad453bb3d90e4b942ec802200a251eabfd788859e5c9a0bc70e8738e5010c882cb55ce0420d44b6672e7109c01483045022100e280b6f6578dc3c8d3e4aeb156d5b6d699d9e5f95e0f85f9398570e40e32f70a0220742c7390f2cd1e68aab92025e930ff3c6d20cab45cf7ddd436626bbd3b70c9b701004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac6721034ac695f3269d836cd00072a088a9109d83609e6e69955bcf415acda0179b6ed97c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914dfd1c066155d9a82067f199d093e96903abee2ec88ac6868",
				},
				{ // 3,1
					index:           1,
					remoteSigHex:    "3045022100e968cbbb5f402ed389fdc7f6cd2a80ed650bb42c79aeb2a5678444af94f6c78502204b47a1cb24ab5b0b6fe69fe9cfc7dba07b9dd0d8b95f372c1d9435146a88f8d4",
					resolutionTxHex: "02000000000101579c183eca9e8236a5d7f5dcd79cfec32c497fdc0ec61533cde99ecd436cadd10100000000000000000109060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100e968cbbb5f402ed389fdc7f6cd2a80ed650bb42c79aeb2a5678444af94f6c78502204b47a1cb24ab5b0b6fe69fe9cfc7dba07b9dd0d8b95f372c1d9435146a88f8d40147304402207679cf19790bea76a733d2fa0672bd43ab455687a068f815a3d237581f57139a0220683a1a799e102071c206b207735ca80f627ab83d6616b4bcd017c5d79ef3e7d0012001010101010101010101010101010101010101010101010101010101010101018a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac686800000000",
				},
				{ // 3,2
					index:           3,
					remoteSigHex:    "3045022100ce53433839f6b410de3353564a9e6b920b8aed6316e2a00e1d84b42d82572e11022067bbce4e60ec39615f5656bb28cc39228b5b735286831bad326b8e0ce49b0371",
					resolutionTxHex: "02000000019c5f29a38561fa36e3be8a8f36e84ba325fb4026db7dca88ba730798222e1f0602000000000000000001ba0a000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd1a01483045022100ce53433839f6b410de3353564a9e6b920b8aed6316e2a00e1d84b42d82572e11022067bbce4e60ec39615f5656bb28cc39228b5b735286831bad326b8e0ce49b037101483045022100dab3ac287b84105fac30d367ad3a47aed95f055c606466b00978922f39b1a150022042c4cd775f2a6a60a8412ff2f1c509165b2e46215bccec2034f4887500e4009901004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac6721034ac695f3269d836cd00072a088a9109d83609e6e69955bcf415acda0179b6ed97c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868",
				},
				{ // 3,3
					index:           4,
					remoteSigHex:    "3044022035cac88040a5bba420b1c4257235d5015309113460bc33f2853cd81ca36e632402202fc94fd3e81e9d34a9d01782a0284f3044370d03d60f3fc041e2da088d2de58f",
					resolutionTxHex: "02000000000101579c183eca9e8236a5d7f5dcd79cfec32c497fdc0ec61533cde99ecd436cadd103000000000000000001d90d0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022035cac88040a5bba420b1c4257235d5015309113460bc33f2853cd81ca36e632402202fc94fd3e81e9d34a9d01782a0284f3044370d03d60f3fc041e2da088d2de58f0147304402200daf2eb7afd355b4caf6fb08387b5f031940ea29d1a9f35071288a839c9039e4022067201b562456e7948616c13acb876b386b511599b58ac1d94d127f91c50463a6012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8006d007000000000000000017a9140a3842d32acc80c37dc7f1db7178b9296a82fcff87d007000000000000000017a9140fe4df1a510ea44f1549f89be7905711e7cbff6c87b80b000000000000000017a9140a06ff784e8fd539ec17caa27edbe3520289d2c787a00f000000000000000017a914c07cabde46d487782573d1f6790f7e8c8b353d6087c0c62d000000000000001976a914f682e6254058108032264237a8e62b4777400d4e88ac9c9f6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd947304402200d0b769068793336a7a35f175f32d687cf4cf4b250f2794e7ebfb77a15dd8b8902201957e8c257552535414e78fd04909832ade8553aabdbc7ddacec0ea5764f10e0014830450221008277afd270807a9a2a539e9cc175da1d62abe9016947ec360118cca1066abc8902200e12b0b2362cb589945cb4b92d721f94b91dc498292e755f751905dabe0fbc9501475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "30450221008277afd270807a9a2a539e9cc175da1d62abe9016947ec360118cca1066abc8902200e12b0b2362cb589945cb4b92d721f94b91dc498292e755f751905dabe0fbc95",
		},
		{ // 4
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKB:      2069,
			},
			htlcDescs: []htlcDesc{
				{ // 4,0
					index:           2,
					remoteSigHex:    "304402201862a6d4e965ea0163b6b863a59b56bc4e8afc75914ac03e8dd21b2a5077049c02204b53b2c23a9d99ff8b150ed44d9f0c9257d01cfaaa35420436a4b9229742e90d",
					resolutionTxHex: "020000000108724b58ec47dd8bdf1c2bbeb631506676c444c379453a69364a7029a879b88500000000000000000001a504000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f6010000000000000100000000000000000000000000000000fd180147304402201862a6d4e965ea0163b6b863a59b56bc4e8afc75914ac03e8dd21b2a5077049c02204b53b2c23a9d99ff8b150ed44d9f0c9257d01cfaaa35420436a4b9229742e90d0147304402206edc444a6d7616321cdc3652d2567477f7358c11c438ae063111f90b47bfef7a02205ab52360caacadc003e78e48ff3ce2b215b666f842f96c857b89996f1e62f93901004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac6721034ac695f3269d836cd00072a088a9109d83609e6e69955bcf415acda0179b6ed97c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914dfd1c066155d9a82067f199d093e96903abee2ec88ac6868",
				},
				{ // 4,1
					index:           1,
					remoteSigHex:    "3045022100d065569dcb94f090345402736385efeb8ea265131804beac06dd84d15dd2d6880220664feb0b4b2eb985fadb6ec7dc58c9334ea88ce599a9be760554a2d4b3b5d9f4",
					resolutionTxHex: "0200000001cdd89ae2becc198085cbe354f957cbfaef88f86990a6dd3ddc7a2ce0cbb3461d010000000000000000018b0800000000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80ef7010000000000000100000000000000000000000000000000fd1801473044022071e9357619fd8d29a411dc053b326a5224c5d11268070e88ecb981b174747c7a02202b763ae29a9d0732fa8836dd8597439460b50472183f420021b768981b4f7cf601473044022055ced5fb769834f73eee4c3eb5f42c2ee95af231be81ae8be4e7f10ce239f2ca022020537289328cd497ff6f8f59015d24bda936e62ed1c8f9dc331aefd190a5fbcb01004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868",
				},
				{ // 4,2
					index:           3,
					remoteSigHex:    "3044022031f7341f95d40f80e8330442307dddeaa13a1c89d133d388beaabc30857fb49302204f36c9c149cfc4d65939edf503224e9078c593a87ade06ae4bbd1df4df83e3fd",
					resolutionTxHex: "020000000108724b58ec47dd8bdf1c2bbeb631506676c444c379453a69364a7029a879b885020000000000000000018d08000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd1901473044022031f7341f95d40f80e8330442307dddeaa13a1c89d133d388beaabc30857fb49302204f36c9c149cfc4d65939edf503224e9078c593a87ade06ae4bbd1df4df83e3fd01483045022100f53864388b315576da7da92db52221d209f9245478613c90d5575c997619774a0220310db4b1c2d330d389ac0b47f53698ef5ce8bed1d9a78ae8f83700646fd50c8101004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac6721034ac695f3269d836cd00072a088a9109d83609e6e69955bcf415acda0179b6ed97c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868"},
				{ // 4,3
					index:           4,
					remoteSigHex:    "30450221008ec888e36e4a4b3dc2ed6b823319855b2ae03006ca6ae0d9aa7e24bfc1d6f07102203b0f78885472a67ff4fe5916c0bb669487d659527509516fc3a08e87a2cc0a7c",
					resolutionTxHex: "02000000000101ca94a9ad516ebc0c4bdd7b6254871babfa978d5accafb554214137d398bfcf6a03000000000000000001f2090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004830450221008ec888e36e4a4b3dc2ed6b823319855b2ae03006ca6ae0d9aa7e24bfc1d6f07102203b0f78885472a67ff4fe5916c0bb669487d659527509516fc3a08e87a2cc0a7c0147304402202c3e14282b84b02705dfd00a6da396c9fe8a8bcb1d3fdb4b20a4feba09440e8b02202b058b39aa9b0c865b22095edcd9ff1f71bbfe20aa4993755e54d042755ed0d5012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8006d007000000000000000017a9140a3842d32acc80c37dc7f1db7178b9296a82fcff87d007000000000000000017a9140fe4df1a510ea44f1549f89be7905711e7cbff6c87b80b000000000000000017a9140a06ff784e8fd539ec17caa27edbe3520289d2c787a00f000000000000000017a914c07cabde46d487782573d1f6790f7e8c8b353d6087c0c62d000000000000001976a914f682e6254058108032264237a8e62b4777400d4e88acd69c6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd947304402200d4096c1bcc68239943d776815c660f979ba98822b40535815280f6d51b771ac02207994c8b119071a814d623fc528ada1ad49a369fd4b014ec00add68dfe765d25801483045022100fc675bd299563bdd398603d60518b4bd3b2ff5a375cbbadf0ce89b6afdde71c902202a911e7a340655694725c8b0f6c8e40798d029bc87af82a8d70d1b0b85d787d301475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "3045022100fc675bd299563bdd398603d60518b4bd3b2ff5a375cbbadf0ce89b6afdde71c902202a911e7a340655694725c8b0f6c8e40798d029bc87af82a8d70d1b0b85d787d3",
		},
		{ // 5
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKB:      2070,
			},
			htlcDescs: []htlcDesc{
				{ // 5,0
					index:           2,
					remoteSigHex:    "3045022100d2002152822951c4a854504e10128a088bd0e3493f466938ce62b8394837fed702203557d0f032640ce81177b8d494961fbe9d57acf6a8e7ce66e89b436afe673d99",
					resolutionTxHex: "02000000010652aa47d6f7c7eab4dfe9689bb4d62cf4de5460d5c54c395971c771ceda53ca00000000000000000001a504000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f6010000000000000100000000000000000000000000000000fd1901483045022100d2002152822951c4a854504e10128a088bd0e3493f466938ce62b8394837fed702203557d0f032640ce81177b8d494961fbe9d57acf6a8e7ce66e89b436afe673d9901473044022058ab162b9b0b8c0abc0dc9280e2e83287d1076713bf7c6be4666ea066fed84ef02205e9e423690c12e45c1f20bd99170ec6e7c29b27fc463e13e1827473cdb23737801004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac6721034ac695f3269d836cd00072a088a9109d83609e6e69955bcf415acda0179b6ed97c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914dfd1c066155d9a82067f199d093e96903abee2ec88ac6868"},
				{ // 5,1
					index:           3,
					remoteSigHex:    "3045022100a7dd113fc5255380ce8feeba3b23595b1b655352fdf656e01c6e149b7d29801202205a922957b1f23a4b61785f4c57335704ba37c518bd0e876a39ccd674205cbab4",
					resolutionTxHex: "02000000010652aa47d6f7c7eab4dfe9689bb4d62cf4de5460d5c54c395971c771ceda53ca010000000000000000018d08000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd1a01483045022100a7dd113fc5255380ce8feeba3b23595b1b655352fdf656e01c6e149b7d29801202205a922957b1f23a4b61785f4c57335704ba37c518bd0e876a39ccd674205cbab401483045022100da4ca05eeb57096bf2d71df7744b7abf8d6a69eb9616ad9477b844cda85a85c102203f2bf8d15382f7793d02101169b4bb236fe1a9ba59baf64b2aee8b182488e4c701004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac6721034ac695f3269d836cd00072a088a9109d83609e6e69955bcf415acda0179b6ed97c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868"},
				{ // 5,2
					index:           4,
					remoteSigHex:    "3045022100c9458a4d2cbb741705577deb0a890e5cb90ee141be0400d3162e533727c9cb2102206edcf765c5dc5e5f9b976ea8149bf8607b5a0efb30691138e1231302b640d2a4",
					resolutionTxHex: "020000000112b0f746ca4c74cd579424e3110a8e75e1e00a24f4f37eb5cbc3bfdb9a83944d020000000000000000018b0800000000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80ef7010000000000000100000000000000000000000000000000fd1901483045022100d4e69d363de993684eae7b37853c40722a4c1b4a7b588ad7b5d8a9b5006137a102207a069c628170ee34be5612747051bdcc087466dbaa68d5756ea81c10155aef180147304402200405a71afc1e023e501c390770e4859e84601986975293fbdae165224a2a2f4802206a88efb0fa687a0372155bc1d1c9feddf11c1fc9b25751326973079090e29cc401004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6868",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8005d007000000000000000017a9140a3842d32acc80c37dc7f1db7178b9296a82fcff87b80b000000000000000017a9140a06ff784e8fd539ec17caa27edbe3520289d2c787a00f000000000000000017a914c07cabde46d487782573d1f6790f7e8c8b353d6087c0c62d000000000000001976a914f682e6254058108032264237a8e62b4777400d4e88ac1c9d6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd9483045022100f4f11fa79902083132207d6bb386b8f30c8501f51909d68bb4c43a9d424bcb8502203eb082c239c91da0a4e08efd9f6594c9a580e945f46ae04aecd0e35d63da88e20147304402203a45943e6028770420c0a5defce25387bf11a6bb69dec254a41bf1a6c7c1b45502203d8f4fcfa6076a7154ff8a647b56b32071b14dba900baeb1204ba7a9a32ffac301475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "304402203a45943e6028770420c0a5defce25387bf11a6bb69dec254a41bf1a6c7c1b45502203d8f4fcfa6076a7154ff8a647b56b32071b14dba900baeb1204ba7a9a32ffac3",
		},
		{ // 6
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKB:      2194,
			},
			htlcDescs: []htlcDesc{
				{ // 6,0
					index:           2,
					remoteSigHex:    "3045022100da5eda57b7f768c44067b7b903314667b58c4c21ea8a8b0ab085080d6f78c3650220751a93624fc7300ab9eefe8ce40bb38f08f9fdcb7481c0fca14295aa985ac2d8",
					resolutionTxHex: "0200000001b2776623ab5361b28b15619b65b449de79ec4c70a0a63b97c4abcccdcce13bf7000000000000000000017404000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f6010000000000000100000000000000000000000000000000fd1901483045022100da5eda57b7f768c44067b7b903314667b58c4c21ea8a8b0ab085080d6f78c3650220751a93624fc7300ab9eefe8ce40bb38f08f9fdcb7481c0fca14295aa985ac2d80147304402203009b65f4832f91caba31f09c6178045be175534b34959076bf3e69e30f9805c02204519c6299ffb988f9433cb171bfbdaa5a244bef204c37d2aa34eadb2bd8b89df01004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac6721034ac695f3269d836cd00072a088a9109d83609e6e69955bcf415acda0179b6ed97c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914dfd1c066155d9a82067f199d093e96903abee2ec88ac6868"},
				{ // 6,1
					index:           3,
					remoteSigHex:    "3045022100c3d2b1d19fa3216f974cf03d69783fa1273550ce6fb8858a8f51920f5ca5fd7302206551282eaf8fb2b5c0c8648facc0c715137e4cee0600cc1efa3400f31e8105cc",
					resolutionTxHex: "0200000001b2776623ab5361b28b15619b65b449de79ec4c70a0a63b97c4abcccdcce13bf7010000000000000000015c08000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd1a01483045022100c3d2b1d19fa3216f974cf03d69783fa1273550ce6fb8858a8f51920f5ca5fd7302206551282eaf8fb2b5c0c8648facc0c715137e4cee0600cc1efa3400f31e8105cc01483045022100cb441ce8689edf7c1352f5137c09441751fce241ad0710ff54a629c832f27994022040dd45d67bd5c0e7e469cbe4bdcdf8f4d92a3e2d54c75c080488a88ac1af5c5601004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac6721034ac695f3269d836cd00072a088a9109d83609e6e69955bcf415acda0179b6ed97c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868"},
				{ // 6,2
					index:           4,
					remoteSigHex:    "3045022100a12a9a473ece548584aabdd051779025a5ed4077c4b7aa376ec7a0b1645e5a48022039490b333f53b5b3e2ddde1d809e492cba2b3e5fc3a436cd3ffb4cd3d500fa5a",
					resolutionTxHex: "02000000000101fb824d4e4dafc0f567789dee3a6bce8d411fe80f5563d8cdfdcc7d7e4447d43a020000000000000000019a090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100a12a9a473ece548584aabdd051779025a5ed4077c4b7aa376ec7a0b1645e5a48022039490b333f53b5b3e2ddde1d809e492cba2b3e5fc3a436cd3ffb4cd3d500fa5a01483045022100ff200bc934ab26ce9a559e998ceb0aee53bc40368e114ab9d3054d9960546e2802202496856ca163ac12c143110b6b3ac9d598df7254f2e17b3b94c3ab5301f4c3b0012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8005d007000000000000000017a9140a3842d32acc80c37dc7f1db7178b9296a82fcff87b80b000000000000000017a9140a06ff784e8fd539ec17caa27edbe3520289d2c787a00f000000000000000017a914c07cabde46d487782573d1f6790f7e8c8b353d6087c0c62d000000000000001976a914f682e6254058108032264237a8e62b4777400d4e88ace29c6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd947304402207caa318e519e0afe053da95135ef4dfb7a6464225615de5bb21b9507541f6165022012d96e3a7ad840cd97ea003883c5fb780d6262868850c30a3b11caa0fe111ae601483045022100a29f91f5b13ac1e92ec33d48b1f98302ade53572cce8734b2dab95ea86920cd80220217054e4b573be2089d810313f22344944bc81658d78bedc0b080c1b88dc168b01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "3045022100a29f91f5b13ac1e92ec33d48b1f98302ade53572cce8734b2dab95ea86920cd80220217054e4b573be2089d810313f22344944bc81658d78bedc0b080c1b88dc168b",
		},
		{ // 7
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKB:      2195,
			},
			htlcDescs: []htlcDesc{
				{ // 7,0
					index:           3,
					remoteSigHex:    "3045022100bb4f2853e9991f326b5370a28b5e7967a89fc7116fc2f65be9ffb2d8162576210220648f9cdd76e65d5a9dca4c36e2e02f811fd05b8e97cfba5404294cd07e4d54b4",
					resolutionTxHex: "0200000001b75b1cbe876247e196ac6cf8bff879f2d0e7ff322e79b920ced3461590c74d0f000000000000000000015c08000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd1a01483045022100bb4f2853e9991f326b5370a28b5e7967a89fc7116fc2f65be9ffb2d8162576210220648f9cdd76e65d5a9dca4c36e2e02f811fd05b8e97cfba5404294cd07e4d54b401483045022100d58d5c5f00fe3453cdec17bfe87b1839dba68e0eadfc09e8a59bb74bdb807a92022054e7900acb9f2ae5765439278a6408e67e6c194a8cd240ffc79278f97c0e9d4a01004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac6721034ac695f3269d836cd00072a088a9109d83609e6e69955bcf415acda0179b6ed97c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868"},
				{ // 7,1
					index:           4,
					remoteSigHex:    "3045022100e769cb156aa2f7515d126cef7a69968629620ce82afcaa9e210969de6850df4602200b16b3f3486a229a48aadde520dbee31ae340dbadaffae74fbb56681fef27b92",
					resolutionTxHex: "020000000001014e16c488fa158431c1a82e8f661240ec0a71ba0ce92f2721a6538c510226ad5c0100000000000000000199090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100e769cb156aa2f7515d126cef7a69968629620ce82afcaa9e210969de6850df4602200b16b3f3486a229a48aadde520dbee31ae340dbadaffae74fbb56681fef27b92014730440220665b9cb4a978c09d1ca8977a534999bc8a49da624d0c5439451dd69cde1a003d022070eae0620f01f3c1bd029cc1488da13fb40fdab76f396ccd335479a11c5276d8012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8004b80b000000000000000017a9140a06ff784e8fd539ec17caa27edbe3520289d2c787a00f000000000000000017a914c07cabde46d487782573d1f6790f7e8c8b353d6087c0c62d000000000000001976a914f682e6254058108032264237a8e62b4777400d4e88ac2c9d6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffda483045022100fbc94f2cae5577c29fc43346c8e7c03534c49e681be45bebc2cacd0def476ae50220381d5aae828094e289ce93bfb58403a3a488b8f9cfab2368fa6ee9b4ee85d073014830450221009345f7415146f1d02ff2b1479f48f3ec983e3626a0e3a4fc93b70011d23c93bb02207da5d0e96e2ea931fbf0eef2754e4ba2d58993daebd1290976f570ac3257af8b01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "30450221009345f7415146f1d02ff2b1479f48f3ec983e3626a0e3a4fc93b70011d23c93bb02207da5d0e96e2ea931fbf0eef2754e4ba2d58993daebd1290976f570ac3257af8b",
		},
		{ // 8
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKB:      3702,
			},
			htlcDescs: []htlcDesc{
				{ // 8,0
					index:           3,
					remoteSigHex:    "304402204d4658fe23b5bfdc19f3278ffd9e24503ffffa19ddfa3b26ef4deb7b36973f1102201cd2709c4ecbb413be73ff0664499d227880ccb1d4f4456cfb9339c0fa88a4bb",
					resolutionTxHex: "0200000001e7e04648649b8740a961988cf76217c3d9e3499c930e38f26801667a3de0aeed000000000000000000010d06000000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda087f7010000000000000100000000000000000000000000000000fd190147304402204d4658fe23b5bfdc19f3278ffd9e24503ffffa19ddfa3b26ef4deb7b36973f1102201cd2709c4ecbb413be73ff0664499d227880ccb1d4f4456cfb9339c0fa88a4bb01483045022100c04a2c0dd1b6893351e8aeaff302d244dfca8ef745471df7d686a494f4366d9102202edd836d6c391543c7f213ba7e4f37baa5721ec6dea52196e0d772d7a26dcfa301004c8576a914f06a2ee4f3cc96a8b6963e14c601fef5ee3de3ce8763ac6721034ac695f3269d836cd00072a088a9109d83609e6e69955bcf415acda0179b6ed97c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a91489aa86712b33657a8424f45cd9e81e31ab022f1c88ac6868"},
				{ // 8,1
					index:           4,
					remoteSigHex:    "3045022100ea9dc2a7c3c3640334dab733bb4e036e32a3106dc707b24227874fa4f7da746802204d672f7ac0fe765931a8df10b81e53a3242dd32bd9dc9331eb4a596da87954e9",
					resolutionTxHex: "02000000000101b8de11eb51c22498fe39722c7227b6e55ff1a94146cf638458cb9bc6a060d3a30100000000000000000176050000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100ea9dc2a7c3c3640334dab733bb4e036e32a3106dc707b24227874fa4f7da746802204d672f7ac0fe765931a8df10b81e53a3242dd32bd9dc9331eb4a596da87954e9014730440220048a41c660c4841693de037d00a407810389f4574b3286afb7bc392a438fa3f802200401d71fa87c64fe621b49ac07e3bf85157ac680acb977124da28652cc7f1a5c012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8004b80b000000000000000017a9140a06ff784e8fd539ec17caa27edbe3520289d2c787a00f000000000000000017a914c07cabde46d487782573d1f6790f7e8c8b353d6087c0c62d000000000000001976a914f682e6254058108032264237a8e62b4777400d4e88aca19a6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffda483045022100ac934981fd9b79916f3c80ac59cf12e2b9d2ef87eca2ede850680ada5a10851202205d0da496745aeb334dd6eea0ff00d551434bbd75a8b707296a6923083f47935301483045022100de1627cb8ebd4c63460db607d50a80de561575e36e769361c74397edd208948802203c75b55a04e2cd062e8a0e602201232c28c31a1243d814263ed229710b14a3f301475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "3045022100de1627cb8ebd4c63460db607d50a80de561575e36e769361c74397edd208948802203c75b55a04e2cd062e8a0e602201232c28c31a1243d814263ed229710b14a3f3",
		},
		{ // 9
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKB:      3703,
			},
			htlcDescs: []htlcDesc{
				{ // 9,0
					index:           4,
					remoteSigHex:    "3044022044f65cf833afdcb9d18795ca93f7230005777662539815b8a601eeb3e57129a902206a4bf3e53392affbba52640627defa8dc8af61c958c9e827b2798ab45828abdd",
					resolutionTxHex: "020000000001011c076aa7fb3d7460d10df69432c904227ea84bbf3134d4ceee5fb0f135ef206d0000000000000000000175050000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022044f65cf833afdcb9d18795ca93f7230005777662539815b8a601eeb3e57129a902206a4bf3e53392affbba52640627defa8dc8af61c958c9e827b2798ab45828abdd01483045022100b94d931a811b32eeb885c28ddcf999ae1981893b21dd1329929543fe87ce793002206370107fdd151c5f2384f9ceb71b3107c69c74c8ed5a28a94a4ab2d27d3b0724012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8003a00f000000000000000017a914c07cabde46d487782573d1f6790f7e8c8b353d6087c0c62d000000000000001976a914f682e6254058108032264237a8e62b4777400d4e88ac1f9b6a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd84730440220127f605c0343493dcf03a3d13d88bb27eff1dd0d587a12c4393342dadd6f2f1c02207d673d7f5630960583bbf8d42fcd8642d8a60610579a2bc9591cefeb63bfec6e0147304402201702409a316314e49899ad91eb563a43b57eeb7b79aa84a85e6820a59a61c3a002206e6029a1ca877fe8065309ac43a49f30e0ea3f3cbe1f70eafe5fb4a306cc0b6a01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "304402201702409a316314e49899ad91eb563a43b57eeb7b79aa84a85e6820a59a61c3a002206e6029a1ca877fe8065309ac43a49f30e0ea3f3cbe1f70eafe5fb4a306cc0b6a",
		},
		{ // 10
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKB:      4914,
			},
			htlcDescs: []htlcDesc{
				{ // 10,0
					index:           4,
					remoteSigHex:    "3045022100fcb38506bfa11c02874092a843d0cc0a8613c23b639832564a5f69020cb0f6ba02206508b9e91eaa001425c190c68ee5f887e1ad5b1b314002e74db9dbd9e42dbecf",
					resolutionTxHex: "0200000000010110a3fdcbcd5db477cd3ad465e7f501ffa8c437e8301f00a6061138590add757f0000000000000000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100fcb38506bfa11c02874092a843d0cc0a8613c23b639832564a5f69020cb0f6ba02206508b9e91eaa001425c190c68ee5f887e1ad5b1b314002e74db9dbd9e42dbecf0148304502210086e76b460ddd3cea10525fba298405d3fe11383e56966a5091811368362f689a02200f72ee75657915e0ede89c28709acd113ede9e1b7be520e3bc5cda425ecd6e68012004040404040404040404040404040404040404040404040404040404040404048a76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac686800000000",
				},
			},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8003a00f000000000000000017a914c07cabde46d487782573d1f6790f7e8c8b353d6087c0c62d000000000000001976a914f682e6254058108032264237a8e62b4777400d4e88ac3d996a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd847304402203123c061526eb445af29c230190c3279a19f46055d14701ffffc3c358629a50702204d4b9981f610ad39c5abdd963a8330de7bdb1b12c31d12368aafe26aa58da5c00147304402206f514872c83c69b2f98536ebf1fef1c47de605e157c9c728e16b9abb0c4c809102200e3ea985e666d5dd5381f774402a5f81a5f5453e841e4f79150e2e17bbab672f01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "304402206f514872c83c69b2f98536ebf1fef1c47de605e157c9c728e16b9abb0c4c809102200e3ea985e666d5dd5381f774402a5f81a5f5453e841e4f79150e2e17bbab672f",
		},
		{ // 11
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKB:      4915,
			},
			htlcDescs:               []htlcDesc{},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8002c0c62d000000000000001976a914f682e6254058108032264237a8e62b4777400d4e88ace3996a0000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffda483045022100e7fdcfb6a28ea2191e4c5147cc8f127a34915eef373d785ed691bb4acecbd9c70220323bdb4aa9ab743f76d4fa41a6266c0097674a67395358070c4ed2f758e080aa01483045022100ab3723ed562027a17f33f3a2c3bd1a958c7dd8e3e7476f7cef4416a7dc592ee2022021c9c97b998719be84f520415e9905a5cd7dbcad54c0b620ab5afd19e660ae6101475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "3045022100ab3723ed562027a17f33f3a2c3bd1a958c7dd8e3e7476f7cef4416a7dc592ee2022021c9c97b998719be84f520415e9905a5cd7dbcad54c0b620ab5afd19e660ae61",
		},
		{ // 12
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKB:      9651180,
			},
			htlcDescs:               []htlcDesc{},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8002c0c62d000000000000001976a914f682e6254058108032264237a8e62b4777400d4e88ac1b06350000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd9473044022057d1b2bd4375e82a07147157e2ce5315d59aacd36750b75e0a135052c7ffec2902206c6fba9f71bc9c8a92c7d65238d687bda31285b343ad65ce8784e2d589f3004501483045022100c7b4ee1c16739013fb0274838a3a4b80b6e01887e20dfc6629c291bcf5fbcf5c02204bba54deaedd44b06783561fe61f7ea261d341b3ea577efdc53ce99c1bd3824901475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "3045022100c7b4ee1c16739013fb0274838a3a4b80b6e01887e20dfc6629c291bcf5fbcf5c02204bba54deaedd44b06783561fe61f7ea261d341b3ea577efdc53ce99c1bd38249",
		},
		{ // 13
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKB:      9651181,
			},
			htlcDescs:               []htlcDesc{},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8002c0c62d000000000000001976a914f682e6254058108032264237a8e62b4777400d4e88ac1b06350000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd9473044022057d1b2bd4375e82a07147157e2ce5315d59aacd36750b75e0a135052c7ffec2902206c6fba9f71bc9c8a92c7d65238d687bda31285b343ad65ce8784e2d589f3004501483045022100c7b4ee1c16739013fb0274838a3a4b80b6e01887e20dfc6629c291bcf5fbcf5c02204bba54deaedd44b06783561fe61f7ea261d341b3ea577efdc53ce99c1bd3824901475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "3045022100c7b4ee1c16739013fb0274838a3a4b80b6e01887e20dfc6629c291bcf5fbcf5c02204bba54deaedd44b06783561fe61f7ea261d341b3ea577efdc53ce99c1bd38249",
		},
		{ // 14
			commitment: channeldb.ChannelCommitment{
				CommitHeight:  42,
				LocalBalance:  6988000000,
				RemoteBalance: 3000000000,
				FeePerKB:      9651936,
			},
			htlcDescs:               []htlcDesc{},
			expectedCommitmentTxHex: "0200000001c402e4061d82e9d8cc5b653813bc4cd5afebeffdc71c664258f41275804d4af9000000000038b02b8002c0c62d000000000000001976a914f682e6254058108032264237a8e62b4777400d4e88ac0805350000000000000017a91496fbabc4e9b687c24342b316586fc2cc8f70dda0873e1952200000000001000000000000000000000000ffffffffd94830450221008e8e2f2d046e8349873dff6636823c1aebf12f2247ec1fdd95d1dd30d5a150380220123ab652499bd4e874d407fb22b981eaf00b1bb60831771cf3b1fc779d52c2a501473044022020ee4a24358d5f06bac9e1595f415fb4c700ea4e5f9e86963aa433a9b2ce3465022012186c1308621a7e400b13d8f8e96b7894a594de174093ac526b5776ef5827f201475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21037f6fc2b0e0d63fab64424ef15991dfb76151ba0cf60dd2992015bf81b2eafdd552ae",
			remoteSigHex:            "3044022020ee4a24358d5f06bac9e1595f415fb4c700ea4e5f9e86963aa433a9b2ce3465022012186c1308621a7e400b13d8f8e96b7894a594de174093ac526b5776ef5827f2",
		},
	}

	pCache := &mockPreimageCache{
		// hash -> preimage
		preimageMap: make(map[[32]byte][]byte),
	}

	fundingTxOut := channel.signDesc.Output
	_ = fundingTxOut

	for i, test := range testCases {
		expectedCommitmentTx, err := txFromHex(test.expectedCommitmentTxHex)
		if err != nil {
			t.Fatalf("Case %d: Failed to parse serialized tx: %v", i, err)
		}

		// Build required HTLC structs from raw test vector data.
		htlcs := make([]channeldb.HTLC, len(test.htlcDescs))
		for i, htlcDesc := range test.htlcDescs {
			htlcs[i], err = tc.getHTLC(i, &htlcDesc)
			if err != nil {
				t.Fatal(err)
			}
		}
		theHTLCView := htlcViewFromHTLCs(htlcs)

		// Create unsigned commitment transaction.
		commitmentView := &commitment{
			height:       test.commitment.CommitHeight,
			ourBalance:   test.commitment.LocalBalance,
			theirBalance: test.commitment.RemoteBalance,
			feePerKB:     AtomPerKByte(test.commitment.FeePerKB),
			dustLimit:    tc.dustLimit,
			isOurs:       true,
		}
		err = channel.createCommitmentTx(
			commitmentView, theHTLCView, keys,
		)
		if err != nil {
			t.Errorf("Case %d: Failed to create new commitment tx: %v", i, err)
			continue
		}

		// Initialize LocalCommit, which is used in getSignedCommitTx.
		channelState.LocalCommitment = test.commitment
		channelState.LocalCommitment.Htlcs = htlcs
		channelState.LocalCommitment.CommitTx = commitmentView.txn

		// This is the remote party's signature over the commitment
		// transaction which is included in the commitment tx's witness
		// data.
		channelState.LocalCommitment.CommitSig, err = hex.DecodeString(test.remoteSigHex)
		if err != nil {
			t.Fatalf("Case %d: Failed to parse serialized signature: %v",
				i, err)
		}

		commitTx, err := channel.getSignedCommitTx()
		if err != nil {
			t.Errorf("Case %d: Failed to sign commitment tx: %v", i, err)
			continue
		}

		// Sanity check the commitment to ensure it has a chance of being valid.
		if err = checkSignedCommitmentTxSanity(commitTx, fundingTxOut, tc.netParams); err != nil {
			t.Errorf("Case %d: Failed commitment tx sanity check: %v", i, err)
		}

		// Check that commitment transaction was created correctly.
		if commitTx.TxHashWitness() != expectedCommitmentTx.MsgTx().TxHashWitness() {
			t.Errorf("Case %d: Generated unexpected commitment tx: "+
				"expected %s, got %s", i, spew.Sdump(expectedCommitmentTx),
				spew.Sdump(commitTx))
			continue
		}

		// Generate second-level HTLC transactions for HTLCs in
		// commitment tx.
		htlcResolutions, err := extractHtlcResolutions(
			AtomPerKByte(test.commitment.FeePerKB), true, signer,
			htlcs, keys, channel.localChanCfg, channel.remoteChanCfg,
			commitTx.TxHash(), pCache,
		)
		if err != nil {
			t.Errorf("Case %d: Failed to extract HTLC resolutions: %v", i, err)
			continue
		}

		resolutionIdx := 0
		for j, htlcDesc := range test.htlcDescs {
			// TODO: Check HTLC success transactions; currently not implemented.
			// resolutionIdx can be replaced by j when this is handled.
			if htlcs[j].Incoming {
				continue
			}

			expectedTx, err := txFromHex(htlcDesc.resolutionTxHex)
			if err != nil {
				t.Fatalf("Failed to parse serialized tx: %d %d %v", i, j, err)
			}

			htlcResolution := htlcResolutions.OutgoingHTLCs[resolutionIdx]
			resolutionIdx++

			actualTx := htlcResolution.SignedTimeoutTx
			if actualTx == nil {
				t.Errorf("Case %d: Failed to generate second level tx: "+
					"output %d, %v", i, j,
					htlcResolution)
				continue
			}

			// Sanity check the resulting tx to ensure it has a chance of being
			// mined.
			if err = checkSignedCommitmentSpendingTxSanity(actualTx, commitTx, tc.netParams); err != nil {
				t.Errorf("Case %d: Failed htlc resolution tx sanity check: "+
					"output %d, %v", i, j, err)
			}

			// Check that second-level HTLC transaction was created correctly.
			if actualTx.TxHashWitness() != expectedTx.MsgTx().TxHashWitness() {
				t.Fatalf("Case %d: Generated unexpected second level tx: "+
					"output %d, expected %s, got %s", i, j,
					expectedTx.MsgTx().TxHashWitness(), actualTx.TxHashWitness())
				continue
			}
		}
	}
}

// htlcViewFromHTLCs constructs an htlcView of PaymentDescriptors from a slice
// of channeldb.HTLC structs.
func htlcViewFromHTLCs(htlcs []channeldb.HTLC) *htlcView {
	var theHTLCView htlcView
	for _, htlc := range htlcs {
		paymentDesc := &PaymentDescriptor{
			RHash:   htlc.RHash,
			Timeout: htlc.RefundTimeout,
			Amount:  htlc.Amt,
		}
		if htlc.Incoming {
			theHTLCView.theirUpdates =
				append(theHTLCView.theirUpdates, paymentDesc)
		} else {
			theHTLCView.ourUpdates =
				append(theHTLCView.ourUpdates, paymentDesc)
		}
	}
	return &theHTLCView
}
