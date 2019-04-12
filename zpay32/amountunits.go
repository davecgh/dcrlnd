package zpay32

import (
	"fmt"
	"strconv"

	"github.com/decred/dcrlnd/lnwire"
)

var (
	// toMAtoms is a map from a unit to a function that converts an amount
	// of that unit to MilliAtoms.
	toMAtoms = map[byte]func(uint64) (lnwire.MilliAtom, error){
		'm': mDcrToMAtoms,
		'u': uDcrToMAtoms,
		'n': nDcrToMAtoms,
		'p': pDcrToMAtoms,
	}

	// fromMAtoms is a map from a unit to a function that converts an amount
	// in MilliAtoms to an amount of that unit.
	fromMAtoms = map[byte]func(lnwire.MilliAtom) (uint64, error){
		'm': mAtToMDcr,
		'u': mAtToUDcr,
		'n': mAtToNDcr,
		'p': mAtToPDcr,
	}
)

// mDcrToMAtoms converts the given amount in milliDCR to MilliAtoms.
func mDcrToMAtoms(m uint64) (lnwire.MilliAtom, error) {
	return lnwire.MilliAtom(m) * 100000000, nil
}

// uDcrToMAtoms converts the given amount in microDCR to MilliAtoms.
func uDcrToMAtoms(u uint64) (lnwire.MilliAtom, error) {
	return lnwire.MilliAtom(u * 100000), nil
}

// nDcrToMAtoms converts the given amount in nanoDCR to MilliAtoms.
func nDcrToMAtoms(n uint64) (lnwire.MilliAtom, error) {
	return lnwire.MilliAtom(n * 100), nil
}

// pDcrToMAtoms converts the given amount in picoDCR to MilliAtoms.
func pDcrToMAtoms(p uint64) (lnwire.MilliAtom, error) {
	if p < 10 {
		return 0, fmt.Errorf("minimum amount is 10p")
	}
	if p%10 != 0 {
		return 0, fmt.Errorf("amount %d pDCR not expressible in mAt",
			p)
	}
	return lnwire.MilliAtom(p / 10), nil
}

// mAtToMDcr converts the given amount in MilliAtoms to milliDCR.
func mAtToMDcr(mat lnwire.MilliAtom) (uint64, error) {
	if mat%100000000 != 0 {
		return 0, fmt.Errorf("%d mAt not expressible "+
			"in mDCR", mat)
	}
	return uint64(mat / 100000000), nil
}

// mAtToUDcr converts the given amount in MilliAtoms to microDCR.
func mAtToUDcr(mat lnwire.MilliAtom) (uint64, error) {
	if mat%100000 != 0 {
		return 0, fmt.Errorf("%d mAt not expressible "+
			"in uDCR", mat)
	}
	return uint64(mat / 100000), nil
}

// mAtToNDcr converts the given amount in MilliAtoms to nanoDCR.
func mAtToNDcr(mat lnwire.MilliAtom) (uint64, error) {
	if mat%100 != 0 {
		return 0, fmt.Errorf("%d mAt not expressible in nDCR", mat)
	}
	return uint64(mat / 100), nil
}

// mAtToPDcr converts the given amount in MilliAtoms to picoDCR.
func mAtToPDcr(mat lnwire.MilliAtom) (uint64, error) {
	return uint64(mat * 10), nil
}

// decodeAmount returns the amount encoded by the provided string in
// MilliAtom.
func decodeAmount(amount string) (lnwire.MilliAtom, error) {
	if len(amount) < 1 {
		return 0, fmt.Errorf("amount must be non-empty")
	}

	// If last character is a digit, then the amount can just be
	// interpreted as DCR.
	char := amount[len(amount)-1]
	digit := char - '0'
	if digit <= 9 {
		btc, err := strconv.ParseUint(amount, 10, 64)
		if err != nil {
			return 0, err
		}
		return lnwire.MilliAtom(btc) * mAtPerDcr, nil
	}

	// If not a digit, it must be part of the known units.
	conv, ok := toMAtoms[char]
	if !ok {
		return 0, fmt.Errorf("unknown multiplier %c", char)
	}

	// Known unit.
	num := amount[:len(amount)-1]
	if len(num) < 1 {
		return 0, fmt.Errorf("number must be non-empty")
	}

	am, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		return 0, err
	}

	return conv(am)
}

// encodeAmount encodes the provided MilliAtom amount using as few characters
// as possible.
func encodeAmount(mat lnwire.MilliAtom) (string, error) {
	// If possible to express in DCR, that will always be the shortest
	// representation.
	if mat%mAtPerDcr == 0 {
		return strconv.FormatInt(int64(mat/mAtPerDcr), 10), nil
	}

	// Should always be expressible in pico DCR.
	pico, err := fromMAtoms['p'](mat)
	if err != nil {
		return "", fmt.Errorf("unable to express %d mAt as pDCR: %v",
			mat, err)
	}
	shortened := strconv.FormatUint(pico, 10) + "p"
	for unit, conv := range fromMAtoms {
		am, err := conv(mat)
		if err != nil {
			// Not expressible using this unit.
			continue
		}

		// Save the shortest found representation.
		str := strconv.FormatUint(am, 10) + string(unit)
		if len(str) < len(shortened) {
			shortened = str
		}
	}

	return shortened, nil
}
