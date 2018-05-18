package shachain

// changeBit is a function that flips a bit of the hash at a particluar
// bit-index. You should be aware that the bit flipping in this function a bit
// strange, example:
// hash: [0b00000000, 0b00000000,  ... 0b00000000]
//        0		      1            ... 31
//
// byte: 0 0 0 0 0 0 0 0
//       7 6 5 4 3 2 1 0
//
// By flipping the bit at 7 position you will flip the first bit in hash and by
// flipping the bit at 8 position you will flip the 16 bit in hash.
func changeBit(hash []byte, position uint8) []byte {
	byteNumber := position / 8
	bitNumber := position % 8

	hash[byteNumber] ^= (1 << bitNumber)
	return hash
}

// getBit returns bit on index at position.
func getBit(index index, position uint8) uint8 {
	return uint8((uint64(index) >> position) & 1)
}

func getPrefix(index index, position uint8) uint64 {
	//	+ -------------------------- +
	// 	| №  | value | mask | return |
	//	+ -- + ----- + ---- + ------ +
	//	| 63 |	 1   |  0   |	 0   |
	//	| 62 |	 0   |  0   |	 0   |
	//	| 61 |   1   |  0   |	 0   |
	//		....
	//	|  4 |	 1   |  0   |	 0   |
	//	|  3 |   1   |  0   |	 0   |
	//	|  2 |   1   |  1   |	 1   | <--- position
	//	|  1 |   0   |  1   |	 0   |
	//	|  0 |   1   |  1   |	 1   |
	//	+ -- + ----- + ---- + ------ +

	var zero uint64
	mask := (zero - 1) - uint64((1<<position)-1)
	return (uint64(index) & mask)
}

// countTrailingZeros counts number of trailing zero bits, this function is
// used to determine the number of element bucket.
func countTrailingZeros(index index) uint8 {
	var zeros uint8
	for ; zeros < maxHeight; zeros++ {
		if getBit(index, zeros) != 0 {
			break
		}
	}

	return zeros
}
