package cuda

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
)

var scalarModulus = func() (v [32]byte) {
	b, _ := hex.DecodeString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
	copy(v[:], b)
	return
}()
var baseModulus, _ = new(big.Int).SetString("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)

func reverse(dst, src []byte) {
	for i := range src {
		dst[len(src)-1-i] = src[i]
	}
}

func domainBytes() (roots, differences []byte) {
	r := new(big.Int).SetBytes(scalarModulus[:])
	generator, _ := new(big.Int).SetString("10238227357739495823651030575849232062558860180284477541189508159991286009131", 10)
	root := new(big.Int).Exp(generator, new(big.Int).Lsh(big.NewInt(1), 20), r)
	roots = make([]byte, 4096*32)
	differences = make([]byte, len(roots))
	value := big.NewInt(1)
	var encoded [32]byte
	for i := 0; i < 4096; i++ {
		value.FillBytes(encoded[:])
		reverse(roots[i*32:(i+1)*32], encoded[:])
		if i > 0 {
			inverse := new(big.Int).Sub(value, big.NewInt(1))
			inverse.ModInverse(inverse, r)
			inverse.FillBytes(encoded[:])
			reverse(differences[i*32:(i+1)*32], encoded[:])
		}
		value.Mul(value, root).Mod(value, r)
	}
	return
}

func encodePoint(raw []byte) (point [48]byte, err error) {
	if len(raw) != 96 {
		return point, errors.New("invalid CUDA affine point length")
	}
	var x, y [48]byte
	reverse(x[:], raw[:48])
	reverse(y[:], raw[48:])
	copy(point[:], x[:])
	xi := new(big.Int).SetBytes(x[:])
	yi := new(big.Int).SetBytes(y[:])
	if xi.Cmp(baseModulus) >= 0 || yi.Cmp(baseModulus) >= 0 {
		return point, errors.New("noncanonical CUDA affine point")
	}
	if bytes.Equal(raw, make([]byte, 96)) {
		point[0] = 0xc0
		return point, nil
	}
	point[0] |= 0x80
	if yi.Cmp(new(big.Int).Rsh(new(big.Int).Set(baseModulus), 1)) > 0 {
		point[0] |= 0x20
	}
	return point, nil
}
