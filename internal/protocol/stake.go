package protocol

import (
	"math/big"
)

func StakeWeight(rawStake *big.Int) *big.Int {
	if rawStake == nil || rawStake.Sign() <= 0 {
		return new(big.Int)
	}

	// floor(stake^(9/10)) = floor(10thRoot(stake^9)).
	target := new(big.Int).Exp(rawStake, big.NewInt(9), nil)
	low := new(big.Int)
	high := new(big.Int).Add(new(big.Int).Set(rawStake), big.NewInt(1))
	mid := new(big.Int)
	power := new(big.Int)

	for difference := new(big.Int).Sub(high, low); difference.Cmp(big.NewInt(1)) > 0; {
		mid.Add(low, high)
		mid.Rsh(mid, 1)
		power.Exp(mid, big.NewInt(10), nil)
		if power.Cmp(target) <= 0 {
			low.Set(mid)
		} else {
			high.Set(mid)
		}
		difference.Sub(high, low)
	}
	return new(big.Int).Set(low)
}

func RawStakeFromUnits(units int64) *big.Int {
	base, _ := new(big.Int).SetString(IDenaBase, 10)
	return new(big.Int).Mul(base, big.NewInt(units))
}
