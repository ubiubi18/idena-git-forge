package protocol

import (
	"math/big"
	"testing"
)

func TestStakeWeightIsSublinearAndDeterministic(t *testing.T) {
	small := StakeWeight(RawStakeFromUnits(100_000))
	large := StakeWeight(RawStakeFromUnits(400_000))
	if small.Sign() <= 0 || large.Sign() <= 0 {
		t.Fatal("weights must be positive")
	}
	if large.Cmp(small) <= 0 {
		t.Fatal("larger stake must have larger weight")
	}
	if large.Cmp(new(big.Int).Mul(small, big.NewInt(4))) >= 0 {
		t.Fatal("weight must remain sublinear")
	}
	if StakeWeight(RawStakeFromUnits(400_000)).Cmp(large) != 0 {
		t.Fatal("weight calculation changed between runs")
	}
}

func TestStakeWeightKnownSmallValues(t *testing.T) {
	if got := StakeWeight(big.NewInt(0)); got.Sign() != 0 {
		t.Fatalf("zero weight = %s", got)
	}
	if got := StakeWeight(big.NewInt(1)); got.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("one weight = %s", got)
	}
}

func TestStakeWeightIdentitySplittingHasSublinearEffect(t *testing.T) {
	singleIdentity := StakeWeight(RawStakeFromUnits(1_000_000))
	perIdentity := StakeWeight(RawStakeFromUnits(10_000))
	hundredIdentitySplit := new(big.Int).Mul(perIdentity, big.NewInt(100))

	if hundredIdentitySplit.Cmp(singleIdentity) <= 0 {
		t.Fatal("per-identity weighting must preserve the selected identity-splitting effect")
	}
	if hundredIdentitySplit.Cmp(new(big.Int).Mul(singleIdentity, big.NewInt(2))) >= 0 {
		t.Fatal("identity-splitting effect must remain sublinear")
	}
}
