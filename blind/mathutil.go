package blind

import "math/big"

// AddMod(modulus,st ...big.Int) -> big.Int
// Inverse(big.int,modules) -> big.Int

func Mod(i *Skalar, modulus *Skalar) *Skalar {
	return (*Skalar)(new(big.Int).Mod((*big.Int)(i), (*big.Int)(modulus)))
}

// AddMod sums s and applies modulus.
func AddMod(modulus *Skalar, s ...*Skalar) *Skalar {
	return (*Skalar)(new(big.Int).Mod((*big.Int)(Add(s...)), (*big.Int)(modulus)))
}

func MulMod(modulus *big.Int, s ...*Skalar) *Skalar {
	return (*Skalar)(new(big.Int).Mod((*big.Int)(Multiply(s...)), modulus))
}

// Add many big.Int.
func Add(s ...*Skalar) *Skalar {
	switch len(s) {
	case 1:
		return (*Skalar)(new(big.Int).Set((*big.Int)(s[0])))
	case 2:
		return (*Skalar)(new(big.Int).Add((*big.Int)(s[0]), (*big.Int)(s[1])))
	default:
		z := big.NewInt(1)
		for _, f := range s {
			z = z.Add((*big.Int)(z), (*big.Int)(f))
		}
		return (*Skalar)(z)
	}
}

// Multiply many big.Int.
func Multiply(factors ...*Skalar) *Skalar {
	switch len(factors) {
	case 1:
		return (*Skalar)(new(big.Int).Set((*big.Int)(factors[0])))
	case 2:
		return (*Skalar)(new(big.Int).Mul((*big.Int)(factors[0]), (*big.Int)(factors[1])))
	default:
		z := big.NewInt(1)
		for _, f := range factors {
			z = z.Mul((*big.Int)(z), (*big.Int)(f))
		}
		return (*Skalar)(z)
	}
}
