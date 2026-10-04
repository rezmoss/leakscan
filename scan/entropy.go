package scan

import "math"

// Entropy: Shannon, bits/byte.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := range len(s) {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
