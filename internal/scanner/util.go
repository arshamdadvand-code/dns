package scanner

import "strconv"

func itoaPort(p int) string {
	if p <= 0 {
		return "0"
	}
	return strconv.Itoa(p)
}
