// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package compression

const (
	TypeOff  = 0
	TypeZSTD = 1
	TypeLZ4  = 2
	TypeZLIB = 3
)

func NormalizeType(value uint8) uint8 {
	switch value {
	case TypeOff, TypeZSTD, TypeLZ4, TypeZLIB:
		return value
	default:
		return TypeOff
	}
}

func PackPair(uploadType uint8, downloadType uint8) uint8 {
	return (NormalizeType(uploadType) << 4) | NormalizeType(downloadType)
}

func SplitPair(value uint8) (uint8, uint8) {
	return NormalizeType((value >> 4) & 0x0F), NormalizeType(value & 0x0F)
}
