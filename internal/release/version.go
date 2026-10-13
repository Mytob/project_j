package release

import (
	"errors"
	"math/big"
	"strings"
)

// CompareVersions compares release versions using Semantic Versioning
// precedence. Build metadata does not affect ordering.
func CompareVersions(left, right string) (int, error) {
	if !ValidVersion(left) || !ValidVersion(right) {
		return 0, errors.New("release version is invalid")
	}
	leftCore, leftPre := splitVersion(left)
	rightCore, rightPre := splitVersion(right)
	for index := range 3 {
		comparison := compareDecimal(leftCore[index], rightCore[index])
		if comparison != 0 {
			return comparison, nil
		}
	}
	if leftPre == "" && rightPre == "" {
		return 0, nil
	}
	if leftPre == "" {
		return 1, nil
	}
	if rightPre == "" {
		return -1, nil
	}
	leftIDs, rightIDs := strings.Split(leftPre, "."), strings.Split(rightPre, ".")
	for index := 0; index < len(leftIDs) && index < len(rightIDs); index++ {
		leftNumeric, rightNumeric := decimalIdentifier(leftIDs[index]), decimalIdentifier(rightIDs[index])
		switch {
		case leftNumeric && rightNumeric:
			if comparison := compareDecimal(leftIDs[index], rightIDs[index]); comparison != 0 {
				return comparison, nil
			}
		case leftNumeric:
			return -1, nil
		case rightNumeric:
			return 1, nil
		default:
			if leftIDs[index] < rightIDs[index] {
				return -1, nil
			}
			if leftIDs[index] > rightIDs[index] {
				return 1, nil
			}
		}
	}
	if len(leftIDs) < len(rightIDs) {
		return -1, nil
	}
	if len(leftIDs) > len(rightIDs) {
		return 1, nil
	}
	return 0, nil
}

func splitVersion(version string) ([3]string, string) {
	version, _, _ = strings.Cut(version, "+")
	core, prerelease, hasPrerelease := strings.Cut(version, "-")
	parts := strings.Split(core, ".")
	return [3]string{parts[0], parts[1], parts[2]}, func() string {
		if hasPrerelease {
			return prerelease
		}
		return ""
	}()
}

func decimalIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func compareDecimal(left, right string) int {
	leftValue, rightValue := new(big.Int), new(big.Int)
	leftValue.SetString(left, 10)
	rightValue.SetString(right, 10)
	return leftValue.Cmp(rightValue)
}
