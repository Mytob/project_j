package release

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		left, right string
		want        int
	}{
		{left: "1.0.0", right: "1.0.0", want: 0},
		{left: "1.0.1", right: "1.0.0", want: 1},
		{left: "2.0.0", right: "10.0.0", want: -1},
		{left: "1.0.0-dev", right: "1.0.0", want: -1},
		{left: "1.0.0", right: "1.0.0-rc.1", want: 1},
		{left: "1.0.0-rc.2", right: "1.0.0-rc.10", want: -1},
		{left: "1.0.0-alpha", right: "1.0.0-alpha.1", want: -1},
		{left: "1.0.0+build.1", right: "1.0.0+build.2", want: 0},
		{left: "1.0.0-999999999999999999999", right: "1.0.0-1000000000000000000000", want: -1},
	}
	for _, test := range tests {
		got, err := CompareVersions(test.left, test.right)
		if err != nil || got != test.want {
			t.Errorf("CompareVersions(%q, %q) = %d, %v; want %d", test.left, test.right, got, err, test.want)
		}
	}
	if _, err := CompareVersions("bad", "1.0.0"); err == nil {
		t.Fatal("invalid release version was accepted")
	}
}
