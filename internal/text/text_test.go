package text

import (
	"reflect"
	"testing"
)

func TestSlug(t *testing.T) {
	cases := map[string]string{
		"NAS":            "nas",
		"My Server 2":    "my-server-2",
		"  --Edge__Node": "edge-node",
		"кириллица":      "",
		"a.b.c":          "a-b-c",
		"trailing---":    "trailing",
	}
	for in, want := range cases {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFields(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"  ", nil},
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , ,b ,", []string{"a", "b"}},
	}
	for _, c := range cases {
		if got := Fields(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Fields(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestCSVRoundTrip(t *testing.T) {
	if got := SplitCSV(""); got != nil {
		t.Errorf("SplitCSV(\"\") = %v, want nil", got)
	}
	in := []string{"192.168.0.0/24", "10.0.0.0/8"}
	if got := SplitCSV(JoinCSV(in)); !reflect.DeepEqual(got, in) {
		t.Errorf("round-trip = %v, want %v", got, in)
	}
}
