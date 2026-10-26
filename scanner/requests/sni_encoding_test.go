package requests

import (
	"bytes"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestBuildSNIExtensionNamesBytes(t *testing.T) {
	tests := []struct {
		name  string
		names []string
		want  []byte
	}{
		{
			name:  "no names",
			names: []string{},
			want:  []byte{0x00, 0x00},
		},
		{
			name:  "single empty name preserves zero-length host_name",
			names: []string{""},
			want:  []byte{0x00, 0x03, 0x00, 0x00, 0x00},
		},
		{
			name:  "single name",
			names: []string{"abc"},
			want:  []byte{0x00, 0x06, 0x00, 0x00, 0x03, 'a', 'b', 'c'},
		},
		{
			name:  "two names",
			names: []string{"a", "bc"},
			want:  []byte{0x00, 0x09, 0x00, 0x00, 0x01, 'a', 0x00, 0x00, 0x02, 'b', 'c'},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext := buildSNIExtensionNames(tt.names)
			if ext.Id != 0 {
				t.Fatalf("extension id = %d, want 0", ext.Id)
			}
			if !bytes.Equal(ext.Data, tt.want) {
				t.Fatalf("data = %v, want %v", ext.Data, tt.want)
			}
		})
	}
}

func TestBuildSNIExtensionWrapperMatchesNames(t *testing.T) {
	for _, name := range []string{"", "example.com", "a.b.c"} {
		single := buildSNIExtension(name)
		list := buildSNIExtensionNames([]string{name})
		if !bytes.Equal(single.Data, list.Data) {
			t.Fatalf("wrapper mismatch for %q: %v vs %v", name, single.Data, list.Data)
		}
	}
}

func TestBuildSNIExtensions(t *testing.T) {
	t.Run("empty without force sends nothing", func(t *testing.T) {
		if got := buildSNIExtensions([]string{""}, false, false); len(got) != 0 {
			t.Fatalf("expected no extension, got %d", len(got))
		}
	})
	t.Run("forced empty sends one extension", func(t *testing.T) {
		got := buildSNIExtensions([]string{""}, true, false)
		if len(got) != 1 {
			t.Fatalf("expected 1 extension, got %d", len(got))
		}
		if ext := got[0].(*utls.GenericExtension); ext.Id != 0 {
			t.Fatalf("extension id = %d, want 0", ext.Id)
		}
	})
	t.Run("duplicate emits two identical extensions", func(t *testing.T) {
		got := buildSNIExtensions([]string{"example.com"}, false, true)
		if len(got) != 2 {
			t.Fatalf("expected 2 extensions, got %d", len(got))
		}
		first := got[0].(*utls.GenericExtension)
		second := got[1].(*utls.GenericExtension)
		if first.Id != 0 || second.Id != 0 || !bytes.Equal(first.Data, second.Data) {
			t.Fatalf("extensions not identical: %#v %#v", first, second)
		}
	})
	t.Run("duplicate of empty name without force sends nothing", func(t *testing.T) {
		if got := buildSNIExtensions([]string{""}, false, true); len(got) != 0 {
			t.Fatalf("expected no extension, got %d", len(got))
		}
	})
}
