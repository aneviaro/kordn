package cache

import "testing"

func FuzzLRUBounded(f *testing.F) {
	f.Add([]byte("seed"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c := MustNewLRU[string, []byte](8)
		for i, value := range data {
			key := string(rune(i % 16))
			c.Put(key, []byte{value})
		}
		if c.Len() > c.Capacity() {
			t.Fatal("cache exceeded capacity")
		}
	})
}
