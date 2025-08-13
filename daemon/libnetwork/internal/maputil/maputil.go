package maputil

func FilterValues[K comparable, V any](in map[K]V, fn func(V) bool) []V {
	var out []V
	for _, v := range in {
		if fn(v) {
			out = append(out, v)
		}
	}
	return out
}

func Map[K1 comparable, V1 any, K2 comparable, V2 any](m map[K1]V1, fn func(K1, V1) (K2, V2)) map[K2]V2 {
	if m == nil {
		return nil
	}
	res := make(map[K2]V2, len(m))
	for k, v := range m {
		k2, v2 := fn(k, v)
		res[k2] = v2
	}
	return res
}
