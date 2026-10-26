package helpers

import "strings"

func RemoveDuplicate[T string | int](sliceList []T) []T {
	allKeys := make(map[T]bool)
	list := []T{}
	for _, item := range sliceList {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func RemoveEmpty[T string](s []T) []T {
	var r []T
	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}

func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func ContainsFold(s []string, e string) bool {
	for _, a := range s {
		if strings.EqualFold(a, e) {
			return true
		}
	}
	return false
}
func MetaSplit(s []string, sep string) []string {
	result := []string{}
	for _, e := range s {
		result = append(result, strings.Split(e, sep)...)
	}
	return result
}

func ChunkBy[T any](items []T, chunkSize int) (chunks [][]T) {
	if chunkSize < 1 || len(items) == 0 {
		return nil
	}
	for chunkSize < len(items) {
		items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
	}
	return append(chunks, items)
}
