package common

import "strings"

func Strstr(haystack string, needle string, before bool) (res string) {
	if needle == "" {
		res = haystack
		return
	}

	idx := strings.Index(haystack, needle)

	if idx == -1 {
		res = haystack
		return
	}

	txt := strings.Split(haystack, needle)

	if before {
		res = txt[0]
	} else {
		res = txt[1]
	}

	return
}
