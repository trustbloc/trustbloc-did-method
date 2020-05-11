/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package jsoncanonicalizer

import (
	"sort"
	"strings"
)

func (t *transformer) parseArraySorted() string {
	var elements []string

	var next bool = false
	for t.globalError == nil && t.testNextNonWhiteSpaceChar() != ']' {
		if next {
			t.scanFor(',')
		} else {
			next = true
		}
		elements = append(elements, t.parseElement())
	}
	t.scan()

	// sort the elements so we enforce an order
	sort.Strings(elements)

	var arrayData strings.Builder

	arrayData.WriteByte('[')
	next = false
	for _, element := range elements {
		if next {
			arrayData.WriteByte(',')
		} else {
			next = true
		}
		arrayData.WriteString(element)
	}

	return arrayData.String()
}
