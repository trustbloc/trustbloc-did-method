//
//  Copyright 2006-2019 WebPKI.org (http://webpki.org).
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

// This package transforms JSON data in UTF-8 according to:
// https://tools.ietf.org/html/draft-rundgren-json-canonicalization-scheme-02

package jsoncanonicalizer

import (
	"container/list"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

type nameValueType struct {
	name    string
	sortKey []uint16
	value   string
}

// JSON standard escapes (modulo \u)
var asciiEscapes = []byte{'\\', '"', 'b', 'f', 'n', 'r', 't'}
var binaryEscapes = []byte{'\\', '"', '\b', '\f', '\n', '\r', '\t'}

// JSON literals
var literals = []string{"true", "false", "null"}

func Transform(jsonData []byte, sortArrays bool) (result []byte, e error) {
	t := transformer{}
	return t.transform(jsonData, sortArrays)
}

type transformer struct {
	globalError    error
	index          int
	jsonDataLength int
	jsonData       []byte
	sortArrays     bool
}

func (t *transformer) transform(jsonData []byte, sortArrays bool) (result []byte, e error) {
	t.jsonData = jsonData
	t.sortArrays = sortArrays

	// JSON data MUST be UTF-8 encoded
	t.jsonDataLength = len(jsonData)

	// Current pointer in jsonData
	t.index = 0

	// "Forward" declarations are needed for closures referring each other

	t.globalError = nil
	/////////////////////////////////////////////////
	// This is where Transform actually begins...  //
	/////////////////////////////////////////////////
	var transformed string

	if t.testNextNonWhiteSpaceChar() == '[' {
		t.scan()
		if sortArrays {
			transformed = t.parseArraySorted()
		} else {
			transformed = t.parseArray()
		}
	} else {
		t.scanFor('{')
		transformed = t.parseObject()
	}
	for t.index < t.jsonDataLength {
		if !t.isWhiteSpace(t.jsonData[t.index]) {
			t.setError("Improperly terminated JSON object")
			break
		}
		t.index++
	}
	return []byte(transformed), t.globalError
}

func (t *transformer) checkError(e error) {
	// We only honor the first reported error
	if t.globalError == nil {
		t.globalError = e
	}
}

func (t *transformer) setError(msg string) {
	t.checkError(errors.New(msg))
}

func (t *transformer) isWhiteSpace(c byte) bool {
	return c == 0x20 || c == 0x0a || c == 0x0d || c == 0x09
}

func (t *transformer) nextChar() byte {
	if t.index < t.jsonDataLength {
		c := t.jsonData[t.index]
		if c > 0x7f {
			t.setError("Unexpected non-ASCII character")
		}
		t.index++
		return c
	}
	t.setError("Unexpected EOF reached")
	return '"'
}

func (t *transformer) scan() byte {
	for {
		c := t.nextChar()
		if t.isWhiteSpace(c) {
			continue
		}
		return c
	}
}

func (t *transformer) scanFor(expected byte) {
	c := t.scan()
	if c != expected {
		t.setError("Expected '" + string(expected) + "' but got '" + string(c) + "'")
	}
}

func (t *transformer) getUEscape() rune {
	start := t.index
	t.nextChar()
	t.nextChar()
	t.nextChar()
	t.nextChar()
	if t.globalError != nil {
		return 0
	}
	u16, err := strconv.ParseUint(string(t.jsonData[start:t.index]), 16, 64)
	t.checkError(err)
	return rune(u16)
}

func (t *transformer) testNextNonWhiteSpaceChar() byte {
	save := t.index
	c := t.scan()
	t.index = save
	return c
}

func (t *transformer) decorateString(rawUTF8 string) string {
	var quotedString strings.Builder
	quotedString.WriteByte('"')
CoreLoop:
	for _, c := range []byte(rawUTF8) {
		// Is this within the JSON standard escapes?
		for i, esc := range binaryEscapes {
			if esc == c {
				quotedString.WriteByte('\\')
				quotedString.WriteByte(asciiEscapes[i])
				continue CoreLoop
			}
		}
		if c < 0x20 {
			// Other ASCII control characters must be escaped with \uhhhh
			quotedString.WriteString(fmt.Sprintf("\\u%04x", c))
		} else {
			quotedString.WriteByte(c)
		}
	}
	quotedString.WriteByte('"')
	return quotedString.String()
}

func (t *transformer) parseQuotedString() string {
	var rawString strings.Builder
CoreLoop:
	for t.globalError == nil {
		var c byte
		if t.index < t.jsonDataLength {
			c = t.jsonData[t.index]
			t.index++
		} else {
			t.nextChar()
			break
		}
		if c == '"' {
			break
		}
		if c < ' ' {
			t.setError("Unterminated string literal")
		} else if c == '\\' {
			// Escape sequence
			c = t.nextChar()
			if c == 'u' {
				// The \u escape
				firstUTF16 := t.getUEscape()
				if utf16.IsSurrogate(firstUTF16) {
					// If the first UTF-16 code unit has a certain value there must be
					// another succeeding UTF-16 code unit as well
					if t.nextChar() != '\\' || t.nextChar() != 'u' {
						t.setError("Missing surrogate")
					} else {
						// Output the UTF-32 code point as UTF-8
						rawString.WriteRune(utf16.DecodeRune(firstUTF16, t.getUEscape()))
					}
				} else {
					// Single UTF-16 code identical to UTF-32.  Output as UTF-8
					rawString.WriteRune(firstUTF16)
				}
			} else if c == '/' {
				// Benign but useless escape
				rawString.WriteByte('/')
			} else {
				// The JSON standard escapes
				for i, esc := range asciiEscapes {
					if esc == c {
						rawString.WriteByte(binaryEscapes[i])
						continue CoreLoop
					}
				}
				t.setError("Unexpected escape: \\" + string(c))
			}
		} else {
			// Just an ordinary ASCII character alternatively a UTF-8 byte
			// outside of ASCII.
			// Note that properly formatted UTF-8 never clashes with ASCII
			// making byte per byte search for ASCII break characters work
			// as expected.
			rawString.WriteByte(c)
		}
	}
	return rawString.String()
}

func (t *transformer) parseSimpleType() string {
	var token strings.Builder
	t.index--
	for t.globalError == nil {
		c := t.testNextNonWhiteSpaceChar()
		if c == ',' || c == ']' || c == '}' {
			break
		}
		c = t.nextChar()
		if t.isWhiteSpace(c) {
			break
		}
		token.WriteByte(c)
	}
	if token.Len() == 0 {
		t.setError("Missing argument")
	}
	value := token.String()
	// Is it a JSON literal?
	for _, literal := range literals {
		if literal == value {
			return literal
		}
	}
	// Apparently not so we assume that it is a I-JSON number
	ieeeF64, err := strconv.ParseFloat(value, 64)
	t.checkError(err)
	value, err = NumberToJSON(ieeeF64)
	t.checkError(err)
	return value
}

func (t *transformer) parseElement() string {
	switch t.scan() {
	case '{':
		return t.parseObject()
	case '"':
		return t.decorateString(t.parseQuotedString())
	case '[':
		if t.sortArrays {
			return t.parseArraySorted()
		} else {
			return t.parseArray()
		}
	default:
		return t.parseSimpleType()
	}
}

func (t *transformer) parseArray() string {
	var arrayData strings.Builder
	arrayData.WriteByte('[')
	var next bool = false
	for t.globalError == nil && t.testNextNonWhiteSpaceChar() != ']' {
		if next {
			t.scanFor(',')
			arrayData.WriteByte(',')
		} else {
			next = true
		}
		arrayData.WriteString(t.parseElement())
	}
	t.scan()
	arrayData.WriteByte(']')
	return arrayData.String()
}

func (t *transformer) lexicographicallyPrecedes(sortKey []uint16, e *list.Element) bool {
	// Find the minimum length of the sortKeys
	oldSortKey := e.Value.(nameValueType).sortKey
	minLength := len(oldSortKey)
	if minLength > len(sortKey) {
		minLength = len(sortKey)
	}
	for q := 0; q < minLength; q++ {
		diff := int(sortKey[q]) - int(oldSortKey[q])
		if diff < 0 {
			// Smaller => Precedes
			return true
		} else if diff > 0 {
			// Bigger => No match
			return false
		}
		// Still equal => Continue
	}
	// The sortKeys compared equal up to minLength
	if len(sortKey) < len(oldSortKey) {
		// Shorter => Precedes
		return true
	}
	if len(sortKey) == len(oldSortKey) {
		t.setError("Duplicate key: " + e.Value.(nameValueType).name)
	}
	// Longer => No match
	return false
}

func (t *transformer) parseObject() string {
	nameValueList := list.New()
	var next bool = false
CoreLoop:
	for t.globalError == nil && t.testNextNonWhiteSpaceChar() != '}' {
		if next {
			t.scanFor(',')
		}
		next = true
		t.scanFor('"')
		rawUTF8 := t.parseQuotedString()
		if t.globalError != nil {
			break
		}
		// Sort keys on UTF-16 code units
		// Since UTF-8 doesn't have endianess this is just a value transformation
		// In the Go case the transformation is UTF-8 => UTF-32 => UTF-16
		sortKey := utf16.Encode([]rune(rawUTF8))
		t.scanFor(':')
		nameValue := nameValueType{rawUTF8, sortKey, t.parseElement()}
		for e := nameValueList.Front(); e != nil; e = e.Next() {
			// Check if the key is smaller than a previous key
			if t.lexicographicallyPrecedes(sortKey, e) {
				// Precedes => Insert before and exit sorting
				nameValueList.InsertBefore(nameValue, e)
				continue CoreLoop
			}
			// Continue searching for a possibly succeeding sortKey
			// (which is straightforward since the list is ordered)
		}
		// The sortKey is either the first or is succeeding all previous sortKeys
		nameValueList.PushBack(nameValue)
	}
	// Scan away '}'
	t.scan()
	// Now everything is sorted so we can properly serialize the object
	var objectData strings.Builder
	objectData.WriteByte('{')
	next = false
	for e := nameValueList.Front(); e != nil; e = e.Next() {
		if next {
			objectData.WriteByte(',')
		}
		next = true
		nameValue := e.Value.(nameValueType)
		objectData.WriteString(t.decorateString(nameValue.name))
		objectData.WriteByte(':')
		objectData.WriteString(nameValue.value)
	}
	objectData.WriteByte('}')
	return objectData.String()
}
