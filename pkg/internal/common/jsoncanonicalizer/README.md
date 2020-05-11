## JSON Cononicalizer

The files in this folder are derived from [Cyberphone JSON Canonicalization Go Library](https://github.com/cyberphone/json-canonicalization/tree/master/go/src/webpki.org/jsoncanonicalizer). 
The licence details are available at [LICENCE](https://github.com/cyberphone/json-canonicalization/blob/master/LICENSE).

The changes herein are as follows:
- Refactor Transform() into a struct 'transformer' with methods and member variables instead of inner functions and local variables used by said inner functions.
- Add a modified parseArray function in parsearraysorted.go, so it can optionally lexicographically sort the contents of the array.
- Modify the interface of Transform() so it takes a flag parameter to toggle array sorting.
- Add jsoncanonicalizer_test.go to test the new sorting function.
