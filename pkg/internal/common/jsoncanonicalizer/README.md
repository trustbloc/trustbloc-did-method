## JSON Cononicalizer

The files in this folder are derived from [Cyberphone JSON Canonicalization Go Library](https://github.com/cyberphone/json-canonicalization/tree/master/go/src/webpki.org/jsoncanonicalizer). 
The licence details are available at [LICENCE](https://github.com/cyberphone/json-canonicalization/blob/master/LICENSE).

The changes herein are as follows:
- Modify the parseArray function inside Transform(), so it can optionally lexicographically sort the contents of the array.
- Modify the interface of Transform() so it takes a flag parameter to toggle array sorting.
- Add jsoncanonicalizer_test.go to test the new sorting functionality.
 