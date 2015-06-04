// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
  "testing"
  "encoding/json"
  "reflect"
  "fmt"

  "github.com/letsencrypt/boulder/test"
  "github.com/letsencrypt/boulder/core"

  jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
)

const JWK_1_JSON = `{
  "kty": "RSA",
  "n": "vuc785P8lBj3fUxyZchF_uZw6WtbxcorqgTyq-qapF5lrO1U82Tp93rpXlmctj6fyFHBVVB5aXnUHJ7LZeVPod7Wnfl8p5OyhlHQHC8BnzdzCqCMKmWZNX5DtETDId0qzU7dPzh0LP0idt5buU7L9QNaabChw3nnaL47iu_1Di5Wp264p2TwACeedv2hfRDjDlJmaQXuS8Rtv9GnRWyC9JBu7XmGvGDziumnJH7Hyzh3VNu-kSPQD3vuAFgMZS6uUzOztCkT0fpOalZI6hqxtWLvXUMj-crXrn-Maavz8qRhpAyp5kcYk3jiHGgQIi7QSK2JIdRJ8APyX9HlmTN5AQ",
  "e": "AAEAAQ"
}`

func toFromDbBinder(t *testing.T, initial interface{}, out interface{}) {
  tc := BoulderTypeConverter{}

  marshaled, err := tc.ToDb(initial)
  test.AssertNotError(t, err, "Could not ToDb")
  t.Logf("M: %T %v", marshaled, marshaled)

  value := reflect.New(reflect.TypeOf(initial)).Interface()
  scanner, ok := tc.FromDb(value)
  test.Assert(t, ok, "FromDb failed")
  if !ok {
    t.FailNow()
    return
  }

  storage := new(string)
  *storage = fmt.Sprintf("%s", marshaled)

  t.Logf("S1: %v %T", storage, storage)
  t.Logf("V1: %v %T", value, value)

  err = scanner.Binder(storage, &out)
  test.AssertNotError(t, err, "Could not scan")
  if err != nil {
    t.FailNow()
    return
  }

  t.Logf("S2: %v %T", storage, storage)
  t.Logf("V2: %v %T", value, value)
  t.Logf("O: %v %T", out, out)

}

func TestAcmeIdentifier(t *testing.T) {
  ai := core.AcmeIdentifier{ "data1", "data2" }
  out := new(core.AcmeIdentifier)

  toFromDbBinder(t, ai, &out)
  test.AssertEquals(t, ai, *out)
}

func TestJsonWebKey(t *testing.T) {
  t.Skip("Causes panic; test not complete.")

  var jwk jose.JsonWebKey
  json.Unmarshal([]byte(JWK_1_JSON), &jwk)
  out := new(jose.JsonWebKey)

  toFromDbBinder(t, jwk, out)
  test.AssertEquals(t, jwk, *out)
}

func TestAcmeStatus(t *testing.T) {
  t.Skip("Causes panic; test not complete.")

  var as core.AcmeStatus
  as = "core.AcmeStatus"
  out := new(core.AcmeStatus)

  toFromDbBinder(t, as, out)
  test.AssertEquals(t, as, *out)
}

func TestOCSPStatus(t *testing.T) {
  t.Skip("Causes panic; test not complete.")

  var os core.OCSPStatus
  os = "core.OCSPStatus"
  out := new(core.OCSPStatus)

  toFromDbBinder(t, os, out)
  test.AssertEquals(t, os, *out)
}