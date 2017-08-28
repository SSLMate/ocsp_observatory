// Copyright (C) 2017 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"software.sslmate.com/src/certspotter"
)

var (
	oidExtensionAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidAuthorityInfoAccessOcsp      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
)

func getKey(tbs *certspotter.TBSCertificate) ([]byte, error) {
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(tbs.GetRawPublicKey(), &spki); err != nil {
		return nil, err
	}
	return spki.PublicKey.RightAlign(), nil
}

type authorityInfoAccess struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

func getResponderURIs(tbs *certspotter.TBSCertificate) ([]string, error) {
	var uris []string

	for _, aiaExt := range tbs.GetExtension(oidExtensionAuthorityInfoAccess) {
		var aia []authorityInfoAccess
		if rest, err := asn1.Unmarshal(aiaExt.Value, &aia); err != nil {
			return nil, err
		} else if len(rest) > 0 {
			return nil, fmt.Errorf("trailing data in AIA extension: %v", rest)
		}

		for _, item := range aia {
			if !item.Method.Equal(oidAuthorityInfoAccessOcsp) {
				continue
			}
			if item.Location.Tag != 6 { // URI
				continue
			}
			uris = append(uris, string(item.Location.Bytes))
		}
	}

	return uris, nil
}

func getSignatureAlgorithm(tbs *certspotter.TBSCertificate) (*pkix.AlgorithmIdentifier, error) {
	var id pkix.AlgorithmIdentifier
	if rest, err := asn1.Unmarshal(tbs.SignatureAlgorithm.FullBytes, &id); err != nil {
		return nil, fmt.Errorf("failed to parse signature algorithm: %s", err)
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after signature algorithm: %v", rest)
	}
	return &id, nil
}

var (
	oidSignatureSHA1WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSignatureDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSignatureECDSAWithSHA1 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
)

func isSha1(id *pkix.AlgorithmIdentifier) bool {
	return id.Algorithm.Equal(oidSignatureSHA1WithRSA) ||
		id.Algorithm.Equal(oidSignatureDSAWithSHA1) ||
		id.Algorithm.Equal(oidSignatureECDSAWithSHA1)
}
