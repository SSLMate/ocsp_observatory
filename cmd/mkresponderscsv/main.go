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
	"encoding/asn1"
	"math/big"
	"encoding/csv"
	"encoding/hex"
	"database/sql"
	"log"
	"time"
	"os"

	_ "github.com/lib/pq"
)

func serialToString(bytes []byte) string {
	if len(bytes) == 0 {
		return ""
	}

	serial := big.NewInt(0)
	if rest, err := asn1.Unmarshal(bytes, &serial); err != nil {
		log.Fatalf("Error parsing serial number: %s", err)
	} else if len(rest) > 0 {
		log.Fatalf("Error parsing serial number: trailing garbage: %v", rest)
	}
	return serial.Text(16)
}
func main() {
	db, err := sql.Open("postgres", os.Getenv("OCSPOBSERVATORY_DB"))
	if err != nil {
		log.Fatalf("Error opening database: %s", err)
	}

	rows, err := db.Query("SELECT uri,issuer_key_sha256,issuer_name_sha256,issuer_key_sha1,issuer_name_sha1,cert_sha256,cert_serial,cert_expiration,sha1_cert_sha256,sha1_cert_serial,sha1_cert_expiration FROM ocspresponders")
	if err != nil {
		log.Fatalf("Database error: %s", err)
	}
	csvwriter := csv.NewWriter(os.Stdout)
	csvwriter.Write([]string{"URI",
				 "Issuer Name Hash (SHA-1)",
				 "Issuer Key Hash (SHA-1)",
				 "Issuer Name Hash (SHA-256)",
				 "Issuer Key Hash (SHA-256)",
				 "Example Certificate Hash (SHA-256)",
				 "Serial Number of Unexpired Certificate",
				 "Serial Number of Unexpired SHA-1 Certificate",
	})

	for rows.Next() {
		var uri string
		var issuerKeySha256 []byte
		var issuerNameSha256 []byte
		var issuerKeySha1 []byte
		var issuerNameSha1 []byte
		var certSha256 []byte
		var certSerialBytes []byte
		var certExpiration *time.Time
		var sha1CertSha256 []byte
		var sha1CertSerialBytes []byte
		var sha1CertExpiration *time.Time
		var exampleCertSha256 []byte

		if err := rows.Scan(&uri, &issuerKeySha256, &issuerNameSha256, &issuerKeySha1, &issuerNameSha1, &certSha256, &certSerialBytes, &certExpiration, &sha1CertSha256, &sha1CertSerialBytes, &sha1CertExpiration); err != nil {
			log.Fatalf("Database error: %s", err)
		}

		if len(certSha256) > 0 {
			exampleCertSha256 = certSha256
		} else if len(sha1CertSha256) > 0 {
			exampleCertSha256 = sha1CertSha256
		}
		if certExpiration != nil && certExpiration.Before(time.Now()) {
			certSha256 = nil
			certSerialBytes = nil
		}
		if sha1CertExpiration != nil && sha1CertExpiration.Before(time.Now()) {
			sha1CertSha256 = nil
			sha1CertSerialBytes = nil
		}

		cols := []string{
			uri,
			hex.EncodeToString(issuerNameSha1),
			hex.EncodeToString(issuerKeySha1),
			hex.EncodeToString(issuerNameSha256),
			hex.EncodeToString(issuerKeySha256),
			hex.EncodeToString(exampleCertSha256),
			serialToString(certSerialBytes),
			serialToString(sha1CertSerialBytes),
		}
		csvwriter.Write(cols)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		log.Fatalf("Database error: %s", err)
	}
	csvwriter.Flush()
}
