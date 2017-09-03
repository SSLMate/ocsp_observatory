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
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/asn1"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"software.sslmate.com/src/certspotter"
	"software.sslmate.com/src/certspotter/cmd"
	"software.sslmate.com/src/certspotter/ct"
)

func DefaultStateDir() string {
	if envVar := os.Getenv("OCSPSPOTTER_STATE_DIR"); envVar != "" {
		return envVar
	} else {
		return cmd.DefaultStateDir("ocspspotter")
	}
}

var stateDir = flag.String("state_dir", DefaultStateDir(), "Directory for storing state")

type responderInfo struct {
	uris           []string
	issuerName     []byte
	issuerKey      []byte
	isSHA1         bool
	certSHA256     []byte
	certSerial     []byte
	certExpiration time.Time
}

func sha1sum(data []byte) []byte {
	sum := sha1.Sum(data)
	return sum[:]
}
func sha256sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func (info *responderInfo) insert(stmt *sql.Stmt) error {
	for _, uri := range info.uris {
		_, err := stmt.Exec(uri, sha256sum(info.issuerKey), sha256sum(info.issuerName),
				    sha1sum(info.issuerKey), sha1sum(info.issuerName),
				    info.certSHA256, info.certSerial, info.certExpiration)
		if err != nil {
			return err
		}
	}
	return nil
}

func examineCert(certBytes []byte, issuerBytes []byte) (*responderInfo, error) {
	var info responderInfo
	var err error

	info.certSHA256 = sha256sum(certBytes)
	cert, err := certspotter.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("Parsing certificate failed: %s", err)
	}
	certTBS, err := cert.ParseTBSCertificate()
	if err != nil {
		return nil, fmt.Errorf("Parsing TBS certificate failed: %s", err)
	}

	info.uris, err = getResponderURIs(certTBS)
	if err != nil {
		return nil, fmt.Errorf("Extracting responder URI failed: %s", err)
	}
	if len(info.uris) == 0 {
		return nil, nil
	}

	if !(certTBS.SerialNumber.Class == asn1.ClassUniversal && certTBS.SerialNumber.Tag == asn1.TagInteger) {
		return nil, fmt.Errorf("Certificate has non-integer serial number: class %d, tag %d", certTBS.SerialNumber.Class, certTBS.SerialNumber.Tag)
	}
	info.certSerial = certTBS.SerialNumber.Bytes
	validity, err := certTBS.ParseValidity()
	if err != nil {
		return nil, fmt.Errorf("Parsing certificate validity failed: %s", err)
	}
	if validity.NotBefore.After(time.Now().Add(24 * time.Hour)) {
		return nil, nil
	}
	info.certExpiration = validity.NotAfter
	signatureAlgorithm, err := getSignatureAlgorithm(certTBS)
	if err != nil {
		return nil, fmt.Errorf("Parsing certificate signature algorithm failed: %s", err)
	}
	info.isSHA1 = isSha1(signatureAlgorithm)

	issuer, err := certspotter.ParseCertificate(issuerBytes)
	if err != nil {
		return nil, fmt.Errorf("Parsing issuer certificate failed: %s", err)
	}
	issuerTBS, err := issuer.ParseTBSCertificate()
	if err != nil {
		return nil, fmt.Errorf("Parsing issuer TBS certificate failed: %s", err)
	}
	info.issuerName = issuerTBS.GetRawSubject()
	info.issuerKey, err = getKey(issuerTBS)
	if err != nil {
		return nil, fmt.Errorf("Parsing issuer key failed: %s", err)
	}

	return &info, nil
}

var db *sql.DB
var wg sync.WaitGroup
var infoChan chan *responderInfo

func processEntry(scanner *certspotter.Scanner, entry *ct.LogEntry) {
	fullChain := certspotter.GetFullChain(entry)

	for i := range fullChain {
		if i+1 >= len(fullChain) {
			break
		}
		info, err := examineCert(fullChain[0], fullChain[1])
		if err != nil {
			log.Printf("%s@%d.%d [%x]: %s", scanner.LogUri, entry.Index, i, sha256sum(fullChain[0]), err)
			continue
		}
		if info == nil {
			continue
		}

		infoChan <- info
	}
}

func doInserts() {
	var err error
	var tx *sql.Tx
	var insertStmt *sql.Stmt
	var insertSha1Stmt *sql.Stmt
	txcount := 0

	for item := range infoChan {
		if tx == nil {
			tx, err = db.Begin()
			if err != nil {
				log.Fatalf("Database error: %s", err)
			}
			insertStmt, err = tx.Prepare("INSERT INTO ocspresponders (uri, issuer_key_sha256, issuer_name_sha256, issuer_key_sha1, issuer_name_sha1, cert_sha256, cert_serial, cert_expiration) VALUES($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (uri, issuer_key_sha256, issuer_name_sha256) DO UPDATE SET cert_sha256 = $6, cert_serial = $7, cert_expiration = $8 WHERE $8 > ocspresponders.cert_expiration OR ocspresponders.cert_expiration IS NULL")
			if err != nil {
				log.Fatalf("Database error: %s", err)
			}
			insertSha1Stmt, err = tx.Prepare("INSERT INTO ocspresponders (uri, issuer_key_sha256, issuer_name_sha256, issuer_key_sha1, issuer_name_sha1, sha1_cert_sha256, sha1_cert_serial, sha1_cert_expiration) VALUES($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (uri, issuer_key_sha256, issuer_name_sha256) DO UPDATE SET sha1_cert_sha256 = $6, sha1_cert_serial = $7, sha1_cert_expiration = $8 WHERE $8 > ocspresponders.sha1_cert_expiration OR ocspresponders.sha1_cert_expiration IS NULL")
			if err != nil {
				log.Fatalf("Database error: %s", err)
			}
		}

		if item.isSHA1 {
			err = item.insert(insertSha1Stmt)
		} else {
			err = item.insert(insertStmt)
		}
		if err != nil {
			log.Fatalf("Database insert error: %s", err)
		}

		txcount++
		if txcount == 10000 {
			if err := tx.Commit(); err != nil {
				log.Fatalf("Database error: %s", err)
			}
			tx = nil
			txcount = 0
		}
	}
	if tx != nil {
		if err := tx.Commit(); err != nil {
			log.Fatalf("Database error: %s", err)
		}
	}
	wg.Done()
}

func main() {
	flag.Parse()

	var err error
	db, err = sql.Open("postgres", os.Getenv("OCSPOBSERVATORY_DB"))
	if err != nil {
		log.Fatalf("Error opening database: %s", err)
	}

	infoChan = make(chan *responderInfo, 1000)
	wg.Add(1)
	go doInserts()
	exitcode := cmd.Main(*stateDir, processEntry)
	close(infoChan)
	wg.Wait()
	os.Exit(exitcode)
}
