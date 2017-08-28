-- Copyright (C) 2017 Opsmate, Inc.
--
-- This Source Code Form is subject to the terms of the Mozilla
-- Public License, v. 2.0. If a copy of the MPL was not distributed
-- with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
--
-- This software is distributed WITHOUT A WARRANTY OF ANY KIND.
-- See the Mozilla Public License for details.

CREATE TABLE ocspresponders (
	id			bigserial	NOT NULL PRIMARY KEY,
	uri			text		NOT NULL,
	issuer_key_sha256	bytea		NOT NULL,
	issuer_name_sha256	bytea		NOT NULL,
	issuer_key_sha1		bytea		NOT NULL,
	issuer_name_sha1	bytea		NOT NULL,
	cert_sha256		bytea,
	cert_serial		bytea,
	cert_expiration		timestamp,
	sha1_cert_sha256	bytea,
	sha1_cert_serial	bytea,
	sha1_cert_expiration	timestamp
);
CREATE UNIQUE INDEX ocspresponders_issuer ON ocspresponders (uri, issuer_key_sha256, issuer_name_sha256);
