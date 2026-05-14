// Copyright (c) 2026 maro (mail@mgoth.de)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.

// embedded CA bundle: ISRG Root X1, DigiCert G2, USERTrust RSA, GTS R1+R2
// all in PEM format, concatenated — mbedtls parses the whole blob at once
#ifndef CA_BUNDLE_H
#define CA_BUNDLE_H

extern const unsigned char g_ca_bundle[];
extern const unsigned int  g_ca_bundle_len;

#endif
