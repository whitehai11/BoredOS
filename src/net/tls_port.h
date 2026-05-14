// Copyright (c) 2026 maro (mail@mgoth.de)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.

#ifndef TLS_PORT_H
#define TLS_PORT_H

// call once at boot, before lwip_init()
void tls_port_init(void);

#endif
