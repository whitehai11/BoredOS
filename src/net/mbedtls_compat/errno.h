// Copyright (c) 2026 maro (mail@mgoth.de)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.

// errno stub for mbedTLS — we use lwIP not POSIX sockets so these are mostly dead code
#ifndef _BOREDOS_COMPAT_ERRNO_H
#define _BOREDOS_COMPAT_ERRNO_H

#define EPERM   1
#define ENOENT  2
#define EINTR   4
#define EIO     5
#define ENOMEM  12
#define EACCES  13
#define EEXIST  17
#define ENODEV  19
#define EINVAL  22
#define ENOSPC  28
#define EAGAIN  35
#define EWOULDBLOCK EAGAIN
#define ENOTSUP 48

static int _bored_errno = 0;
#define errno _bored_errno

#endif
