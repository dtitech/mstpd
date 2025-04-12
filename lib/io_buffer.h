/*****************************************************************************
  Copyright (c) 2025 DTI Technologies s.r.o.

  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by the Free
  Software Foundation; either version 2 of the License, or (at your option)
  any later version.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc., 59
  Temple Place - Suite 330, Boston, MA  02111-1307, USA.

  The full GNU General Public License is included in this distribution in the
  file called LICENSE.

  Authors: Tomas Kyzlink <tkyzlink@dtitech.cz>

******************************************************************************/

#ifndef IO_BUFFER_H
#define IO_BUFFER_H

#include <stdio.h>

struct iobuf
{
    size_t size;       /* size of data in buffer */
    size_t pos;        /* position for next read */
    size_t cap;        /* total allocated buffer size */
    char *data;
};

void iobuf_init(struct iobuf *buffer);
void iobuf_cleanup(struct iobuf *buffer);

int iobuf_resize(struct iobuf *buffer, size_t new_size);

int iobuf_read_from_fd(struct iobuf *buffer, int filedes);
int iobuf_write_to_fd(int filedes, struct iobuf *buffer); /* from current pos */

int iobuf_readcleanline(struct iobuf *buffer, char ** begin); /* reads line from file, return value length+1 */

#endif /* IO_BUFFER */
