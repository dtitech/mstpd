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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "io_buffer.h"

#define IO_PAGE_SIZE         4096

void iobuf_init(struct iobuf *buffer)
{
    buffer->size = 0;
    buffer->pos = 0;
    buffer->cap = 0;
    buffer->data = NULL;
}

void iobuf_cleanup(struct iobuf *buffer)
{
    buffer->size = 0;
    buffer->pos = 0;
    buffer->cap = 0;
    if (buffer->data)
    {
        free(buffer->data);
        buffer->data = NULL;
    }
}

int iobuf_resize(struct iobuf *buffer, size_t new_size)
{
    if (buffer->size >= new_size)
        return 0;

    const size_t new_cap = ((new_size + (IO_PAGE_SIZE - 1)) / IO_PAGE_SIZE)
                             * IO_PAGE_SIZE;

    void *new_data = realloc(buffer->data, new_cap);
    if (!new_data)
        return ENOMEM;

    buffer->data = (char *)new_data;
    buffer->cap = new_cap;
    return 0;
}

int iobuf_read_from_fd(struct iobuf *buffer, int filedes)
{
    size_t rd;

    for (;;)
    {
        size_t bfree = buffer->cap - buffer->size;
        if (bfree < 1024)
        {
            if (iobuf_resize(buffer, buffer->cap + 4096))
                return ENOMEM;

            bfree = buffer->cap - buffer->size;
        }
        rd = read(filedes, buffer->data, bfree);
        if (rd > 0)
        {
            buffer->size += rd;
        }
        else if (rd == 0)
        {
             break;
        }
        else
        {
            return -1;
        }
    }

    return 0;
}

int iobuf_write_to_fd(int filedes, struct iobuf *buffer)
{
    for (;;)
    {
        size_t wsize = buffer->size - buffer->pos;
        if (!wsize)
            return 0;

        if (wsize > 65536)
        {
            wsize = 65536;
        }

        size_t wr = write(filedes, &buffer->data[buffer->pos], wsize);
        if (wr < 0)
        {
            return -1;
        }
    }

    return 0;
}

int iobuf_readcleanline(struct iobuf *buffer, char **begin)
{
    size_t bpos = buffer->pos;
    size_t bsize = buffer->size;

    if (bpos >= bsize)
        return -1;

    *begin = &buffer->data[bpos];
    size_t bbegin = bpos;

    for (; bpos < bsize; bpos++)
    {
        const char bchar = buffer->data[bpos];
        if (bchar == 0x0A)
        {
            break;
        }
    }

    buffer->pos = (bpos < bsize) ? bpos + 1 : bpos;

    for (; bpos > bbegin; bpos--)
    {
        const char bchar = buffer->data[bpos - 1];
        if ((bchar != 0x0D) && (bchar != 0x09) && (bchar != 0x20))
            break;
    }

    size_t blen = bpos - bbegin;
    return blen + 1;
}
