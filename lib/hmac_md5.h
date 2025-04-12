/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

#ifndef HMAC_MD5_H
#define HMAC_MD5_H

/* #define HMAC_MDS_TEST_FUNCTIONS */

/* 13.7, Table 13-1 */
#define HMAC_KEY    {0x13, 0xAC, 0x06, 0xA6, 0x2E, 0x47, 0xFD, 0x51, \
                     0xF9, 0x5D, 0x2B, 0xA2, 0x43, 0xCD, 0x03, 0x46}
void hmac_md5(unsigned char * text, int text_len, unsigned char * key,
              int key_len, caddr_t digest);
#ifdef HMAC_MDS_TEST_FUNCTIONS
bool MD5TestSuite(void);
#endif /* HMAC_MDS_TEST_FUNCTIONS */

#endif /* HMAC_MD5_H */
