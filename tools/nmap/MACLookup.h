

/* $Id$ */

#ifndef MACLOOKUP_H
#define MACLOOKUP_H

#include <nbase.h>

/* Takes a MAC address and returns the company which has registered the prefix.
   NULL is returned if no vendor is found for the given prefix or if there
   is some other error. */
const char *MACPrefix2Corp(const u8 *prefix);

/* Takes a string and looks through the table for a vendor name which
   contains that string. Sets the initial bytes in mac_data and returns the
   number of nibbles (half-bytes) set for the first matching entry found. If no
   entries match, leaves mac_data untouched and returns false.  Note that this
   is not particularly efficient and so should be rewritten if it is
   called often */
int MACCorp2Prefix(const char *vendorstr, u8 *mac_data);

#endif /* MACLOOKUP_H */
