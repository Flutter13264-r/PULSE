
/* $Id$ */

#include "nmap.h"

#include <map>

/* Character pool memory allocation */
#include "MACLookup.h"
#include "NmapOps.h"
#include "nmap_error.h"
#include "string_pool.h"

extern NmapOps o;

typedef std::map<u64, const char *> MacMap;
MacMap MacTable;

static inline u64 nibble(char hex) {
  return (hex & 0xf) + ((hex & 0x40) ? 9 : 0);
}

static void mac_prefix_init() {
  static int initialized = 0;
  if (initialized) return;
  initialized = 1;
  char filename[256];
  FILE *fp;
  char line[128];
  u64 pfx;
  const char *endptr, *vendor;
  int lineno = 0;

  /* Now it is time to read in all of the entries ... */
  if (nmap_fetchfile(filename, sizeof(filename), "nmap-mac-prefixes") != 1){
    error("Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed");
    return;
  }

  fp = fopen(filename, "r");
  if (!fp) {
    gh_perror("Unable to open %s.  Ethernet vendor correlation will not be performed ", filename);
    return;
  }
  /* Record where this data file was found. */
  o.loaded_data_files["nmap-mac-prefixes"] = filename;

  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    if (*line == '#') continue;
    if (!isxdigit((int) (unsigned char) *line)) {
      error("Parse error on line #%d of %s. Giving up parsing.", lineno, filename);
      break;
    }
    /* First grab the prefix */
    endptr = line;
    while(*endptr && isxdigit((int) (unsigned char) *endptr)) endptr++;
    switch (endptr - line) {
      case 6:
        /* MA-L: 24 bits */
        pfx = (nibble(line[0]) << 20) + (nibble(line[1]) << 16)
            + (nibble(line[2]) << 12) + (nibble(line[3]) << 8)
            + (nibble(line[4]) << 4)  +  nibble(line[5])
            + ((u64)6 << 36);
        break;
      case 7:
        /* MA-M: 28 bits */
        pfx = (nibble(line[0]) << 24) + (nibble(line[1]) << 20)
            + (nibble(line[2]) << 16) + (nibble(line[3]) << 12)
            + (nibble(line[4]) << 8)  + (nibble(line[5]) << 4)
            +  nibble(line[6])
            + ((u64)7 << 36);
        break;
      case 9:
        /* MA-S: 36 bits */
        pfx = (nibble(line[0]) << 32) + (nibble(line[1]) << 28)
            + (nibble(line[2]) << 24) + (nibble(line[3]) << 20)
            + (nibble(line[4]) << 16) + (nibble(line[5]) << 12)
            + (nibble(line[6]) << 8)  + (nibble(line[7]) << 4)
            +  nibble(line[8])
            + ((u64)9 << 36);
        break;
      default:
        error("Parse error on line #%d of %s. Giving up parsing.", lineno, filename);
        endptr = NULL; // force failure below
        break;
    }
    if (!endptr || !isspace((int) (unsigned char) *endptr)) {
      error("Parse error on line #%d of %s. Giving up parsing.", lineno, filename);
      break;
    }
    /* Now grab the vendor */
    while(*endptr && isspace((int) (unsigned char) *endptr)) endptr++;
    assert(*endptr);
    vendor = endptr;
    while(*endptr && *endptr != '\n' && *endptr != '\r') endptr++;

    std::pair<MacMap::iterator, bool> status = MacTable.insert(std::pair<u64, const char *>(pfx, string_pool_substr(vendor, endptr)));

    if (!status.second && o.debugging > 1)
      error("MAC prefix %0*lX is duplicated in %s; ignoring duplicates.", (int)(pfx >> 36), pfx & 0xfffffffffL, filename);
  }

  fclose(fp);
  return;
}


static const char *findMACEntry(u64 prefix) {
  MacMap::const_iterator i;

  i = MacTable.find(prefix);
  if (i == MacTable.end())
    return NULL;

  return i->second;
}

/* Takes 6-byte MAC address and returns the company which has registered the prefix.
   NULL is returned if no vendor is found for the given prefix or if there
   is some other error. */
const char *MACPrefix2Corp(const u8 *prefix) {
  u64 key = 0;
  const char *corp = NULL;

  if (!prefix) fatal("%s called with a NULL prefix", __func__);
  mac_prefix_init();

  /* MA-S: 36 bits (9 nibbles)*/
  key = ((u64)prefix[0] << 28) + (prefix[1] << 20) + (prefix[2] << 12) + (prefix[3] << 4) + (prefix[4] >> 4);
  corp = findMACEntry(((u64)9 << 36) + key);
  if (corp)
    return corp;

  /* MA-M: 28 bits (7 nibbles) */
  key = key >> 8;
  corp = findMACEntry(((u64)7 << 36) + key);
  if (corp)
    return corp;

  /* MA-L: 24 bits (6 nibbles)*/
  key = key >> 4;
  corp = findMACEntry(((u64)6 << 36) + key);

  return corp;
}

/* Takes a string and looks through the table for a vendor name which
   contains that string. Sets the initial bytes in mac_data and returns the
   number of nibbles (half-bytes) set for the first matching entry found. If no
   entries match, leaves mac_data untouched and returns false.  Note that this
   is not particularly efficient and so should be rewritten if it is
   called often */
int MACCorp2Prefix(const char *vendorstr, u8 *mac_data) {
  MacMap::const_iterator i;

  if (!vendorstr) fatal("%s: vendorstr is NULL", __func__);
  if (!mac_data) fatal("%s: mac_data is NULL", __func__);
  mac_prefix_init();

  for (i = MacTable.begin(); i != MacTable.end(); i++) {
    if (strcasestr(i->second, vendorstr)) {
      int len = i->first >> 36;
      int j = 0;
      u64 pfx = i->first;
      switch (len) {
        case 9:
          mac_data[j++] = (pfx >> 28) & 0xff;
        case 7:
          mac_data[j++] = (pfx >> 20) & 0xff;
          pfx = pfx << 4;
        case 6:
          mac_data[j++] = (pfx >> 16) & 0xff;
          mac_data[j++] = (pfx >> 8) & 0xff;
          mac_data[j++] = (pfx) & 0xff;
          break;
        default:
          break;
      }
      assert(j == (len + 1) / 2);
      return len;
    }
  }
  return 0;
}
