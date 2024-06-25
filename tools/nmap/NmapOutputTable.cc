
/* $Id$ */

#ifdef WIN32
#include "nmap_winconfig.h"
#endif

#include "NmapOutputTable.h"
#include "nmap_error.h"

#include <stdlib.h>

NmapOutputTable::NmapOutputTable(int nrows, int ncols) {
  numRows = nrows;
  numColumns = ncols;
  assert(numRows > 0);
  assert(numColumns > 0);
  table = (struct NmapOutputTableCell *) safe_zalloc(sizeof(struct NmapOutputTableCell) * nrows * ncols);
  maxColLen = (int *) safe_zalloc(sizeof(*maxColLen) * ncols);
  itemsInRow = (int *) safe_zalloc(sizeof(*itemsInRow) * nrows);
  tableout = NULL;
  tableoutsz = 0;
}

NmapOutputTable::~NmapOutputTable() {
  unsigned int col, row;
  struct NmapOutputTableCell *cell;

  for(row = 0; row < numRows; row++) {
    for(col = 0; col < numColumns; col++) {
      cell = getCellAddy(row, col);
      if (cell->weAllocated) {
        assert(cell->str);
        free(cell->str);
      }
    }
  }

  free(table);
  free(maxColLen);
  free(itemsInRow);
  if (tableout) free(tableout);
}

void NmapOutputTable::addItem(unsigned int row, unsigned int column, bool fullrow,
                                bool copy, const char *item, int itemlen) {
  struct NmapOutputTableCell *cell;
  int mc = maxColLen[column];

  addItem(row, column, copy, item, itemlen);

  if(fullrow) {
    maxColLen[column] = mc;
    cell = getCellAddy(row, column);
    cell->fullrow = fullrow;
  }
  return;
}

void NmapOutputTable::addItem(unsigned int row, unsigned int column, bool copy, const char *item,
                              int itemlen) {
  struct NmapOutputTableCell *cell;

  assert(row < numRows);
  assert(column < numColumns);

  if (itemlen < 0)
    itemlen = strlen(item);

  if (itemlen == 0)
    return;

  cell = getCellAddy(row, column);
  assert(cell->str == NULL); // I'll worry about replacing members if I ever need it
  itemsInRow[row]++;

  cell->strlength = itemlen;

  if (copy) {
    cell->str = (char *) safe_malloc(itemlen + 1);
    memcpy(cell->str, item, itemlen);
    cell->str[itemlen] = '\0';
  } else {
    cell->str = (char *) item;
  }
  cell->weAllocated = copy;

  if (maxColLen[column] < itemlen)
    maxColLen[column] = itemlen;

  return;
}

void NmapOutputTable::addItemFormatted(unsigned int row,
                                          unsigned int column,
                                          bool fullrow,
                                          const char *fmt, ...) {
  struct NmapOutputTableCell *cell;
  int mc = maxColLen[column];
  unsigned int res;
  va_list ap;
  va_start(ap,fmt);
  char buf[4096];
  res = Vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if (res >= sizeof(buf))
    fatal("NmapOutputTable only supports adding up to 4096 to a cell via %s.", __func__);

  addItem(row, column, fullrow, true, buf, res);

  if(fullrow) {
    maxColLen[column] = mc;
    cell = getCellAddy(row, column);
    cell->fullrow = fullrow;
  }
}

/* True if every column in nrow is empty */
bool NmapOutputTable::emptyRow(unsigned int nrow) {
        NmapOutputTableCell *cell;
        unsigned int col;
        bool isEmpty = true;

        assert(nrow < numRows);

        for(col = 0 ; col < numColumns; col++) {
                cell = getCellAddy(nrow, col);
                if(cell->strlength > 0) {
                        isEmpty = false;
                        break;
                }
        }
        return isEmpty;
}

 // This function sticks the entire table into a character buffer.
 // Note that the buffer is likely to be reused if you call the
 // function again, and it will also be invalidated if you free the
 // table. If size is not NULL, it will be filled with the size of
 // the ASCII table in bytes (not including the terminating NUL)
 // All blank rows are removed from the returned string
char *NmapOutputTable::printableTable(int *size) {
  unsigned int col, row;
  int p = 0; /* The offset into tableout */
  int clen = 0;
  int i;
  struct NmapOutputTableCell *cell;
  int validthisrow;

  if (tableoutsz == 0) {
    tableoutsz = 512; /* Start us off with half a k */
    tableout = (char *) safe_malloc(tableoutsz);
  }

  for(row = 0; row < numRows; row++) {
    validthisrow = 0;

    if(emptyRow(row))
        continue;

    cell = getCellAddy(row, 0);
    if(cell->fullrow && cell->strlength > 0) {
      /* Full rows are easy, just make sure we have the space + \n\0 */
      if (cell->strlength + p + 2 > tableoutsz) {
        tableoutsz = (cell->strlength + p + 2) * 2;
        tableout = (char *) safe_realloc(tableout, tableoutsz);
      }
      memcpy(tableout + p, cell->str,  cell->strlength);
      p += cell->strlength;
    } else {
      for(col = 0; col < numColumns; col++) {
        cell = getCellAddy(row, col);
        clen = maxColLen[col];
        /* Cells get padded with an extra space + \n\0 */
        if (clen + p + 3 > tableoutsz) {
          tableoutsz = (cell->strlength + p + 2) * 2;
          tableout = (char *) safe_realloc(tableout, tableoutsz);
        }
        if (cell->strlength > 0) {
          memcpy(tableout + p, cell->str,  cell->strlength);
          p += cell->strlength;
          validthisrow++;
        }
        // No point leaving trailing spaces ...
        if (validthisrow < itemsInRow[row]) {
          for(i=cell->strlength; i <= clen; i++) // one extra because of space between columns
            *(tableout + p++) = ' ';
        }
      }
    }
    *(tableout + p++) = '\n';
  }
  *(tableout + p) = '\0';

  if (size) *size = p;
  return tableout;
}
