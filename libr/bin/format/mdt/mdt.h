#ifndef R_BIN_MDT_H
#define R_BIN_MDT_H

#include <r_types.h>
#include <r_util.h>
#include <r_bin.h>

#define MDT_MAGIC_SIZE 4
#define MDT_MAX_PARTS 64

// MDT file header structure
typedef struct {
	ut32 image_id;
	ut32 header_vsn_num;
	ut32 image_src;
	ut32 image_dest_ptr;
	ut32 image_size;
	ut32 code_size;
	ut32 signature_ptr;
	ut32 signature_size;
	ut32 cert_chain_ptr;
	ut32 cert_chain_size;
} MdtImageHeader;

// Individual MDT part
typedef struct r_bin_mdt_part {
	char *name;
	ut64 paddr;
	ut64 vaddr;
	ut64 size;
	ut32 type;
	ut32 attr;
	RBuffer *buf;
} RBinMdtPart;

// Main MDT object
typedef struct r_bin_mdt_obj {
	RBuffer *buf;
	ut64 size;
	ut32 nparts;
	RBinMdtPart **parts;
	MdtImageHeader header;
	
	// ELF segments
	RList *segments;
	RList *sections;
	RList *symbols;
	RList *imports;
	RList *libs;
	RList *relocs;
	RList *maps;
	RList *entries;
	
	// Base addresses
	ut64 baddr;
	bool big_endian;
	int bits;
	char *arch;
	char *machine;
	char *os;
} RBinMdtObj;

// Segment types
typedef enum {
	MDT_SEGMENT_NULL = 0,
	MDT_SEGMENT_LOAD = 1,
	MDT_SEGMENT_DYNAMIC = 2,
	MDT_SEGMENT_INTERP = 3,
	MDT_SEGMENT_NOTE = 4,
	MDT_SEGMENT_SHLIB = 5,
	MDT_SEGMENT_PHDR = 6,
	MDT_SEGMENT_TLS = 7
} MdtSegmentType;

// Function declarations
bool r_bin_mdt_check(RBuffer *buf);
RBinMdtObj *r_bin_mdt_new_buf(RBuffer *buf);
void r_bin_mdt_free(RBinMdtObj *obj);

ut64 r_bin_mdt_get_baddr(RBinMdtObj *obj);
ut64 r_bin_mdt_get_size(RBinMdtObj *obj);
RBinInfo *r_bin_mdt_get_info(RBinMdtObj *obj);

RList *r_bin_mdt_get_entries(RBinMdtObj *obj);
RList *r_bin_mdt_get_sections(RBinMdtObj *obj);
RList *r_bin_mdt_get_symbols(RBinMdtObj *obj);
RList *r_bin_mdt_get_imports(RBinMdtObj *obj);
RList *r_bin_mdt_get_libs(RBinMdtObj *obj);
RList *r_bin_mdt_get_relocs(RBinMdtObj *obj);
RList *r_bin_mdt_get_maps(RBinMdtObj *obj);

// MBN support functions (for MBN files within MDT)
bool r_bin_mbn_check_buffer(RBuffer *buf);
RBinMdtPart *r_bin_mdt_parse_mbn(RBuffer *buf, const char *name);

#endif /* R_BIN_MDT_H */