#ifndef R_BIN_MDT_H
#define R_BIN_MDT_H

#include <r_types.h>
#include <r_util.h>
#include <r_bin.h>

// Qualcomm MDT constants
#define QCOM_MDT_TYPE_MASK         0x07000000
#define QCOM_MDT_TYPE_LAYOUT       0x00000000
#define QCOM_MDT_TYPE_SIGNATURE    0x01000000
#define QCOM_MDT_RELOCATABLE       0x08000000

// MDT segment types
typedef enum {
	RZ_BIN_MDT_PART_UNIDENTIFIED = 0,
	RZ_BIN_MDT_PART_ELF = 1,
	RZ_BIN_MDT_PART_MBN = 2,
	RZ_BIN_MDT_PART_COMPRESSED_Q6ZIP = 3,
	RZ_BIN_MDT_PART_COMPRESSED_CLADE2 = 4,
	RZ_BIN_MDT_PART_COMPRESSED_ZLIB = 5
} RBinMdtPartFormat;

// Simple virtual file structure for radare2
typedef struct r_bin_virtual_file {
	char *name;
	RBuffer *buf;
	bool buf_owned;
} RBinVirtualFile;

// Individual MDT part structure
typedef struct r_bin_mdt_part {
	char *name;
	ut64 paddr;
	ut32 pflags;
	bool relocatable;
	bool is_layout;
	RBinMdtPartFormat format;
	
	// Virtual file and mapping
	RBinVirtualFile *vfile;
	RBinMap *map;
	RList *sub_maps;  // For patched ELF maps
	
	// Content containers
	RList *sections;
	RList *symbols;
	RList *relocs;
	
	// Object data based on format
	union {
		void *elf;    // ELFOBJ pointer for ELF parts
		void *mbn;    // SblHeader pointer for MBN parts
	} obj;
	
	// Virtual file names for patches and relocs
	char *patches_vfile_name;
	char *relocs_vfile_name;
} RBinMdtPart;

// Main MDT object
typedef struct r_bin_mdt_obj {
	char *name;
	void *header;  // ELFOBJ pointer for main header
	RList *parts;  // List of RBinMdtPart
} RBinMdtObj;

// MBN header structure for signature segments
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
} SblHeader;

// Function declarations
bool r_bin_mdt_check_buffer(RBuffer *b);
bool r_bin_mdt_check_filename(const char *filename);
bool r_bin_mdt_load_buffer(RBinFile *bf, RBinObject *obj, RBuffer *buf, Sdb *sdb);
void r_bin_mdt_destroy(RBinFile *bf);

RList *r_bin_mdt_virtual_files(RBinFile *bf);
RList *r_bin_mdt_get_maps(RBinFile *bf);
RList *r_bin_mdt_get_entry_points(RBinFile *bf);
RList *r_bin_mdt_symbols(RBinFile *bf);
RList *r_bin_mdt_sections(RBinFile *bf);
RList *r_bin_mdt_relocs(RBinFile *bf);
void r_bin_mdt_print_header(RBinFile *bf);

// Internal helper functions
RBinMdtPart *r_bin_mdt_part_new(const char *name, size_t p_flags);
void r_bin_mdt_part_free(RBinMdtPart *part);
RBinMdtObj *r_bin_mdt_obj_new(void);
void r_bin_mdt_obj_free(RBinMdtObj *obj);

// VirtualFile helpers
RBinVirtualFile *r_bin_virtual_file_new(void);
void r_bin_virtual_file_free(RBinVirtualFile *vf);
RBinVirtualFile *r_bin_virtual_file_clone(RBinVirtualFile *vf);

// Map helpers
RBinMap *r_bin_map_clone(RBinMap *map);

// Symbol/Section/Reloc helpers  
RBinSymbol *r_bin_symbol_clone(RBinSymbol *sym);
RBinSection *r_bin_section_clone(RBinSection *sec);
RBinReloc *r_bin_reloc_clone(RBinReloc *rel);

// MBN support
bool mbn_check_buffer(RBuffer *buf);
bool mbn_read_sbl_header(RBuffer *buf, SblHeader *hdr, ut64 *offset);
void mbn_destroy_obj(SblHeader *obj);
void mbn_header_obj(SblHeader *obj, PrintfCallback printf_fn);

// ELF integration helpers (to be implemented with proper ELF integration)
bool elf_check_buffer_aux(RBuffer *b);
void *Elf32_rz_bin_elf_new_buf(RBuffer *buf, void *opts);
void Elf32_rz_bin_elf_free(void *elf);
bool Elf32_rz_bin_elf_is_big_endian(void *elf);
bool Elf32_rz_bin_elf_has_va(void *elf);
bool Elf32_rz_bin_elf_has_nx(void *elf);
char *Elf32_rz_bin_elf_get_intrp(void *elf);
char *Elf32_rz_bin_elf_get_compiler(void *elf);
char *Elf32_rz_bin_elf_get_arch(void *elf);
char *Elf32_rz_bin_elf_get_cpu(void *elf);
char *Elf32_rz_bin_elf_get_machine_name(void *elf);

// Utility macros
#define qcom_p_flags(pflags) ((pflags) & 0xFF000000)

#endif /* R_BIN_MDT_H */