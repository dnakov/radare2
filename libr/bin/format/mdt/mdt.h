#ifndef R_BIN_MDT_H
#define R_BIN_MDT_H

#include <r_types.h>
#include <r_util.h>
#include <r_bin.h>

#define qcom_p_flags(p_flags) ((p_flags) >> 24)

/**
 * \brief Mask for the segment type.
 */
#define QCOM_MDT_TYPE_MASK (7 << 24)
/**
 * \brief Bits set for the first firmware part.
 */
#define QCOM_MDT_TYPE_LAYOUT (7 << 24)
/**
 * \brief Type of the signature segment.
 */
#define QCOM_MDT_TYPE_SIGNATURE (2 << 24)
/**
 * \brief Relocatable segment.
 */
#define QCOM_MDT_RELOCATABLE (1 << 27)

/**
 * \brief The segment type/p_type as it is in the ELF.
 */
typedef ut32 RBinMdtPFlags;

typedef enum r_bin_mdt_seg_type {
	R_BIN_MDT_PART_UNIDENTIFIED = 0,
	R_BIN_MDT_PART_ELF, ///< An ELF file.
	R_BIN_MDT_PART_MBN, ///< The secure boot authentication signature segment.
	R_BIN_MDT_PART_COMPRESSED_Q6ZIP, ///< Q6ZIP compressed segment (if identified).
	R_BIN_MDT_PART_COMPRESSED_CLADE2, ///< CLADE2 compressed segment (if identified).
	R_BIN_MDT_PART_COMPRESSED_ZLIB, ///< Zlib compressed segment (if identified).
} RBinMdtSegBinFormat;

// Use the existing MBN structure from radare2
typedef struct sbl_header {
	ut32 load_index; // image_id in Rizin version
	ut32 version;    // (flash_partition_version) 3 = nand
	ut32 paddr;      // This + 40 is the start of the code in the file
	ut32 vaddr;	 // Where it's loaded in memory
	ut32 psize;      // code_size + signature_size + cert_chain_size
	ut32 code_pa;    // Only what's loaded to memory
	ut32 sign_va;
	ut32 sign_sz;
	ut32 cert_va;    // Max of 3 certs?
	ut32 cert_sz;
} SblHeader;

/**
 * \brief An MDT firmware part and some descriptions.
 */
typedef struct {
	char *name; ///< The name of the part. Should be equal to the base name of the file.
	bool relocatable; ///< True if the Qualcomm relocatable flag is set for the segment.
	bool is_layout; ///< True if the ELF segment is the firmware layout.
	RBinMdtSegBinFormat format; ///< The segment type.
	RBinMdtPFlags pflags; ///< The segment p_flags.
	RBuffer *buf; ///< The buffer for the `.bNN` file.
	union {
		void *elf; ///< Set if this part is an ELF (ELFOBJ pointer).
		SblHeader *mbn; ///< Set if this part is an MBN auth segment.
	} obj;
	RBinAddr *entry; ///< The entry point, if any.
	RBinMap *map; ///< The mapping of the part in memory.
	/**
	 * \brief The physical address as in the layout. This is not the same as map->addr!
	 * Because map is used to read from the files. So it has be zero (to not mess up the reading offsets).
	 */
	ut64 paddr;
	char *patches_vfile_name; ///< Name of the vfile of patches to the binary. If NULL, no patches are supported.
	char *relocs_vfile_name; ///< Name of the vfile of relocs to the binary. If NULL, no relocs are supported.
	RList /*<RBinSymbol *>*/ *symbols; ///< Symbols in this part.
	RList /*<RBinReloc *>*/ *relocs; ///< Relocs in this part.
	RList /*<RBinSection *>*/ *sections; ///< Sections in this part.
	RList /*<RBinMap *>*/ *sub_maps; ///< Maps of the obj, if any.
} RBinMdtPart;

typedef struct {
	char *name; ///< The name of the peripheral firmware. E.g. modem, adsp, cdsp or npu.
	void *header; ///< The ELF header of the whole firmware. From `<peripheral>.mdt`.
	RList /*<RBinMdtPart *>*/ *parts; ///< All parts from the `<peripheral>.bNN` files.
} RBinMdtObj;

// Forward declarations for functions that will be implemented
bool r_bin_mdt_part_new(RBinMdtPart **part, const char *name, size_t p_flags);
void r_bin_mdt_part_free(RBinMdtPart *part);
bool r_bin_mdt_obj_new(RBinMdtObj **obj);
void r_bin_mdt_obj_free(RBinMdtObj *obj);
bool r_bin_mdt_check_filename(const char *filename);
bool r_bin_mdt_load_buffer(RBinFile *bf, RBinObject *obj, RBuffer *buf, Sdb *sdb);
bool r_bin_mdt_check_buffer(RBuffer *b);
void r_bin_mdt_destroy(RBinFile *bf);
RList *r_bin_mdt_get_maps(RBinFile *bf);
RList *r_bin_mdt_get_entry_points(RBinFile *bf);
RList *r_bin_mdt_symbols(RBinFile *bf);
void r_bin_mdt_print_header(RBinFile *bf);
RList *r_bin_mdt_sections(RBinFile *bf);
RList *r_bin_mdt_relocs(RBinFile *bf);

// ELF integration helpers
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

#endif /* R_BIN_MDT_H */