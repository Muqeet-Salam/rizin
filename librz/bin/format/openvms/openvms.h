// SPDX-FileCopyrightText: 2026 Muqeet-Salam <muqeetsalam168@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file OpenVMS executable format support (VAX and Alpha architectures)
 *
 * Detection heuristic:
 * - VAX magic: 0xB0 0x00 0x30 0x00 at offset 0
 * - Alpha magic: 0x03 0x00 0x00 0x00 at offset 0
 *
 * Reference: https://links.twibright.com/download/binaries/openvms/
 */
 
#ifndef RZ_BIN_OPENVMS_H
#define RZ_BIN_OPENVMS_H
 
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
 
/* Magic values for architecture detection */
#define VMS_VAX_MAGIC_MAJOR     0x00B0
#define VMS_VAX_MAGIC_MINOR     0x0030
#define VMS_ALPHA_MAGIC_MAJOR   0x0003
#define VMS_ALPHA_MAGIC_MINOR   0x0000
#define VMS_OLB_MAGIC           0x00000201  /* Object Library */
#define VMS_OBJ_MAGIC           0x00000101  /* Object Module */
 
#define VMS_MIN_FILE_SIZE       68
#define VMS_VAX_EIHD_SIZE       68
#define VMS_ALPHA_EIHD_SIZE     256
#define VMS_PAGE_SIZE 			512
#define VMS_ALPHA_ISD_SIZE      36

#define VMS_VAX_IMAGE_NAME_OFF  0x60
#define VMS_VAX_VERSION_OFF     0x88
#define VMS_VAX_VMSVER_OFF      0xA0

#define VMS_ALPHA_IMAGE_NAME_OFF 0xC8
#define VMS_ALPHA_VERSION_OFF    0xF0
#define VMS_ALPHA_VMSVER_OFF     0x100
 
/* Architecture types */
typedef enum {
	VMS_ARCH_UNKNOWN = 0,
	VMS_ARCH_VAX,
	VMS_ARCH_ALPHA,
} VMSArch;
 
/* File types */
typedef enum {
	VMS_TYPE_UNKNOWN = 0,
	VMS_TYPE_EXE,       ///< Executable image
	VMS_TYPE_OBJ,       ///< Object module
	VMS_TYPE_OLB,       ///< Object library (archive)
} VMSFileType;
 
/**
 * \brief VAX Executable Image Header (EIHD)
 * Size: 68 bytes (0x44)
 */
typedef struct vms_vax_eihd_t {
	ut16 majorid;           ///< 0x00: Major ID - 0x00B0 for VAX
	ut16 minorid;           ///< 0x02: Minor ID - 0x0030 for VAX
	ut16 eihd_size;         ///< 0x04: Size of EIHD (68 bytes)
	ut16 isdoff;            ///< 0x06: Offset to Image Section Descriptors
	ut32 unknown1;          ///< 0x08: Unknown
	ut8  ident[8];          ///< 0x0C: Image identification
	ut16 version;           ///< 0x14: Version
	ut16 unknown2;          ///< 0x16: Unknown
	ut32 unknown3[4];       ///< 0x18: Unknown fields
	ut32 unknown4[4];       ///< 0x28: Unknown fields
	ut32 unknown5;          ///< 0x38: Unknown
	ut32 unknown6;          ///< 0x3C: Unknown
	ut32 unknown7;          ///< 0x40: Unknown
} VMSVaxEIHD;
 
/**
 * \brief Alpha Executable Image Header (EIHD)
 */
typedef struct vms_alpha_eihd_t {
	ut32 majorid;           ///< 0x00: Major ID - 0x0003 for Alpha
	ut32 minorid;           ///< 0x04: Minor ID - 0x0000 for Alpha
	ut32 eihd_size;         ///< 0x08: Size of EIHD
	ut32 isdoff;            ///< 0x0C: Offset to Image Section Descriptors
	ut32 unknown1[4];       ///< 0x10-0x1F: Unknown
	ut32 unknown2[4];       ///< 0x20-0x2F: Unknown
	ut32 unknown3[4];       ///< 0x30-0x3F: Unknown
	ut32 unknown4[4];       ///< 0x40-0x4F: Unknown
} VMSAlphaEIHD;
 
/**
 * \brief Image Section Descriptor (ISD)
 */
typedef struct vms_vax_isd_t {
	ut16 size;              ///< Size/type field
	ut16 flags;             ///< Section flags
	ut32 vbn;               ///< Virtual Block Number
	ut32 unknown1;
	ut32 unknown2;
} VMSVaxISD;
 
typedef struct vms_alpha_isd_t {
	ut32 type;
	ut32 flags;
	ut32 rec_size;
	ut32 section_size;
	ut32 section_addr;
	ut32 reserved0;
	ut32 attrs;
	ut32 aux;
	ut32 reserved1;
} VMSAlphaISD;
 
/**
 * \brief Shared library reference
 */
typedef struct vms_shared_lib_t {
	char *name;             ///< Library name
	ut32 offset;            ///< Offset in file
} VMSSharedLib;
 
/**
 * \brief OpenVMS executable object
 */
typedef struct openvms_obj_t {
	VMSArch arch;
	VMSFileType file_type;
	union {
		VMSVaxEIHD vax;
		VMSAlphaEIHD alpha;
	} header;
	
	char image_name[256];   ///< Image name
	char version[256];      ///< Version string
	char vms_version[256];  ///< VMS version
	
	ut32 num_sections;      ///< Number of sections
	void *sections;         ///< Array of ISDs
	
	ut32 num_libs;          ///< Number of shared libraries
	VMSSharedLib *libs;     ///< Shared libraries array
	
	ut64 file_size;         ///< File size
} OpenVMSObj;
 
/* API Functions */
RZ_IPI bool rz_bin_openvms_check_buffer(RzBuffer *b);
RZ_IPI bool rz_bin_openvms_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb);
RZ_IPI void rz_bin_openvms_destroy(RzBinFile *bf);
RZ_IPI RzBinInfo *rz_bin_openvms_info(RzBinFile *bf);
RZ_IPI RzPVector /*<RzBinAddr *>*/ *rz_bin_openvms_entries(RzBinFile *bf);
RZ_IPI RzPVector /*<RzBinSection *>*/ *rz_bin_openvms_sections(RzBinFile *bf);
RZ_IPI RzPVector /*<RzBinImport *>*/ *rz_bin_openvms_imports(RzBinFile *bf);
RZ_IPI RzPVector /*<char *>*/ *rz_bin_openvms_libs(RzBinFile *bf);
RZ_IPI RzStructuredData *rz_bin_openvms_structure(RzBinFile *bf);
 
#endif /* RZ_BIN_OPENVMS_H */