// SPDX-FileCopyrightText: 2026 Muqeet-Salam <muqeetsalam168@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Implementation of OpenVMS executable format parser (VAX and Alpha).
 *
 * Detection heuristic:
 * - VAX: First 4 bytes must be 0xB0 0x00 0x30 0x00
 * - Alpha: First 4 bytes must be 0x03 0x00 0x00 0x00
 *
 * Reference: https://links.twibright.com/download/binaries/openvms/
 */
#include "openvms.h"
#include <rz_util/rz_str.h>
 
/**
 * \brief Detect VMS file type from magic bytes
 */
static VMSFileType vms_detect_file_type(RzBuffer *b) {
	ut8 magic[4];
	if (rz_buf_read_at(b, 0, magic, 4) != 4) {
		return VMS_TYPE_UNKNOWN;
	}
	
	ut32 magic32 = magic[0] | (magic[1] << 8) | (magic[2] << 16) | (magic[3] << 24);
	
	// Check for OLB (Object Library): 01 02 00 00
	if (magic32 == VMS_OLB_MAGIC) {
		return VMS_TYPE_OLB;
	}
	
	// Check for OBJ (Object Module): 01 01 00 00  
	if (magic32 == VMS_OBJ_MAGIC) {
		return VMS_TYPE_OBJ;
	}
	
	// Check for VAX EXE: B0 00 30 00
	if (magic[0] == 0xB0 && magic[1] == 0x00 &&
	    magic[2] == 0x30 && magic[3] == 0x00) {
		return VMS_TYPE_EXE;
	}
	
	// Check for Alpha EXE: 03 00 00 00
	if (magic[0] == 0x03 && magic[1] == 0x00 &&
	    magic[2] == 0x00 && magic[3] == 0x00) {
		return VMS_TYPE_EXE;
	}
	
	return VMS_TYPE_UNKNOWN;
}
 
/**
 * \brief Detect VMS architecture from magic bytes
 */
static VMSArch vms_detect_arch(RzBuffer *b) {
	ut8 magic[4];
	if (rz_buf_read_at(b, 0, magic, 4) != 4) {
		return VMS_ARCH_UNKNOWN;
	}
	
	// Check for VAX magic: 0xB0 0x00 0x30 0x00
	if (magic[0] == 0xB0 && magic[1] == 0x00 &&
	    magic[2] == 0x30 && magic[3] == 0x00) {
		return VMS_ARCH_VAX;
	}
	
	// Check for Alpha magic: 0x03 0x00 0x00 0x00
	if (magic[0] == 0x03 && magic[1] == 0x00 &&
	    magic[2] == 0x00 && magic[3] == 0x00) {
		return VMS_ARCH_ALPHA;
	}
	
	// OBJ and OLB can be for any architecture - need to parse further
	// For now, default to VAX for these
	ut32 magic32 = magic[0] | (magic[1] << 8) | (magic[2] << 16) | (magic[3] << 24);
	if (magic32 == VMS_OLB_MAGIC || magic32 == VMS_OBJ_MAGIC) {
		return VMS_ARCH_VAX; // Default assumption
	}
	
	return VMS_ARCH_UNKNOWN;
}
 
/**
 * \brief Read a Pascal-style length-prefixed string
 */
static int vms_read_pstring(RzBuffer *b, ut64 offset, char *out, size_t out_size) {
	ut8 length;
	if (!rz_buf_read8_at(b, offset, &length)) {
		return -1;
	}
	
	if (length == 0 || length >= out_size) {
		return -1;
	}
	
	if (rz_buf_read_at(b, offset + 1, (ut8 *)out, length) != length) {
		return -1;
	}
	
	out[length] = '\0';
	return length;
}

static void vms_read_best_effort_pstring(RzBuffer *b, const ut64 *offsets, size_t n_offsets, char *out, size_t out_size) {
	for (size_t i = 0; i < n_offsets; i++) {
		if (vms_read_pstring(b, offsets[i], out, out_size) > 0) {
			return;
		}
	}
	out[0] = '\0';
}
 
/**
 * \brief Parse VAX header
 */
static bool vms_parse_vax_header(OpenVMSObj *obj, RzBuffer *b) {
	ut64 offset = 0;
	
	if (!rz_buf_read_le16_offset(b, &offset, &obj->header.vax.majorid) ||
	    !rz_buf_read_le16_offset(b, &offset, &obj->header.vax.minorid) ||
	    !rz_buf_read_le16_offset(b, &offset, &obj->header.vax.eihd_size) ||
	    !rz_buf_read_le16_offset(b, &offset, &obj->header.vax.isdoff)) {
		return false;
	}
	
	const ut64 image_name_offsets[] = { VMS_VAX_IMAGE_NAME_OFF };
	const ut64 version_offsets[] = { VMS_VAX_VERSION_OFF, 0x80 };
	const ut64 vms_version_offsets[] = { VMS_VAX_VMSVER_OFF };

	vms_read_best_effort_pstring(b, image_name_offsets, sizeof(image_name_offsets) / sizeof(image_name_offsets[0]), obj->image_name, sizeof(obj->image_name));
	vms_read_best_effort_pstring(b, version_offsets, sizeof(version_offsets) / sizeof(version_offsets[0]), obj->version, sizeof(obj->version));
	vms_read_best_effort_pstring(b, vms_version_offsets, sizeof(vms_version_offsets) / sizeof(vms_version_offsets[0]), obj->vms_version, sizeof(obj->vms_version));
	
	return true;
}
 
/**
 * \brief Parse Alpha header
 */
static bool vms_parse_alpha_header(OpenVMSObj *obj, RzBuffer *b) {
	ut64 offset = 0;
	
	if (!rz_buf_read_le32_offset(b, &offset, &obj->header.alpha.majorid) ||
	    !rz_buf_read_le32_offset(b, &offset, &obj->header.alpha.minorid) ||
	    !rz_buf_read_le32_offset(b, &offset, &obj->header.alpha.eihd_size) ||
	    !rz_buf_read_le32_offset(b, &offset, &obj->header.alpha.isdoff)) {
		return false;
	}
	
	const ut64 image_name_offsets[] = { VMS_ALPHA_IMAGE_NAME_OFF, 0xC4 };
	const ut64 version_offsets[] = { VMS_ALPHA_VERSION_OFF };
	const ut64 vms_version_offsets[] = { VMS_ALPHA_VMSVER_OFF };

	vms_read_best_effort_pstring(b, image_name_offsets, sizeof(image_name_offsets) / sizeof(image_name_offsets[0]), obj->image_name, sizeof(obj->image_name));
	vms_read_best_effort_pstring(b, version_offsets, sizeof(version_offsets) / sizeof(version_offsets[0]), obj->version, sizeof(obj->version));
	vms_read_best_effort_pstring(b, vms_version_offsets, sizeof(vms_version_offsets) / sizeof(vms_version_offsets[0]), obj->vms_version, sizeof(obj->vms_version));
	
	return true;
}
 
/**
 * \brief Parse Image Section Descriptors (ISDs) for VAX
 */
static void vms_parse_vax_isds(OpenVMSObj *vms, RzBuffer *b) {
	ut16 isdoff = vms->header.vax.isdoff;
	if (isdoff == 0 || isdoff >= rz_buf_size(b)) {
		return;
	}
	
	// Skip past the string table entries (image name, version, etc.)
	// ISDs typically start after offset 0xB0 for VAX
	ut64 offset = 0xB0;
	
	// Parse ISDs until we hit terminator (all 0xFF)
	int max_sections = 100; // Safety limit
	for (int i = 0; i < max_sections; i++) {
		VMSVaxISD isd;
		
		if (!rz_buf_read_le16_at(b, offset, &isd.size)) break;
		if (!rz_buf_read_le16_at(b, offset + 2, &isd.flags)) break;
		if (!rz_buf_read_le32_at(b, offset + 4, &isd.vbn)) break;
		
		// Check for terminator (all 0xFF or size == 0)
		if (isd.size == 0xFFFF || isd.size == 0) {
			break;
		}
		
		vms->num_sections++;
		offset += 16; // VAX ISD is typically 16 bytes based on pattern
	}
}
 
/**
 * \brief Parse Image Section Descriptors (ISDs) for Alpha  
 */
static void vms_parse_alpha_isds(OpenVMSObj *vms, RzBuffer *b) {
	ut64 offset = vms->header.alpha.isdoff;
	ut64 file_size = rz_buf_size(b);

	if (offset == 0 || offset >= file_size) {
		return;
	}

	for (int i = 0; i < 256 && offset + VMS_ALPHA_ISD_SIZE <= file_size; i++) {
		VMSAlphaISD isd;

		if (!rz_buf_read_le32_at(b, offset, &isd.type)) break;
		if (!rz_buf_read_le32_at(b, offset + 4, &isd.flags)) break;
		if (!rz_buf_read_le32_at(b, offset + 8, &isd.rec_size)) break;
		if (!rz_buf_read_le32_at(b, offset + 12, &isd.section_size)) break;

		if (isd.type == UT32_MAX && isd.flags == UT32_MAX && isd.rec_size == UT32_MAX) {
			break;
		}
		if (isd.rec_size != VMS_ALPHA_ISD_SIZE) {
			break;
		}
		if (isd.section_size == 0 || isd.section_size == UT32_MAX) {
			break;
		}

		vms->num_sections++;
		offset += VMS_ALPHA_ISD_SIZE;
	}
}
static void vms_find_libraries(OpenVMSObj *obj, RzBuffer *b) {
	ut64 file_size = rz_buf_size(b);
	if (file_size > 0x10000000) { // 256MB sanity limit
		return;
	}
	
	// Read entire file for string scanning
	ut8 *data = malloc(file_size);
	if (!data) {
		return;
	}
	
	if (rz_buf_read_at(b, 0, data, file_size) != file_size) {
		free(data);
		return;
	}
	
	// Common OpenVMS library keywords
	const char *keywords[] = {
		"SHR", "RTL", "LIB", "DECW$", "CMA$", 
		"DECC$", "VAX", "PTHREAD", NULL
	};
	
	RzList *lib_list = rz_list_newf(free);
	if (!lib_list) {
		free(data);
		return;
	}
	
	// Scan for library-like strings
	for (ut64 i = 0; i < file_size - 16; i++) {
		if (data[i] < 32 || data[i] > 126) {
			continue;
		}
		
		// Check for keyword match
		for (int k = 0; keywords[k] != NULL; k++) {
			const char *kw = keywords[k];
			size_t kw_len = strlen(kw);
			
			if (i + kw_len >= file_size) {
				continue;
			}
			
			if (memcmp(&data[i], kw, kw_len) != 0) {
				continue;
			}
			
			// Find string boundaries
			ut64 start = i;
			while (start > 0 && data[start - 1] >= 32 && data[start - 1] <= 126) {
				start--;
			}
			
			ut64 end = i + kw_len;
			while (end < file_size && data[end] >= 32 && data[end] <= 126) {
				end++;
			}
			
			size_t lib_len = end - start;
			if (lib_len < 4 || lib_len >= 128) {
				continue;
			}
			
			char *lib_name = rz_str_ndup((const char *)&data[start], lib_len);
			if (!lib_name) {
				continue;
			}
			
			// Check if it looks like a library name
			if (!strchr(lib_name, '$') && !strchr(lib_name, '_')) {
				free(lib_name);
				continue;
			}
			
			// Check for duplicates
			bool duplicate = false;
			RzListIter *iter;
			char *existing;
			rz_list_foreach (lib_list, iter, existing) {
				if (!strcmp(existing, lib_name)) {
					duplicate = true;
					break;
				}
			}
			
			if (!duplicate) {
				rz_list_append(lib_list, lib_name);
			} else {
				free(lib_name);
			}
			
			i = end;
			break;
		}
	}
	
	free(data);
	
	// Convert list to array
	obj->num_libs = rz_list_length(lib_list);
	if (obj->num_libs > 0) {
		obj->libs = RZ_NEWS0(VMSSharedLib, obj->num_libs);
		if (obj->libs) {
			RzListIter *iter;
			char *lib_name;
			int idx = 0;
			rz_list_foreach (lib_list, iter, lib_name) {
				obj->libs[idx].name = rz_str_dup(lib_name);
				obj->libs[idx].offset = 0;
				idx++;
			}
		}
	}
	
	rz_list_free(lib_list);
}
 
// Check if buffer contains valid OpenVMS executable
RZ_IPI bool rz_bin_openvms_check_buffer(RzBuffer *b) {
	rz_return_val_if_fail(b, false);
	
	ut64 size = rz_buf_size(b);
	if (size < 32) { // Minimum size for any VMS file
		return false;
	}
	
	VMSFileType file_type = vms_detect_file_type(b);
	if (file_type == VMS_TYPE_UNKNOWN) {
		return false;
	}
	
	// For OLB and OBJ, basic magic check is enough
	if (file_type == VMS_TYPE_OLB || file_type == VMS_TYPE_OBJ) {
		return true;
	}
	
	// For EXE files, additional validation
	if (file_type == VMS_TYPE_EXE) {
		if (size < VMS_MIN_FILE_SIZE) {
			return false;
		}
		
		VMSArch arch = vms_detect_arch(b);
		if (arch == VMS_ARCH_UNKNOWN) {
			return false;
		}
		
		// Additional validation: check for image name string at expected offset
		// This helps avoid false positives with other formats
		if (arch == VMS_ARCH_VAX) {
			// VAX: image name at 0x60
			ut8 name_len;
			if (rz_buf_read8_at(b, 0x60, &name_len) && name_len > 0 && name_len < 32) {
				return true;
			}
		} else if (arch == VMS_ARCH_ALPHA) {
			// Alpha: image name at 0xC8
			ut8 name_len;
			if (rz_buf_read8_at(b, VMS_ALPHA_IMAGE_NAME_OFF, &name_len) && name_len > 0 && name_len < 32) {
				return true;
			}
		}
		
		return false;
	}
	
	return false;
}
 
// Load and parse OpenVMS executable
RZ_IPI bool rz_bin_openvms_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	rz_return_val_if_fail(bf && obj && b, false);
	
	OpenVMSObj *vms = RZ_NEW0(OpenVMSObj);
	if (!vms) {
		return false;
	}
	
	vms->file_size = rz_buf_size(b);
	vms->file_type = vms_detect_file_type(b);
	vms->arch = vms_detect_arch(b);
	
	// Handle different file types
	if (vms->file_type == VMS_TYPE_OLB) {
		// Object Library - read library header
		vms_read_pstring(b, 0x0B, vms->image_name, sizeof(vms->image_name));
		strcpy(vms->version, "OLB");
		obj->bin_obj = vms;
		return true;
	}
	
	if (vms->file_type == VMS_TYPE_OBJ) {
		// Object Module
		strcpy(vms->image_name, "Object Module");
		strcpy(vms->version, "OBJ");
		obj->bin_obj = vms;
		return true;
	}
	
	// Handle executable files (EXE)
	bool ok = false;
	switch (vms->arch) {
	case VMS_ARCH_VAX:
		ok = vms_parse_vax_header(vms, b);
		break;
	case VMS_ARCH_ALPHA:
		ok = vms_parse_alpha_header(vms, b);
		break;
	default:
		break;
	}
	
	if (!ok) {
		free(vms);
		return false;
	}
	
	// Parse ISDs to get section count
	if (vms->arch == VMS_ARCH_VAX) {
		vms_parse_vax_isds(vms, b);
	} else if (vms->arch == VMS_ARCH_ALPHA) {
		vms_parse_alpha_isds(vms, b);
	}
	
	// Find shared libraries
	vms_find_libraries(vms, b);
	
	obj->bin_obj = vms;
	return true;
}
 
// Free OpenVMS object resources
RZ_IPI void rz_bin_openvms_destroy(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return;
	}
	
	OpenVMSObj *vms = bf->o->bin_obj;
	
	if (vms->sections) {
		free(vms->sections);
	}
	
	if (vms->libs) {
		for (ut32 i = 0; i < vms->num_libs; i++) {
			free(vms->libs[i].name);
		}
		free(vms->libs);
	}
	
	free(vms);
}
 
// Get entry points from OpenVMS file
RZ_IPI RzPVector /*<RzBinAddr *>*/ *rz_bin_openvms_entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	
	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}
	
	// TODO: Parse actual entry point from OpenVMS header
	// For now, return empty list
	
	return ret;
}
 
// Create sections from OpenVMS segments
RZ_IPI RzPVector /*<RzBinSection *>*/ *rz_bin_openvms_sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	
	OpenVMSObj *vms = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}
	
	RzBuffer *b = bf->buf;
	
	if (vms->arch == VMS_ARCH_VAX) {
		// Parse VAX ISDs
		ut64 offset = 0xB0;
		ut32 text_idx = 0, data_idx = 0;
		
		for (ut32 i = 0; i < vms->num_sections && i < 100; i++) {
			VMSVaxISD isd;
			
			if (!rz_buf_read_le16_at(b, offset, &isd.size)) break;
			if (!rz_buf_read_le16_at(b, offset + 2, &isd.flags)) break;
			if (!rz_buf_read_le32_at(b, offset + 4, &isd.vbn)) break;
			
			if (isd.size == 0xFFFF || isd.size == 0) break;
			
			RzBinSection *section = RZ_NEW0(RzBinSection);
			if (!section) {
				offset += 16;
				continue;
			}
			
			// Determine section type based on flags
			bool is_exec = (isd.flags & 0x01);
			if (is_exec) {
				section->name = rz_str_newf("text_%u", text_idx++);
				section->perm = RZ_PERM_RX;
			} else {
				section->name = rz_str_newf("data_%u", data_idx++);
				section->perm = RZ_PERM_RW;
			}
			
			section->paddr = offset;
			section->size = isd.size;
			section->vsize = isd.size;
			section->vaddr = isd.vbn;
			
			rz_pvector_push(ret, section);
			offset += 16;
		}
	} else if (vms->arch == VMS_ARCH_ALPHA) {
		// Parse Alpha ISDs
		ut64 offset = vms->header.alpha.isdoff;
		ut32 text_idx = 0, data_idx = 0;
		
		for (ut32 i = 0; i < vms->num_sections && i < 100; i++) {
			VMSAlphaISD isd;
			
			if (!rz_buf_read_le32_at(b, offset, &isd.type)) break;
			if (!rz_buf_read_le32_at(b, offset + 4, &isd.flags)) break;
			if (!rz_buf_read_le32_at(b, offset + 8, &isd.rec_size)) break;
			if (!rz_buf_read_le32_at(b, offset + 12, &isd.section_size)) break;
			if (!rz_buf_read_le32_at(b, offset + 16, &isd.section_addr)) break;
			
			if (isd.type == UT32_MAX && isd.flags == UT32_MAX && isd.rec_size == UT32_MAX) break;
			if (isd.rec_size != VMS_ALPHA_ISD_SIZE || isd.section_size == 0 || isd.section_size == UT32_MAX) break;
			
			RzBinSection *section = RZ_NEW0(RzBinSection);
			if (!section) {
				offset += VMS_ALPHA_ISD_SIZE;
				continue;
			}
			
			// Determine section type based on flags
			bool is_exec = (isd.flags & 0x01);
			if (is_exec) {
				section->name = rz_str_newf("text_%u", text_idx++);
				section->perm = RZ_PERM_RX;
			} else {
				section->name = rz_str_newf("data_%u", data_idx++);
				section->perm = RZ_PERM_RW;
			}
			
			section->paddr = isd.section_addr < rz_buf_size(b) ? isd.section_addr : offset;
			section->size = isd.section_size;
			section->vsize = isd.section_size;
			section->vaddr = isd.section_addr;
			
			rz_pvector_push(ret, section);
			offset += VMS_ALPHA_ISD_SIZE;
		}
	}
	
	return ret;
}
 
// Get Binary Information
RZ_IPI RzBinInfo *rz_bin_openvms_info(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	
	OpenVMSObj *vms = bf->o->bin_obj;
	
	RzBinInfo *info = RZ_NEW0(RzBinInfo);
	if (!info) {
		return NULL;
	}
	
	info->file = bf->file ? rz_str_dup(bf->file) : NULL;
	info->os = rz_str_dup("OpenVMS");
	info->has_va = true;
	info->big_endian = false;
	
	// Set type based on file type
	if (vms->file_type == VMS_TYPE_OLB) {
		info->type = rz_str_dup("OLB");
		info->rclass = rz_str_dup("library");
	} else if (vms->file_type == VMS_TYPE_OBJ) {
		info->type = rz_str_dup("OBJ");
		info->rclass = rz_str_dup("object");
	} else {
		info->type = rz_str_dup("EXEC");
		info->rclass = rz_str_dup("openvms");
	}
	
	if (vms->arch == VMS_ARCH_VAX) {
		info->arch = rz_str_dup("vax");
		info->machine = rz_str_dup("VAX");
		info->bits = 32;
	} else if (vms->arch == VMS_ARCH_ALPHA) {
		info->arch = rz_str_dup("alpha");
		info->machine = rz_str_dup("Alpha");
		info->bits = 64;
	}
	
	
	return info;
}
 
// Get imports (shared libraries)
RZ_IPI RzPVector /*<RzBinImport *>*/ *rz_bin_openvms_imports(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	
	OpenVMSObj *vms = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_import_free);
	if (!ret) {
		return NULL;
	}
	
	for (ut32 i = 0; i < vms->num_libs; i++) {
		RzBinImport *import = RZ_NEW0(RzBinImport);
		if (!import) {
			continue;
		}
		
		import->name = rz_str_dup(vms->libs[i].name);
		import->libname = rz_str_dup(vms->libs[i].name);
		
		rz_pvector_push(ret, import);
	}
	
	return ret;
}
 
// Get libraries (shared library dependencies)
RZ_IPI RzPVector /*<char *>*/ *rz_bin_openvms_libs(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	
	OpenVMSObj *vms = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}
	
	for (ut32 i = 0; i < vms->num_libs; i++) {
		rz_pvector_push(ret, rz_str_dup(vms->libs[i].name));
	}
	
	return ret;
}
 
// Get structured data about the OpenVMS file
RZ_IPI RzStructuredData *rz_bin_openvms_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	
	OpenVMSObj *vms = bf->o->bin_obj;
	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}
	
	// File type
	const char *file_type_str = vms->file_type == VMS_TYPE_EXE ? "Executable" :
	                            vms->file_type == VMS_TYPE_OLB ? "Object Library" :
	                            vms->file_type == VMS_TYPE_OBJ ? "Object Module" : "Unknown";
	rz_structured_data_map_add_string(info, "file_type", file_type_str);
	
	// Header information
	const char *arch_str = vms->arch == VMS_ARCH_VAX ? "VAX" : 
	                       vms->arch == VMS_ARCH_ALPHA ? "Alpha" : "Unknown";
	rz_structured_data_map_add_string(info, "architecture", arch_str);
	rz_structured_data_map_add_string(info, "image_name", vms->image_name);
	rz_structured_data_map_add_string(info, "version", vms->version);
	rz_structured_data_map_add_string(info, "vms_version", vms->vms_version);
	rz_structured_data_map_add_unsigned(info, "num_sections", vms->num_sections, false);
	rz_structured_data_map_add_unsigned(info, "num_libraries", vms->num_libs, false);
	rz_structured_data_map_add_unsigned(info, "file_size", vms->file_size, true);
	
	// EIHD information (only for EXE files)
	if (vms->file_type == VMS_TYPE_EXE) {
		if (vms->arch == VMS_ARCH_VAX) {
			rz_structured_data_map_add_unsigned(info, "eihd_major_id", vms->header.vax.majorid, true);
			rz_structured_data_map_add_unsigned(info, "eihd_minor_id", vms->header.vax.minorid, true);
			rz_structured_data_map_add_unsigned(info, "eihd_size", vms->header.vax.eihd_size, false);
			rz_structured_data_map_add_unsigned(info, "isd_offset", vms->header.vax.isdoff, true);
		} else if (vms->arch == VMS_ARCH_ALPHA) {
			rz_structured_data_map_add_unsigned(info, "eihd_major_id", vms->header.alpha.majorid, true);
			rz_structured_data_map_add_unsigned(info, "eihd_minor_id", vms->header.alpha.minorid, true);
			rz_structured_data_map_add_unsigned(info, "eihd_size", vms->header.alpha.eihd_size, false);
			rz_structured_data_map_add_unsigned(info, "isd_offset", vms->header.alpha.isdoff, true);
		}
	}
	
	// Libraries array
	if (vms->num_libs > 0) {
		RzStructuredData *libs = rz_structured_data_map_add_array(info, "libraries");
		if (libs) {
			for (ut32 i = 0; i < vms->num_libs; i++) {
				rz_structured_data_array_add_string(libs, vms->libs[i].name);
			}
		}
	}
	
	return info;
}