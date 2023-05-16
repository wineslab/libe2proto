/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2SM-KPM-RC"
 * 	found in "e2sm-kpm-rc.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -findirect-choice -pdu=auto -gen-PER -gen-OER -no-gen-example -D .`
 */

#include "PerQCIReportListItem.h"

static int
memb_dl_PRBUsage_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 100)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_ul_PRBUsage_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 100)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_memb_dl_PRBUsage_constr_3 CC_NOTUSED = {
	{ 1, 1 }	/* (0..100) */,
	-1};
static asn_per_constraints_t asn_PER_memb_dl_PRBUsage_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 7,  7,  0,  100 }	/* (0..100) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_ul_PRBUsage_constr_4 CC_NOTUSED = {
	{ 1, 1 }	/* (0..100) */,
	-1};
static asn_per_constraints_t asn_PER_memb_ul_PRBUsage_constr_4 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 7,  7,  0,  100 }	/* (0..100) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
asn_TYPE_member_t asn_MBR_PerQCIReportListItem_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PerQCIReportListItem, qci),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_QCI,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"qci"
		},
	{ ATF_POINTER, 2, offsetof(struct PerQCIReportListItem, dl_PRBUsage),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_dl_PRBUsage_constr_3, &asn_PER_memb_dl_PRBUsage_constr_3,  memb_dl_PRBUsage_constraint_1 },
		0, 0, /* No default value */
		"dl-PRBUsage"
		},
	{ ATF_POINTER, 1, offsetof(struct PerQCIReportListItem, ul_PRBUsage),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ &asn_OER_memb_ul_PRBUsage_constr_4, &asn_PER_memb_ul_PRBUsage_constr_4,  memb_ul_PRBUsage_constraint_1 },
		0, 0, /* No default value */
		"ul-PRBUsage"
		},
};
static const int asn_MAP_PerQCIReportListItem_oms_1[] = { 1, 2 };
static const ber_tlv_tag_t asn_DEF_PerQCIReportListItem_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_PerQCIReportListItem_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* qci */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* dl-PRBUsage */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* ul-PRBUsage */
};
asn_SEQUENCE_specifics_t asn_SPC_PerQCIReportListItem_specs_1 = {
	sizeof(struct PerQCIReportListItem),
	offsetof(struct PerQCIReportListItem, _asn_ctx),
	asn_MAP_PerQCIReportListItem_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_PerQCIReportListItem_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_PerQCIReportListItem = {
	"PerQCIReportListItem",
	"PerQCIReportListItem",
	&asn_OP_SEQUENCE,
	asn_DEF_PerQCIReportListItem_tags_1,
	sizeof(asn_DEF_PerQCIReportListItem_tags_1)
		/sizeof(asn_DEF_PerQCIReportListItem_tags_1[0]), /* 1 */
	asn_DEF_PerQCIReportListItem_tags_1,	/* Same as above */
	sizeof(asn_DEF_PerQCIReportListItem_tags_1)
		/sizeof(asn_DEF_PerQCIReportListItem_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_PerQCIReportListItem_1,
	3,	/* Elements count */
	&asn_SPC_PerQCIReportListItem_specs_1	/* Additional specs */
};

