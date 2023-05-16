/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2SM-KPM-RC"
 * 	found in "e2sm-kpm-rc.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -findirect-choice -pdu=auto -gen-PER -gen-OER -no-gen-example -D .`
 */

#include "E2SM-KPM-IndicationMessage-Format1.h"

#include "PM-Containers-Item.h"
#include "PM-Info-Item.h"
#include "PerUE-PM-Item.h"
static int
memb_pm_Containers_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 8)) {
		/* Perform validation of the inner elements */
		return td->encoding_constraints.general_constraints(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_list_of_PM_Information_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 2147483647)) {
		/* Perform validation of the inner elements */
		return td->encoding_constraints.general_constraints(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_list_of_matched_UEs_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1 && size <= 65535)) {
		/* Perform validation of the inner elements */
		return td->encoding_constraints.general_constraints(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_oer_constraints_t asn_OER_type_pm_Containers_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..8)) */};
static asn_per_constraints_t asn_PER_type_pm_Containers_constr_2 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  8 }	/* (SIZE(1..8)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_list_of_PM_Information_constr_5 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..2147483647)) */};
static asn_per_constraints_t asn_PER_type_list_of_PM_Information_constr_5 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 31, -1,  1,  2147483647 }	/* (SIZE(1..2147483647)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_type_list_of_matched_UEs_constr_7 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..65535)) */};
static asn_per_constraints_t asn_PER_type_list_of_matched_UEs_constr_7 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 16,  16,  1,  65535 }	/* (SIZE(1..65535)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_pm_Containers_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..8)) */};
static asn_per_constraints_t asn_PER_memb_pm_Containers_constr_2 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 3,  3,  1,  8 }	/* (SIZE(1..8)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_list_of_PM_Information_constr_5 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..2147483647)) */};
static asn_per_constraints_t asn_PER_memb_list_of_PM_Information_constr_5 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 31, -1,  1,  2147483647 }	/* (SIZE(1..2147483647)) */,
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_list_of_matched_UEs_constr_7 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(1..65535)) */};
static asn_per_constraints_t asn_PER_memb_list_of_matched_UEs_constr_7 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED,	 16,  16,  1,  65535 }	/* (SIZE(1..65535)) */,
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_pm_Containers_2[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_PM_Containers_Item,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_pm_Containers_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_pm_Containers_specs_2 = {
	sizeof(struct E2SM_KPM_IndicationMessage_Format1__pm_Containers),
	offsetof(struct E2SM_KPM_IndicationMessage_Format1__pm_Containers, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_pm_Containers_2 = {
	"pm-Containers",
	"pm-Containers",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_pm_Containers_tags_2,
	sizeof(asn_DEF_pm_Containers_tags_2)
		/sizeof(asn_DEF_pm_Containers_tags_2[0]) - 1, /* 1 */
	asn_DEF_pm_Containers_tags_2,	/* Same as above */
	sizeof(asn_DEF_pm_Containers_tags_2)
		/sizeof(asn_DEF_pm_Containers_tags_2[0]), /* 2 */
	{ &asn_OER_type_pm_Containers_constr_2, &asn_PER_type_pm_Containers_constr_2, SEQUENCE_OF_constraint },
	asn_MBR_pm_Containers_2,
	1,	/* Single element */
	&asn_SPC_pm_Containers_specs_2	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_list_of_PM_Information_5[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_PM_Info_Item,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_list_of_PM_Information_tags_5[] = {
	(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_list_of_PM_Information_specs_5 = {
	sizeof(struct E2SM_KPM_IndicationMessage_Format1__list_of_PM_Information),
	offsetof(struct E2SM_KPM_IndicationMessage_Format1__list_of_PM_Information, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_list_of_PM_Information_5 = {
	"list-of-PM-Information",
	"list-of-PM-Information",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_list_of_PM_Information_tags_5,
	sizeof(asn_DEF_list_of_PM_Information_tags_5)
		/sizeof(asn_DEF_list_of_PM_Information_tags_5[0]) - 1, /* 1 */
	asn_DEF_list_of_PM_Information_tags_5,	/* Same as above */
	sizeof(asn_DEF_list_of_PM_Information_tags_5)
		/sizeof(asn_DEF_list_of_PM_Information_tags_5[0]), /* 2 */
	{ &asn_OER_type_list_of_PM_Information_constr_5, &asn_PER_type_list_of_PM_Information_constr_5, SEQUENCE_OF_constraint },
	asn_MBR_list_of_PM_Information_5,
	1,	/* Single element */
	&asn_SPC_list_of_PM_Information_specs_5	/* Additional specs */
};

static asn_TYPE_member_t asn_MBR_list_of_matched_UEs_7[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_PerUE_PM_Item,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_list_of_matched_UEs_tags_7[] = {
	(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_list_of_matched_UEs_specs_7 = {
	sizeof(struct E2SM_KPM_IndicationMessage_Format1__list_of_matched_UEs),
	offsetof(struct E2SM_KPM_IndicationMessage_Format1__list_of_matched_UEs, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_list_of_matched_UEs_7 = {
	"list-of-matched-UEs",
	"list-of-matched-UEs",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_list_of_matched_UEs_tags_7,
	sizeof(asn_DEF_list_of_matched_UEs_tags_7)
		/sizeof(asn_DEF_list_of_matched_UEs_tags_7[0]) - 1, /* 1 */
	asn_DEF_list_of_matched_UEs_tags_7,	/* Same as above */
	sizeof(asn_DEF_list_of_matched_UEs_tags_7)
		/sizeof(asn_DEF_list_of_matched_UEs_tags_7[0]), /* 2 */
	{ &asn_OER_type_list_of_matched_UEs_constr_7, &asn_PER_type_list_of_matched_UEs_constr_7, SEQUENCE_OF_constraint },
	asn_MBR_list_of_matched_UEs_7,
	1,	/* Single element */
	&asn_SPC_list_of_matched_UEs_specs_7	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_E2SM_KPM_IndicationMessage_Format1_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct E2SM_KPM_IndicationMessage_Format1, pm_Containers),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_pm_Containers_2,
		0,
		{ &asn_OER_memb_pm_Containers_constr_2, &asn_PER_memb_pm_Containers_constr_2,  memb_pm_Containers_constraint_1 },
		0, 0, /* No default value */
		"pm-Containers"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct E2SM_KPM_IndicationMessage_Format1, cellObjectID),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellObjectID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cellObjectID"
		},
	{ ATF_POINTER, 2, offsetof(struct E2SM_KPM_IndicationMessage_Format1, list_of_PM_Information),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		0,
		&asn_DEF_list_of_PM_Information_5,
		0,
		{ &asn_OER_memb_list_of_PM_Information_constr_5, &asn_PER_memb_list_of_PM_Information_constr_5,  memb_list_of_PM_Information_constraint_1 },
		0, 0, /* No default value */
		"list-of-PM-Information"
		},
	{ ATF_POINTER, 1, offsetof(struct E2SM_KPM_IndicationMessage_Format1, list_of_matched_UEs),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		0,
		&asn_DEF_list_of_matched_UEs_7,
		0,
		{ &asn_OER_memb_list_of_matched_UEs_constr_7, &asn_PER_memb_list_of_matched_UEs_constr_7,  memb_list_of_matched_UEs_constraint_1 },
		0, 0, /* No default value */
		"list-of-matched-UEs"
		},
};
static const int asn_MAP_E2SM_KPM_IndicationMessage_Format1_oms_1[] = { 2, 3 };
static const ber_tlv_tag_t asn_DEF_E2SM_KPM_IndicationMessage_Format1_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_E2SM_KPM_IndicationMessage_Format1_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* pm-Containers */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* cellObjectID */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* list-of-PM-Information */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* list-of-matched-UEs */
};
asn_SEQUENCE_specifics_t asn_SPC_E2SM_KPM_IndicationMessage_Format1_specs_1 = {
	sizeof(struct E2SM_KPM_IndicationMessage_Format1),
	offsetof(struct E2SM_KPM_IndicationMessage_Format1, _asn_ctx),
	asn_MAP_E2SM_KPM_IndicationMessage_Format1_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_E2SM_KPM_IndicationMessage_Format1_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	4,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_E2SM_KPM_IndicationMessage_Format1 = {
	"E2SM-KPM-IndicationMessage-Format1",
	"E2SM-KPM-IndicationMessage-Format1",
	&asn_OP_SEQUENCE,
	asn_DEF_E2SM_KPM_IndicationMessage_Format1_tags_1,
	sizeof(asn_DEF_E2SM_KPM_IndicationMessage_Format1_tags_1)
		/sizeof(asn_DEF_E2SM_KPM_IndicationMessage_Format1_tags_1[0]), /* 1 */
	asn_DEF_E2SM_KPM_IndicationMessage_Format1_tags_1,	/* Same as above */
	sizeof(asn_DEF_E2SM_KPM_IndicationMessage_Format1_tags_1)
		/sizeof(asn_DEF_E2SM_KPM_IndicationMessage_Format1_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_E2SM_KPM_IndicationMessage_Format1_1,
	4,	/* Elements count */
	&asn_SPC_E2SM_KPM_IndicationMessage_Format1_specs_1	/* Additional specs */
};

