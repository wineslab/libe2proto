/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2SM-KPM-RC"
 * 	found in "e2sm-kpm-rc.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -findirect-choice -pdu=auto -gen-PER -gen-OER -no-gen-example -D .`
 */

#include "MeasQuantityResultsEUTRA.h"

asn_TYPE_member_t asn_MBR_MeasQuantityResultsEUTRA_1[] = {
	{ ATF_POINTER, 3, offsetof(struct MeasQuantityResultsEUTRA, rsrp),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RSRP_RangeEUTRA,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rsrp"
		},
	{ ATF_POINTER, 2, offsetof(struct MeasQuantityResultsEUTRA, rsrq),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RSRQ_RangeEUTRA,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"rsrq"
		},
	{ ATF_POINTER, 1, offsetof(struct MeasQuantityResultsEUTRA, sinr),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SINR_RangeEUTRA,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"sinr"
		},
};
static const int asn_MAP_MeasQuantityResultsEUTRA_oms_1[] = { 0, 1, 2 };
static const ber_tlv_tag_t asn_DEF_MeasQuantityResultsEUTRA_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MeasQuantityResultsEUTRA_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* rsrp */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* rsrq */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* sinr */
};
asn_SEQUENCE_specifics_t asn_SPC_MeasQuantityResultsEUTRA_specs_1 = {
	sizeof(struct MeasQuantityResultsEUTRA),
	offsetof(struct MeasQuantityResultsEUTRA, _asn_ctx),
	asn_MAP_MeasQuantityResultsEUTRA_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_MeasQuantityResultsEUTRA_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MeasQuantityResultsEUTRA = {
	"MeasQuantityResultsEUTRA",
	"MeasQuantityResultsEUTRA",
	&asn_OP_SEQUENCE,
	asn_DEF_MeasQuantityResultsEUTRA_tags_1,
	sizeof(asn_DEF_MeasQuantityResultsEUTRA_tags_1)
		/sizeof(asn_DEF_MeasQuantityResultsEUTRA_tags_1[0]), /* 1 */
	asn_DEF_MeasQuantityResultsEUTRA_tags_1,	/* Same as above */
	sizeof(asn_DEF_MeasQuantityResultsEUTRA_tags_1)
		/sizeof(asn_DEF_MeasQuantityResultsEUTRA_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MeasQuantityResultsEUTRA_1,
	3,	/* Elements count */
	&asn_SPC_MeasQuantityResultsEUTRA_specs_1	/* Additional specs */
};

