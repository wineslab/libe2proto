/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2SM-KPM-IEs"
 * 	found in "E2SM-KPM-v02.00.03.asn"
 * 	`asn1c -pdu=auto -fno-include-deps -fcompound-names -findirect-choice -gen-PER -gen-OER -no-gen-example -D E2SM-KPM-v02.00.03`
 */

#include "MeasurementInfo-Action-Item.h"

asn_TYPE_member_t asn_MBR_MeasurementInfo_Action_Item_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct MeasurementInfo_Action_Item, measName),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MeasurementTypeName,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"measName"
		},
	{ ATF_POINTER, 1, offsetof(struct MeasurementInfo_Action_Item, measID),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MeasurementTypeID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"measID"
		},
};
static const int asn_MAP_MeasurementInfo_Action_Item_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_MeasurementInfo_Action_Item_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_MeasurementInfo_Action_Item_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* measName */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* measID */
};
asn_SEQUENCE_specifics_t asn_SPC_MeasurementInfo_Action_Item_specs_1 = {
	sizeof(struct MeasurementInfo_Action_Item),
	offsetof(struct MeasurementInfo_Action_Item, _asn_ctx),
	asn_MAP_MeasurementInfo_Action_Item_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_MeasurementInfo_Action_Item_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	2,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_MeasurementInfo_Action_Item = {
	"MeasurementInfo-Action-Item",
	"MeasurementInfo-Action-Item",
	&asn_OP_SEQUENCE,
	asn_DEF_MeasurementInfo_Action_Item_tags_1,
	sizeof(asn_DEF_MeasurementInfo_Action_Item_tags_1)
		/sizeof(asn_DEF_MeasurementInfo_Action_Item_tags_1[0]), /* 1 */
	asn_DEF_MeasurementInfo_Action_Item_tags_1,	/* Same as above */
	sizeof(asn_DEF_MeasurementInfo_Action_Item_tags_1)
		/sizeof(asn_DEF_MeasurementInfo_Action_Item_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_MeasurementInfo_Action_Item_1,
	2,	/* Elements count */
	&asn_SPC_MeasurementInfo_Action_Item_specs_1	/* Additional specs */
};

