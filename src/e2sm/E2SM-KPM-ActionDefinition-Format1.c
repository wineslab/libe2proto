/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2SM-KPM-RC"
 * 	found in "e2sm-kpm-rc.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -findirect-choice -pdu=auto -gen-PER -gen-OER -no-gen-example -D .`
 */

#include "E2SM-KPM-ActionDefinition-Format1.h"

asn_TYPE_member_t asn_MBR_E2SM_KPM_ActionDefinition_Format1_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct E2SM_KPM_ActionDefinition_Format1, cellObjID),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CellObjectID,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"cellObjID"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct E2SM_KPM_ActionDefinition_Format1, measInfoList),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MeasurementInfoList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"measInfoList"
		},
};
static const ber_tlv_tag_t asn_DEF_E2SM_KPM_ActionDefinition_Format1_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_E2SM_KPM_ActionDefinition_Format1_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* cellObjID */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* measInfoList */
};
asn_SEQUENCE_specifics_t asn_SPC_E2SM_KPM_ActionDefinition_Format1_specs_1 = {
	sizeof(struct E2SM_KPM_ActionDefinition_Format1),
	offsetof(struct E2SM_KPM_ActionDefinition_Format1, _asn_ctx),
	asn_MAP_E2SM_KPM_ActionDefinition_Format1_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	2,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_E2SM_KPM_ActionDefinition_Format1 = {
	"E2SM-KPM-ActionDefinition-Format1",
	"E2SM-KPM-ActionDefinition-Format1",
	&asn_OP_SEQUENCE,
	asn_DEF_E2SM_KPM_ActionDefinition_Format1_tags_1,
	sizeof(asn_DEF_E2SM_KPM_ActionDefinition_Format1_tags_1)
		/sizeof(asn_DEF_E2SM_KPM_ActionDefinition_Format1_tags_1[0]), /* 1 */
	asn_DEF_E2SM_KPM_ActionDefinition_Format1_tags_1,	/* Same as above */
	sizeof(asn_DEF_E2SM_KPM_ActionDefinition_Format1_tags_1)
		/sizeof(asn_DEF_E2SM_KPM_ActionDefinition_Format1_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_E2SM_KPM_ActionDefinition_Format1_1,
	2,	/* Elements count */
	&asn_SPC_E2SM_KPM_ActionDefinition_Format1_specs_1	/* Additional specs */
};

