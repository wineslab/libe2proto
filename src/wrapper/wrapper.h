#ifndef	_WRAPPER_H_
#define	_WRAPPER_H_

//#include "ARP.h"
#include "BOOLEAN.h"
#include "NativeReal.h"
#include "NULL.h"
#include "REAL.h"
#include "TimeStamp.h"
#include "OCTET_STRING.h"
#include "E2SM-RC-ControlHeader-Format1.h"
#include "E2SM-RC-ControlHeader.h"
#include "E2SM-RC-ControlMessage-Format1.h"
#include "E2SM-RC-ControlMessage.h"
#include "E2SM-RC-RANFunctionDefinition.h"
#include "INTEGER.h"
#include "NativeInteger.h"
#include "OPEN_TYPE.h"
#include "PrintableString.h"
#include "RAN-ControlParameter-Item.h"
#include "RANParameter-ELEMENT.h"
#include "RANParameter-ID.h"
#include "RANParameter-Item.h"
#include "RANParameter-LIST.h"
#include "RANParameter-Name.h"
#include "RANParameter-STRUCTURE.h"
#include "RANParameter-Value.h"
#include "RANParameter-ValueType.h"
#include "RANfunction-Name.h"
#include "RIC-ControlAction-ID.h"
#include "RIC-ControlAction-Item.h"
#include "RIC-ControlAction-Name.h"
#include "RIC-ControlStyle-Item.h"
#include "RIC-EventTriggerStyle-Item.h"
#include "RIC-Format-Type.h"
#include "RIC-Style-Name.h"
#include "RIC-Style-Type.h"
#include "UE-Identity.h"
#include "RICcontrolRequest.h"
#include "E2AP-PDU.h"
#include "InitiatingMessage.h"
#include "SuccessfulOutcome.h"
#include "UnsuccessfulOutcome.h"
#include "ProtocolIE-Container.h"
#include "ProtocolIE-Field.h"
#include "RICactionDefinition.h"
#include "RICsubsequentAction.h"
#include "CauseRIC.h"
#include "E2SM-KPM-EventTriggerDefinition.h"
#include "E2SM-KPM-EventTriggerDefinition-Format1.h"
#include "Trigger-ConditionIE-Item.h"
#include "E2SM-KPM-ActionDefinition.h"
#include "E2SM-KPM-IndicationHeader.h"
#include "E2SM-KPM-IndicationHeader-Format1.h"
#include "GlobalKPMnode-ID.h"
#include "GlobalKPMnode-gNB-ID.h"
#include "GlobalKPMnode-en-gNB-ID.h"
#include "GlobalKPMnode-ng-eNB-ID.h"
#include "GlobalKPMnode-eNB-ID.h"
#include "PLMN-Identity.h"
#include "GNB-ID-Choice.h"
#include "GNB-CU-UP-ID.h"
#include "GNB-DU-ID.h"
#include "ENGNB-ID.h"
#include "ENB-ID-Choice.h"
#include "ENB-ID.h"
#include "NRCGI.h"
#include "SNSSAI.h"
#include "GNB-Name.h"
#include "E2SM-KPM-IndicationMessage.h"
#include "E2SM-KPM-IndicationMessage-Format1.h"
#include "PM-Containers-List.h"
#include "PF-Container.h"
#include "RAN-Container.h"
#include "ODU-PF-Container.h"
#include "CellResourceReportListItem.h"
#include "ServedPlmnPerCellListItem.h"
#include "FGC-DU-PM-Container.h"
#include "EPC-DU-PM-Container.h"
#include "SlicePerPlmnPerCellListItem.h"
#include "FQIPERSlicesPerPlmnPerCellListItem.h"
#include "PerQCIReportListItem.h"
#include "OCUCP-PF-Container.h"
#include "OCUUP-PF-Container.h"
#include "PF-ContainerListItem.h"
#include "PlmnID-List.h"
#include "FGC-CUUP-PM-Format.h"
#include "SliceToReportListItem.h"
#include "FQIPERSlicesPerPlmnListItem.h"
#include "EPC-CUUP-PM-Format.h"
#include "PerQCIReportListItemFormat.h"
#include "DU-Usage-Report-Per-UE.h"
#include "DU-Usage-Report-CellResourceReportItem.h"
#include "DU-Usage-Report-UeResourceReportItem.h"
#include "CU-CP-Usage-Report-Per-UE.h"
#include "CU-CP-Usage-Report-CellResourceReportItem.h"
#include "CU-CP-Usage-Report-UeResourceReportItem.h"
#include "CU-UP-Usage-Report-Per-UE.h"
#include "CU-UP-Usage-Report-CellResourceReportItem.h"
#include "CU-UP-Usage-Report-UeResourceReportItem.h"

typedef struct RICindicationMessage {
	long requestorID;
	long requestSequenceNumber;
	long ranfunctionID;
	long actionID;
	long indicationSN;
	long indicationType;
	uint8_t *indicationHeader;
	size_t indicationHeaderSize;
	uint8_t *indicationMessage;
	size_t indicationMessageSize;
	uint8_t *callProcessID;
	size_t callProcessIDSize;
} RICindicationMsg;

typedef struct RICcauseItem {
	int ricCauseType;
	long ricCauseID;
} RICcauseItem;

typedef struct RICactionAdmittedList {
	long ricActionID[16];
	int count;
} RICactionAdmittedList;

typedef struct RICactionNotAdmittedList {
	long ricActionID[16];
	RICcauseItem ricCause[16];
	int count;
} RICactionNotAdmittedList;

typedef struct RICsubscriptionResponseMessage {
	long requestorID;
	long requestSequenceNumber;
	long ranfunctionID;
	RICactionAdmittedList ricActionAdmittedList;
	RICactionNotAdmittedList ricActionNotAdmittedList;
} RICsubscriptionResponseMsg;

typedef struct RICactionDefinition {
	uint8_t *actionDefinition;
	int size;
} RICactionDefinition;

typedef struct RICSubsequentAction {
	int isValid;
	long subsequentActionType;
	long timeToWait;
} RICSubsequentAction;

/* General */
size_t encode_E2AP_PDU(E2AP_PDU_t* pdu, void* buffer, size_t buf_size);
E2AP_PDU_t* decode_E2AP_PDU(const void* buffer, size_t buf_size);

/* RICsubscriptionRequest */
long e2ap_get_ric_subscription_request_sequence_number(void *buffer, size_t buf_size);
ssize_t  e2ap_set_ric_subscription_request_sequence_number(void *buffer, size_t buf_size, long sequence_number);
ssize_t e2ap_encode_ric_subscription_request_message(void *buffer, size_t buf_size, long ricRequestorID, long ricRequestSequenceNumber, long ranFunctionID, void *eventTriggerDefinition, size_t eventTriggerDefinitionSize, int actionCount, long *actionIds, long* actionTypes, RICactionDefinition *actionDefinitions, RICSubsequentAction *subsequentActionTypes);

/* RICsubscriptionResponse */
long e2ap_get_ric_subscription_response_sequence_number(void *buffer, size_t buf_size);
ssize_t  e2ap_set_ric_subscription_response_sequence_number(void *buffer, size_t buf_size, long sequence_number);
RICsubscriptionResponseMsg* e2ap_decode_ric_subscription_response_message(void *buffer, size_t buf_size);

/* RICsubscriptionFailure */
long e2ap_get_ric_subscription_failure_sequence_number(void *buffer, size_t buf_size);

/* RICsubscriptionDeleteRequest */
long e2ap_get_ric_subscription_delete_request_sequence_number(void *buffer, size_t buf_size);
ssize_t  e2ap_set_ric_subscription_delete_request_sequence_number(void *buffer, size_t buf_size, long sequence_number);
ssize_t e2ap_encode_ric_subscription_delete_request_message(void *buffer, size_t buf_size, long ricRequestorID, long ricRequestSequenceNumber, long ranFunctionID);

/* RICsubscriptionDeleteResponse */
long e2ap_get_ric_subscription_delete_response_sequence_number(void *buffer, size_t buf_size);
ssize_t  e2ap_set_ric_subscription_delete_response_sequence_number(void *buffer, size_t buf_size, long sequence_number);

/* RICsubscriptionDeleteFailure */
long e2ap_get_ric_subscription_delete_failure_sequence_number(void *buffer, size_t buf_size);

/* RICindication */
RICindicationMsg* e2ap_decode_ric_indication_message(void *buffer, size_t buf_size);
void e2ap_free_decoded_ric_indication_message(RICindicationMsg* msg);

ssize_t e2sm_encode_ric_event_trigger_definition(void *buffer, size_t buf_size, size_t event_trigger_count, long RT_periods);
ssize_t e2sm_encode_ric_action_definition(void *buffer, size_t buf_size, long ric_style_type);
E2SM_KPM_IndicationHeader_t* e2sm_decode_ric_indication_header(void *buffer, size_t buf_size);
void e2sm_free_ric_indication_header(E2SM_KPM_IndicationHeader_t* indHdr);
E2SM_KPM_IndicationMessage_t* e2sm_decode_ric_indication_message(void *buffer, size_t buf_size);
void e2sm_free_ric_indication_message(E2SM_KPM_IndicationMessage_t* indMsg);

/* RICcontrol */
ssize_t e2ap_encode_ric_control_request_message(void *buffer, size_t buf_size, long ricRequestorID, long ricRequestSequenceNumber, long ranFunctionID, void *ricControlHdr, size_t ricControlHdrSize, void *ricControlMsg, size_t ricControlMsgSize);
extern ssize_t e2sm_encode_ric_control_header(void *buffer, size_t buf_size, void *ueIDbuf, size_t ueIDbuf_size, long ricControlStyleType, long ricControlActionID);
extern ssize_t e2sm_encode_ric_control_message(void *buffer, size_t buf_size, long targetPrimaryCell, long targetCell, long nrOrEUtraCell, long nrCGIOrECGI, void *ranParameterValue, size_t  ranParameterValue_size);

#endif /* _WRAPPER_H_ */
