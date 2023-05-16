#include <errno.h>
#include "wrapper.h"
#include "OCTET_STRING.h"

size_t encode_E2AP_PDU(E2AP_PDU_t* pdu, void* buffer, size_t buf_size)
{
    asn_enc_rval_t encode_result;
    encode_result = aper_encode_to_buffer(&asn_DEF_E2AP_PDU, NULL, pdu, buffer, buf_size);
    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    if(encode_result.encoded == -1) {
        fprintf(stderr, "Cannot encode %s: %s\n", encode_result.failed_type->name, strerror(errno));
        return -1;
    } else {
          return encode_result.encoded;
    }
}

E2AP_PDU_t* decode_E2AP_PDU(const void* buffer, size_t buf_size)
{
    asn_dec_rval_t decode_result;
    E2AP_PDU_t *pdu = 0;
    decode_result = aper_decode_complete(NULL, &asn_DEF_E2AP_PDU, (void **)&pdu, buffer, buf_size);
    if(decode_result.code == RC_OK) {
        return pdu;
    } else {
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
        return 0;
    }
}

/* RICsubscriptionRequest */
long e2ap_get_ric_subscription_request_sequence_number(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_initiatingMessage)
    {
        InitiatingMessage_t* initiatingMessage = pdu->choice.initiatingMessage;
        if ( initiatingMessage->procedureCode == ProcedureCode_id_RICsubscription
            && initiatingMessage->value.present == InitiatingMessage__value_PR_RICsubscriptionRequest)
        {
            RICsubscriptionRequest_t *ric_subscription_request = &(initiatingMessage->value.choice.RICsubscriptionRequest);
            for (int i = 0; i < ric_subscription_request->protocolIEs.list.count; ++i )
            {
                if ( ric_subscription_request->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    long sequenceNumber = ric_subscription_request->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                    return sequenceNumber;
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

ssize_t  e2ap_set_ric_subscription_request_sequence_number(void *buffer, size_t buf_size, long sequence_number)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_initiatingMessage)
    {
        InitiatingMessage_t* initiatingMessage = pdu->choice.initiatingMessage;
        if ( initiatingMessage->procedureCode == ProcedureCode_id_RICsubscription
            && initiatingMessage->value.present == InitiatingMessage__value_PR_RICsubscriptionRequest)
        {
            RICsubscriptionRequest_t *ricSubscriptionRequest = &initiatingMessage->value.choice.RICsubscriptionRequest;
            for (int i = 0; i < ricSubscriptionRequest->protocolIEs.list.count; ++i )
            {
                if ( ricSubscriptionRequest->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    ricSubscriptionRequest->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID = sequence_number;
                    return encode_E2AP_PDU(pdu, buffer, buf_size);
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

ssize_t e2ap_encode_ric_subscription_request_message(void *buffer, size_t buf_size, long ricRequestorID, long ricRequestSequenceNumber, long ranFunctionID, void *eventTriggerDefinition, size_t eventTriggerDefinitionSize, int actionCount, long *actionIds, long* actionTypes, RICactionDefinition *actionDefinitions, RICSubsequentAction *subsequentActionTypes) 
{
    E2AP_PDU_t *init = (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU_t));
    if(!init) {
        fprintf(stderr, "alloc E2AP_PDU failed\n");
        return -1;
    }
    
    InitiatingMessage_t *initiatingMsg = (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t));
    if(!initiatingMsg) {
        fprintf(stderr, "alloc InitiatingMessage failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    init->choice.initiatingMessage = initiatingMsg;
    init->present = E2AP_PDU_PR_initiatingMessage;

    initiatingMsg->procedureCode = ProcedureCode_id_RICsubscription;
    initiatingMsg->criticality = Criticality_reject;
    initiatingMsg->value.present = InitiatingMessage__value_PR_RICsubscriptionRequest;

    RICsubscriptionRequest_t *subscription_request = &initiatingMsg->value.choice.RICsubscriptionRequest;
    
    // request contains 5 IEs

    // RICrequestID
    RICsubscriptionRequest_IEs_t *ies_reqID = (RICsubscriptionRequest_IEs_t *)calloc(1, sizeof(RICsubscriptionRequest_IEs_t));
    if(!ies_reqID) {
        fprintf(stderr, "alloc RICrequestID failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    ies_reqID->criticality = Criticality_reject;
    ies_reqID->id = ProtocolIE_ID_id_RICrequestID;
    ies_reqID->value.present = RICsubscriptionRequest_IEs__value_PR_RICrequestID;
    RICrequestID_t *ricrequest_ie = &ies_reqID->value.choice.RICrequestID;
    ricrequest_ie->ricRequestorID = ricRequestorID;
    ricrequest_ie->ricInstanceID = ricRequestSequenceNumber;
    ASN_SEQUENCE_ADD(&subscription_request->protocolIEs.list, ies_reqID);

    // RICfunctionID
    RICsubscriptionRequest_IEs_t *ies_ranfunc = (RICsubscriptionRequest_IEs_t *)calloc(1, sizeof(RICsubscriptionRequest_IEs_t));
    if(!ies_ranfunc) {
        fprintf(stderr, "alloc RICfunctionID failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    ies_ranfunc->criticality = Criticality_reject;
    ies_ranfunc->id = ProtocolIE_ID_id_RANfunctionID;
    ies_ranfunc->value.present = RICsubscriptionRequest_IEs__value_PR_RANfunctionID;
    RANfunctionID_t *ranfunction_ie = &ies_ranfunc->value.choice.RANfunctionID;
    *ranfunction_ie = ranFunctionID;
    ASN_SEQUENCE_ADD(&subscription_request->protocolIEs.list, ies_ranfunc);

    // RICsubscription
    RICsubscriptionRequest_IEs_t *ies_subscription = (RICsubscriptionRequest_IEs_t *)calloc(1, sizeof(RICsubscriptionRequest_IEs_t));
    if(!ies_subscription) {
        fprintf(stderr, "alloc RICsubscription failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    ies_subscription->criticality = Criticality_reject;
    ies_subscription->id = ProtocolIE_ID_id_RICsubscriptionDetails;
    ies_subscription->value.present = RICsubscriptionRequest_IEs__value_PR_RICsubscriptionDetails;
    RICsubscriptionDetails_t *ricsubscription_ie = &ies_subscription->value.choice.RICsubscriptionDetails;

    // RICeventTriggerDefinition
    RICeventTriggerDefinition_t *eventTrigger = &ricsubscription_ie->ricEventTriggerDefinition;
    eventTrigger->buf = (uint8_t *)calloc(1, eventTriggerDefinitionSize);
    if(!eventTrigger->buf) {
        fprintf(stderr, "alloc eventTrigger failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    memcpy(eventTrigger->buf, eventTriggerDefinition, eventTriggerDefinitionSize);
    eventTrigger->size = eventTriggerDefinitionSize;
    
    // RICactions-ToBeSetup-List
    RICactions_ToBeSetup_List_t *ricActions = &ricsubscription_ie->ricAction_ToBeSetup_List;
    int index = 0;
    while (index < actionCount) {
        RICaction_ToBeSetup_ItemIEs_t *ies_action = (RICaction_ToBeSetup_ItemIEs_t *)calloc(1, sizeof(RICaction_ToBeSetup_ItemIEs_t));
        if(!ies_action) {
            fprintf(stderr, "alloc RICaction failed\n");
            ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
            return -1;
        }

        ies_action->criticality = Criticality_reject;
        ies_action->id = ProtocolIE_ID_id_RICaction_ToBeSetup_Item;
        ies_action->value.present = RICaction_ToBeSetup_ItemIEs__value_PR_RICaction_ToBeSetup_Item;
        RICaction_ToBeSetup_Item_t *ricaction_ie = &ies_action->value.choice.RICaction_ToBeSetup_Item;
        ricaction_ie->ricActionID = actionIds[index];
        ricaction_ie->ricActionType = actionTypes[index];

        int actionDefinitionSize = actionDefinitions[index].size;
        if(actionDefinitionSize != 0) {
            RICactionDefinition_t *actionDefinition = ricaction_ie->ricActionDefinition;
            
            actionDefinition->buf = (uint8_t *)calloc(1, actionDefinitionSize);
            if(!actionDefinition->buf) {
                fprintf(stderr, "alloc actionDefinition[%d] failed\n", index);
                ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
                return -1;
            }

            memcpy(actionDefinition->buf, actionDefinitions[index].actionDefinition, actionDefinitionSize);
            actionDefinition->size = actionDefinitionSize;
        }

        if(subsequentActionTypes[index].isValid != 0) {
            RICsubsequentAction_t *subsequentAction = ricaction_ie->ricSubsequentAction;
            subsequentAction->ricSubsequentActionType = subsequentActionTypes[index].subsequentActionType;
            subsequentAction->ricTimeToWait = subsequentActionTypes[index].timeToWait;
        }

        ASN_SEQUENCE_ADD(&ricActions->list, ies_action);
        index++;
    }
    ASN_SEQUENCE_ADD(&subscription_request->protocolIEs.list, ies_subscription);

    return encode_E2AP_PDU(init, buffer, buf_size);
}

/* RICsubscriptionResponse */
long e2ap_get_ric_subscription_response_sequence_number(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_successfulOutcome )
    {
        SuccessfulOutcome_t* successfulOutcome = pdu->choice.successfulOutcome;
        if ( successfulOutcome->procedureCode == ProcedureCode_id_RICsubscription
            && successfulOutcome->value.present == SuccessfulOutcome__value_PR_RICsubscriptionResponse)
        {
            RICsubscriptionResponse_t *ricSubscriptionResponse = &successfulOutcome->value.choice.RICsubscriptionResponse;
            for (int i = 0; i < ricSubscriptionResponse->protocolIEs.list.count; ++i )
            {
                if ( ricSubscriptionResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    long sequenceNumber = ricSubscriptionResponse->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                    return sequenceNumber;
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

ssize_t  e2ap_set_ric_subscription_response_sequence_number(void *buffer, size_t buf_size, long sequence_number)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_successfulOutcome )
    {
        SuccessfulOutcome_t* successfulOutcome = pdu->choice.successfulOutcome;
        if ( successfulOutcome->procedureCode == ProcedureCode_id_RICsubscription
            && successfulOutcome->value.present == SuccessfulOutcome__value_PR_RICsubscriptionResponse)
        {
            RICsubscriptionResponse_t *ricSubscriptionResponse = &successfulOutcome->value.choice.RICsubscriptionResponse;
            for (int i = 0; i < ricSubscriptionResponse->protocolIEs.list.count; ++i )
            {
                if ( ricSubscriptionResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    ricSubscriptionResponse->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID = sequence_number;
                    return encode_E2AP_PDU(pdu, buffer, buf_size);
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

RICsubscriptionResponseMsg* e2ap_decode_ric_subscription_response_message(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_successfulOutcome)
    {
        SuccessfulOutcome_t* successfulOutcome = pdu->choice.successfulOutcome;
        if ( successfulOutcome->procedureCode == ProcedureCode_id_RICsubscription
            && successfulOutcome->value.present == SuccessfulOutcome__value_PR_RICsubscriptionResponse)
        {
            RICsubscriptionResponse_t *subscriptionResponse = &(successfulOutcome->value.choice.RICsubscriptionResponse);
            RICsubscriptionResponseMsg *msg = (RICsubscriptionResponseMsg *)calloc(1, sizeof(RICsubscriptionResponseMsg));
            for (int i = 0; i < subscriptionResponse->protocolIEs.list.count; ++i )
            {
                if (subscriptionResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID) {
                    msg->requestorID = subscriptionResponse->protocolIEs.list.array[i]->value.choice.RICrequestID.ricRequestorID;
                    msg->requestSequenceNumber = subscriptionResponse->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                }
                else if (subscriptionResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RANfunctionID) {
                    msg->ranfunctionID = subscriptionResponse->protocolIEs.list.array[i]->value.choice.RANfunctionID;
                }
                else if (subscriptionResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICactions_Admitted) {
                    RICaction_Admitted_List_t *ricActionAdmittedList = &(subscriptionResponse->protocolIEs.list.array[i]->value.choice.RICaction_Admitted_List);
                    int index = 0;
                    while (index < ricActionAdmittedList->list.count) {
                        RICaction_Admitted_ItemIEs_t *ricActionAdmittedItem = (RICaction_Admitted_ItemIEs_t *)ricActionAdmittedList->list.array[index];
                        if (ricActionAdmittedItem->id == ProtocolIE_ID_id_RICaction_Admitted_Item) {
                            msg->ricActionAdmittedList.ricActionID[index] = ricActionAdmittedItem->value.choice.RICaction_Admitted_Item.ricActionID;
                        }
                        index++;
                    }
                    msg->ricActionAdmittedList.count = index;
                }
                else if (subscriptionResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICactions_NotAdmitted) {
                    RICaction_NotAdmitted_List_t *ricActionNotAdmittedList = &(subscriptionResponse->protocolIEs.list.array[i]->value.choice.RICaction_NotAdmitted_List);
                    int index = 0;
                    while (index < ricActionNotAdmittedList->list.count) {
                        RICaction_NotAdmitted_ItemIEs_t *ricActionNotAdmittedItem = (RICaction_NotAdmitted_ItemIEs_t *)ricActionNotAdmittedList->list.array[index];
                        if (ricActionNotAdmittedItem->id == ProtocolIE_ID_id_RICaction_NotAdmitted_Item) {
                            msg->ricActionNotAdmittedList.ricActionID[index] = ricActionNotAdmittedItem->value.choice.RICaction_NotAdmitted_Item.ricActionID;
                            int RICcauseType = ricActionNotAdmittedItem->value.choice.RICaction_NotAdmitted_Item.cause.present;
                            switch(RICcauseType) {
                                case Cause_PR_ricRequest:
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseType = Cause_PR_ricRequest;
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseID = ricActionNotAdmittedItem->value.choice.RICaction_NotAdmitted_Item.cause.choice.ricRequest;
                                    break;
                                case Cause_PR_ricService:
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseType = Cause_PR_ricService;
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseID = ricActionNotAdmittedItem->value.choice.RICaction_NotAdmitted_Item.cause.choice.ricService;
                                    break;
                                case Cause_PR_transport:
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseType = Cause_PR_transport;
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseID = ricActionNotAdmittedItem->value.choice.RICaction_NotAdmitted_Item.cause.choice.transport;
                                    break;
                                case Cause_PR_protocol:
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseType = Cause_PR_protocol;
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseID = ricActionNotAdmittedItem->value.choice.RICaction_NotAdmitted_Item.cause.choice.protocol;
                                    break;
                                case Cause_PR_misc:
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseType = Cause_PR_misc;
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseID = ricActionNotAdmittedItem->value.choice.RICaction_NotAdmitted_Item.cause.choice.misc;
                                    break;
                            }
                        }
                        index++;
                    }
                    msg->ricActionNotAdmittedList.count = index;
                }
            }
            return msg;
        }
    }
    return NULL;
}

/* RICsubscriptionFailure */
long e2ap_get_ric_subscription_failure_sequence_number(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_unsuccessfulOutcome )
    {
        UnsuccessfulOutcome_t* unsuccessfulOutcome = pdu->choice.unsuccessfulOutcome;
        if ( unsuccessfulOutcome->procedureCode == ProcedureCode_id_RICsubscription
            && unsuccessfulOutcome->value.present == UnsuccessfulOutcome__value_PR_RICsubscriptionFailure)
        {
            RICsubscriptionFailure_t *ricSubscriptionFailure = &unsuccessfulOutcome->value.choice.RICsubscriptionFailure;
            for (int i = 0; i < ricSubscriptionFailure->protocolIEs.list.count; ++i )
            {
                if ( ricSubscriptionFailure->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    long sequenceNumber = ricSubscriptionFailure->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                    return sequenceNumber;
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

/* RICsubscriptionDeleteRequest */
long e2ap_get_ric_subscription_delete_request_sequence_number(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_initiatingMessage )
    {
        InitiatingMessage_t* initiatingMessage = pdu->choice.initiatingMessage;
        if ( initiatingMessage->procedureCode == ProcedureCode_id_RICsubscriptionDelete
            && initiatingMessage->value.present == InitiatingMessage__value_PR_RICsubscriptionDeleteRequest )
        {
            RICsubscriptionDeleteRequest_t *subscriptionDeleteRequest = &initiatingMessage->value.choice.RICsubscriptionDeleteRequest;
            for (int i = 0; i < subscriptionDeleteRequest->protocolIEs.list.count; ++i )
            {
                if ( subscriptionDeleteRequest->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    long sequenceNumber = subscriptionDeleteRequest->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                    return sequenceNumber;
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

ssize_t  e2ap_set_ric_subscription_delete_request_sequence_number(void *buffer, size_t buf_size, long sequence_number)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_initiatingMessage )
    {
        InitiatingMessage_t* initiatingMessage = pdu->choice.initiatingMessage;
        if ( initiatingMessage->procedureCode == ProcedureCode_id_RICsubscriptionDelete
            && initiatingMessage->value.present == InitiatingMessage__value_PR_RICsubscriptionDeleteRequest )
        {
            RICsubscriptionDeleteRequest_t* subscriptionDeleteRequest = &initiatingMessage->value.choice.RICsubscriptionDeleteRequest;
            for (int i = 0; i < subscriptionDeleteRequest->protocolIEs.list.count; ++i )
            {
                if ( subscriptionDeleteRequest->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    subscriptionDeleteRequest->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID = sequence_number;
                    return encode_E2AP_PDU(pdu, buffer, buf_size);
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

ssize_t e2ap_encode_ric_subscription_delete_request_message(void *buffer, size_t buf_size, long ricRequestorID, long ricRequestSequenceNumber, long ranFunctionID)
{
    E2AP_PDU_t *init = (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU_t));
    if(!init) {
        fprintf(stderr, "alloc E2AP_PDU failed\n");
        return -1;
    }

    InitiatingMessage_t *initiatingMsg = (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t));
    if(!initiatingMsg) {
        fprintf(stderr, "alloc InitiatingMessage failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    init->choice.initiatingMessage = initiatingMsg;
    init->present = E2AP_PDU_PR_initiatingMessage;

    initiatingMsg->procedureCode = ProcedureCode_id_RICsubscriptionDelete;
    initiatingMsg->criticality = Criticality_reject;
    initiatingMsg->value.present = InitiatingMessage__value_PR_RICsubscriptionDeleteRequest;

    RICsubscriptionDeleteRequest_t *subscription_delete_request = &initiatingMsg->value.choice.RICsubscriptionDeleteRequest;
    
    // request contains 2 IEs

    // RICrequestID
    RICsubscriptionDeleteRequest_IEs_t *ies_reqID = (RICsubscriptionDeleteRequest_IEs_t *)calloc(1, sizeof(RICsubscriptionDeleteRequest_IEs_t));
    if(!ies_reqID) {
        fprintf(stderr, "alloc RICrequestID failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    ies_reqID->criticality = Criticality_reject;
    ies_reqID->id = ProtocolIE_ID_id_RICrequestID;
    ies_reqID->value.present = RICsubscriptionDeleteRequest_IEs__value_PR_RICrequestID;
    RICrequestID_t *ricrequest_ie = &ies_reqID->value.choice.RICrequestID;
    ricrequest_ie->ricRequestorID = ricRequestorID;
    ricrequest_ie->ricInstanceID = ricRequestSequenceNumber;
    ASN_SEQUENCE_ADD(&subscription_delete_request->protocolIEs.list, ies_reqID);

    // RICfunctionID
    RICsubscriptionDeleteRequest_IEs_t *ies_ranfunc = (RICsubscriptionDeleteRequest_IEs_t *)calloc(1, sizeof(RICsubscriptionDeleteRequest_IEs_t));
    if(!ies_ranfunc) {
        fprintf(stderr, "alloc RICfunctionID failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    ies_ranfunc->criticality = Criticality_reject;
    ies_ranfunc->id = ProtocolIE_ID_id_RANfunctionID;
    ies_ranfunc->value.present = RICsubscriptionDeleteRequest_IEs__value_PR_RANfunctionID;
    RANfunctionID_t *ranfunction_ie = &ies_ranfunc->value.choice.RANfunctionID;
    *ranfunction_ie = ranFunctionID;
    ASN_SEQUENCE_ADD(&subscription_delete_request->protocolIEs.list, ies_ranfunc);

    return encode_E2AP_PDU(init, buffer, buf_size);
}

/* RICsubscriptionDeleteResponse */
long e2ap_get_ric_subscription_delete_response_sequence_number(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_successfulOutcome )
    {
        SuccessfulOutcome_t* successfulOutcome = pdu->choice.successfulOutcome;
        if ( successfulOutcome->procedureCode == ProcedureCode_id_RICsubscriptionDelete
            && successfulOutcome->value.present == SuccessfulOutcome__value_PR_RICsubscriptionDeleteResponse )
        {
            RICsubscriptionDeleteResponse_t* subscriptionDeleteResponse = &successfulOutcome->value.choice.RICsubscriptionDeleteResponse;
            for (int i = 0; i < subscriptionDeleteResponse->protocolIEs.list.count; ++i )
            {
                if ( subscriptionDeleteResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    long sequenceNumber = subscriptionDeleteResponse->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                    return sequenceNumber;
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

ssize_t  e2ap_set_ric_subscription_delete_response_sequence_number(void *buffer, size_t buf_size, long sequence_number)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_successfulOutcome )
    {
        SuccessfulOutcome_t* successfulOutcome = pdu->choice.successfulOutcome;
        if ( successfulOutcome->procedureCode == ProcedureCode_id_RICsubscriptionDelete
            && successfulOutcome->value.present == SuccessfulOutcome__value_PR_RICsubscriptionDeleteResponse )
        {
            RICsubscriptionDeleteResponse_t* subscriptionDeleteResponse = &successfulOutcome->value.choice.RICsubscriptionDeleteResponse;
            for (int i = 0; i < subscriptionDeleteResponse->protocolIEs.list.count; ++i )
            {
                if ( subscriptionDeleteResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    subscriptionDeleteResponse->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID = sequence_number;
                    return encode_E2AP_PDU(pdu, buffer, buf_size);
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

/* RICsubscriptionDeleteFailure */
long e2ap_get_ric_subscription_delete_failure_sequence_number(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_unsuccessfulOutcome )
    {
        UnsuccessfulOutcome_t* unsuccessfulOutcome = pdu->choice.unsuccessfulOutcome;
        if ( unsuccessfulOutcome->procedureCode == ProcedureCode_id_RICsubscriptionDelete
            && unsuccessfulOutcome->value.present == UnsuccessfulOutcome__value_PR_RICsubscriptionDeleteFailure)
        {
            RICsubscriptionDeleteFailure_t *ricSubscriptionDeleteFailure = &unsuccessfulOutcome->value.choice.RICsubscriptionDeleteFailure;
            for (int i = 0; i < ricSubscriptionDeleteFailure->protocolIEs.list.count; ++i )
            {
                if ( ricSubscriptionDeleteFailure->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    long sequenceNumber = ricSubscriptionDeleteFailure->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                    return sequenceNumber;
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

/* RICindication */

RICindicationMsg* e2ap_decode_ric_indication_message(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_initiatingMessage)
    {
        InitiatingMessage_t* initiatingMessage = pdu->choice.initiatingMessage;
        if ( initiatingMessage->procedureCode == ProcedureCode_id_RICindication
            && initiatingMessage->value.present == InitiatingMessage__value_PR_RICindication)
        {
            RICindication_t *indication = &(initiatingMessage->value.choice.RICindication);
            RICindicationMsg *msg = (RICindicationMsg *)calloc(1, sizeof(RICindicationMsg));
            for (int i = 0; i < indication->protocolIEs.list.count; ++i )
            {
                if (indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID) {
                    msg->requestorID = indication->protocolIEs.list.array[i]->value.choice.RICrequestID.ricRequestorID;
                    msg->requestSequenceNumber = indication->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                }
                else if (indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RANfunctionID) {
                    msg->ranfunctionID = indication->protocolIEs.list.array[i]->value.choice.RANfunctionID;
                }
                else if (indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICactionID) {
                    msg->actionID = indication->protocolIEs.list.array[i]->value.choice.RICactionID;
                }
                else if(indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICindicationSN) {
                    msg->indicationSN = indication->protocolIEs.list.array[i]->value.choice.RICindicationSN;
                }
                else if(indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICindicationType) {
                    msg->indicationType = indication->protocolIEs.list.array[i]->value.choice.RICindicationType;
                }
                else if(indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICindicationHeader) {
                    size_t headerSize = indication->protocolIEs.list.array[i]->value.choice.RICindicationHeader.size;
                    msg->indicationHeader = calloc(1, headerSize);
                    if (!msg->indicationHeader) {
                        fprintf(stderr, "alloc RICindicationHeader failed\n");
                        e2ap_free_decoded_ric_indication_message(msg);
                        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                        return NULL;
                    }

                    memcpy(msg->indicationHeader, indication->protocolIEs.list.array[i]->value.choice.RICindicationHeader.buf, headerSize);
                    msg->indicationHeaderSize = headerSize;
                }
                else if(indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICindicationMessage) {
                    size_t messsageSize = indication->protocolIEs.list.array[i]->value.choice.RICindicationMessage.size;
                    msg->indicationMessage = calloc(1, messsageSize);
                    if (!msg->indicationMessage) {
                        fprintf(stderr, "alloc RICindicationMessage failed\n");
                        e2ap_free_decoded_ric_indication_message(msg);
                        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                        return NULL;
                    }

                    memcpy(msg->indicationMessage, indication->protocolIEs.list.array[i]->value.choice.RICindicationMessage.buf, messsageSize);
                    msg->indicationMessageSize = messsageSize;
                }
                else if(indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICcallProcessID) {
                    size_t callProcessIDSize = indication->protocolIEs.list.array[i]->value.choice.RICcallProcessID.size;
                    msg->callProcessID = calloc(1, callProcessIDSize);
                    if (!msg->callProcessID) {
                        fprintf(stderr, "alloc RICcallProcessID failed\n");
                        e2ap_free_decoded_ric_indication_message(msg);
                        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                        return NULL;
                    }

                    memcpy(msg->callProcessID, indication->protocolIEs.list.array[i]->value.choice.RICcallProcessID.buf, callProcessIDSize);
                    msg->callProcessIDSize = callProcessIDSize;
                }
            }
            return msg;
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return NULL;
}

void e2ap_free_decoded_ric_indication_message(RICindicationMsg* msg) {
    if(msg == NULL) {
        return;
    }

    if(msg->indicationHeader != NULL) {
        free(msg->indicationHeader);
        msg->indicationHeader = NULL;
    }
    if(msg->indicationMessage != NULL) {
        free(msg->indicationMessage);
        msg->indicationMessage = NULL;
    }
    if(msg->callProcessID != NULL) {
        free(msg->callProcessID);
        msg->callProcessID = NULL;
    }
    free(msg);
    msg = NULL;
}


ssize_t e2sm_encode_ric_event_trigger_definition(void *buffer, size_t buf_size, size_t event_trigger_count, long *RT_periods) {
	E2SM_KPM_EventTriggerDefinition_t *eventTriggerDef = (E2SM_KPM_EventTriggerDefinition_t *)calloc(1, sizeof(E2SM_KPM_EventTriggerDefinition_t));
	if(!eventTriggerDef) {
		fprintf(stderr, "alloc EventTriggerDefinition failed\n");
		return -1;
	}

	E2SM_KPM_EventTriggerDefinition_Format1_t *innerDef = (E2SM_KPM_EventTriggerDefinition_Format1_t *)calloc(1, sizeof(E2SM_KPM_EventTriggerDefinition_Format1_t));
	if(!innerDef) {
		fprintf(stderr, "alloc EventTriggerDefinition Format1 failed\n");
		ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_EventTriggerDefinition, eventTriggerDef);
		return -1;
	}

	eventTriggerDef->present = E2SM_KPM_EventTriggerDefinition_PR_eventDefinition_Format1;
	eventTriggerDef->choice.eventDefinition_Format1 = innerDef;

	struct E2SM_KPM_EventTriggerDefinition_Format1__policyTest_List *policyTestList = (struct E2SM_KPM_EventTriggerDefinition_Format1__policyTest_List *)calloc(1, sizeof(struct E2SM_KPM_EventTriggerDefinition_Format1__policyTest_List));
	innerDef->policyTest_List = policyTestList;
	
	int index = 0;
	while(index < event_trigger_count) {
		Trigger_ConditionIE_Item_t *triggerCondition = (Trigger_ConditionIE_Item_t *)calloc(1, sizeof(Trigger_ConditionIE_Item_t));
		assert(triggerCondition != 0);
		triggerCondition->report_Period_IE = RT_periods[index];

		ASN_SEQUENCE_ADD(&policyTestList->list, triggerCondition);
		index++;
	}

	asn_enc_rval_t encode_result;
    encode_result = aper_encode_to_buffer(&asn_DEF_E2SM_KPM_EventTriggerDefinition, NULL, eventTriggerDef, buffer, buf_size);
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_EventTriggerDefinition, eventTriggerDef);
    if(encode_result.encoded == -1) {
        fprintf(stderr, "Cannot encode %s: %s\n", encode_result.failed_type->name, strerror(errno));
        return -1;
    } else {
	    return encode_result.encoded;
	}
}

ssize_t e2sm_encode_ric_action_definition(void *buffer, size_t buf_size, long ric_style_type) {
	E2SM_KPM_ActionDefinition_t *actionDef = (E2SM_KPM_ActionDefinition_t *)calloc(1, sizeof(E2SM_KPM_ActionDefinition_t));
	if(!actionDef) {
		fprintf(stderr, "alloc RIC ActionDefinition failed\n");
		return -1;
	}

	actionDef->ric_Style_Type = ric_style_type;

	asn_enc_rval_t encode_result;
    encode_result = aper_encode_to_buffer(&asn_DEF_E2SM_KPM_ActionDefinition, NULL, actionDef, buffer, buf_size);
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_ActionDefinition, actionDef);
	if(encode_result.encoded == -1) {
	    fprintf(stderr, "Cannot encode %s: %s\n", encode_result.failed_type->name, strerror(errno));
	    return -1;
	} else {
    	return encode_result.encoded;
    }
}

E2SM_KPM_IndicationHeader_t* e2sm_decode_ric_indication_header(void *buffer, size_t buf_size) {
	asn_dec_rval_t decode_result;
    E2SM_KPM_IndicationHeader_t *indHdr = 0;
    decode_result = aper_decode_complete(NULL, &asn_DEF_E2SM_KPM_IndicationHeader, (void **)&indHdr, buffer, buf_size);
    if(decode_result.code == RC_OK) {
        return indHdr;
    }
    else {
        ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationHeader, indHdr);
        return NULL;
    }
}

void e2sm_free_ric_indication_header(E2SM_KPM_IndicationHeader_t* indHdr) {
	ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationHeader, indHdr);
}

E2SM_KPM_IndicationMessage_t* e2sm_decode_ric_indication_message(void *buffer, size_t buf_size) {
	asn_dec_rval_t decode_result;
    E2SM_KPM_IndicationMessage_t *indMsg = 0;
    decode_result = aper_decode_complete(NULL, &asn_DEF_E2SM_KPM_IndicationMessage, (void **)&indMsg, buffer, buf_size);
    if(decode_result.code == RC_OK) {
    	return indMsg;
    }
    else {
        ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, indMsg);
        return NULL;
    }
}

void e2sm_free_ric_indication_message(E2SM_KPM_IndicationMessage_t* indMsg) {
	ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, indMsg);
}

ssize_t e2ap_encode_ric_control_request_message(void *buffer, size_t buf_size, long ricRequestorID, long ricRequestSequenceNumber, 
                  long ranFunctionID, void *ricControlHdr, size_t ricControlHdrSize, void *ricControlMsg, size_t ricControlMsgSize)
{
  
    E2AP_PDU_t *init = (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU_t));
    if(!init) {
        fprintf(stderr, "alloc E2AP_PDU failed\n");
        return -1;
    }

    
    InitiatingMessage_t *initiatingMsg = (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t));
    if(!initiatingMsg) {
        fprintf(stderr, "alloc InitiatingMessage failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

        init->choice.initiatingMessage = initiatingMsg;
    init->present = E2AP_PDU_PR_initiatingMessage;

    initiatingMsg->procedureCode = ProcedureCode_id_RICcontrol;
    initiatingMsg->criticality = Criticality_reject;
    initiatingMsg->value.present = InitiatingMessage__value_PR_RICcontrolRequest;

    RICcontrolRequest_t *control_request = &initiatingMsg->value.choice.RICcontrolRequest;


    //RICrequestID
    RICcontrolRequest_IEs_t *controlReqID = (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    if(!controlReqID) {
        fprintf(stderr, "alloc RICrequestID failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    controlReqID->criticality = Criticality_reject;
    controlReqID->id = ProtocolIE_ID_id_RICrequestID;

    controlReqID->value.present = RICcontrolRequest_IEs__value_PR_RICrequestID;
    RICrequestID_t *ricrequest_ie = &controlReqID->value.choice.RICrequestID;
    ricrequest_ie->ricRequestorID = ricRequestorID;
    ricrequest_ie->ricInstanceID = ricRequestSequenceNumber;
    ASN_SEQUENCE_ADD(&control_request->protocolIEs.list, controlReqID);

    //RICfunctionID
    RICcontrolRequest_IEs_t *controlReqFunID = (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    if(!controlReqFunID) {
        fprintf(stderr, "alloc RICrequestID failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    controlReqFunID->criticality = Criticality_reject;
    controlReqFunID->id = ProtocolIE_ID_id_RANfunctionID;
    controlReqFunID->value.present = RICcontrolRequest_IEs__value_PR_RANfunctionID;
    RANfunctionID_t *ranfunction_ie = &controlReqFunID->value.choice.RANfunctionID;
    *ranfunction_ie = ranFunctionID;
    ASN_SEQUENCE_ADD(&control_request->protocolIEs.list, controlReqFunID);

    // RICControlHdr
    RICcontrolRequest_IEs_t *controlReqHdr = (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    if(!controlReqHdr) {
        fprintf(stderr, "alloc RICcontrolRequest_IEs_t failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }
    controlReqHdr->criticality = Criticality_reject;
    controlReqHdr->id = ProtocolIE_ID_id_RICcontrolHeader;
    controlReqHdr->value.present = RICcontrolRequest_IEs__value_PR_RICcontrolHeader;
    RICcontrolHeader_t *controlHdr = &controlReqHdr->value.choice.RICcontrolHeader;
    controlHdr->buf = (uint8_t *)calloc(1, ricControlHdrSize);
    if(!controlHdr->buf) {
        fprintf(stderr, "alloc RICcontrolHeader_t buf failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    memcpy(controlHdr->buf, ricControlHdr, ricControlHdrSize);
    controlHdr->size = ricControlHdrSize;
    ASN_SEQUENCE_ADD(&control_request->protocolIEs.list, controlReqHdr);

    //Ric Control Message
    RICcontrolRequest_IEs_t *controlReqMsg = (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    if(!controlReqMsg) {
        fprintf(stderr, "alloc RICcontrolRequest_IEs_t failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }
    controlReqMsg->criticality = Criticality_reject;
    controlReqMsg->id = ProtocolIE_ID_id_RICcontrolMessage;
    controlReqMsg->value.present = RICcontrolRequest_IEs__value_PR_RICcontrolMessage;
    RICcontrolMessage_t *controlMsg = &controlReqMsg->value.choice.RICcontrolMessage;
    controlMsg->buf = (uint8_t *)calloc(1, ricControlMsgSize);
    if(!controlMsg->buf) {
        fprintf(stderr, "alloc RICcontrolMessage_t buf failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    memcpy(controlMsg->buf, ricControlMsg, ricControlMsgSize);
    controlMsg->size = ricControlMsgSize;
    ASN_SEQUENCE_ADD(&control_request->protocolIEs.list, controlReqMsg);

    fprintf(stderr, "showing xer of asn_DEF_E2AP_PDU data\n");
    xer_fprint(stderr, &asn_DEF_E2AP_PDU, init);
    fprintf(stderr, "\n");
    fprintf(stderr, "After xer of asn_DEF_E2AP_PDU data\n");
   
    return encode_E2AP_PDU(init, buffer, buf_size);
}

                                        
ssize_t e2sm_encode_ric_control_header(void *buffer, size_t buf_size, void *ueIDbuf, size_t ueIDbuf_size, 
                        long ricControlStyleType, long ricControlActionID)
{ 
        E2SM_RC_ControlHeader_t *controlHeaderIE = (E2SM_RC_ControlHeader_t *)calloc(1, sizeof(E2SM_RC_ControlHeader_t));
        if(!controlHeaderIE)
        {
                fprintf(stderr, "alloc E2SM_RC_ControlHeader failed\n");
                   return -1;
        }

        controlHeaderIE->present = E2SM_RC_ControlHeader_PR_controlHeader_Format1;
        //E2SM_RC_ControlHeader_Format1_t  *controlHeader_Fmt1 = controlHeaderIE->choice.controlHeader_Format1;
        E2SM_RC_ControlHeader_Format1_t  *controlHeader_Fmt1 = (E2SM_RC_ControlHeader_Format1_t *)calloc(1, sizeof(E2SM_RC_ControlHeader_Format1_t));
        if(!controlHeader_Fmt1)
        {
                fprintf(stderr, "alloc E2SM_RC_ControlHeader failed\n");
                return -1;
        }
        
        controlHeader_Fmt1->ueId.buf = (uint8_t*)calloc(1, ueIDbuf_size);   
        memcpy(controlHeader_Fmt1->ueId.buf, ueIDbuf, ueIDbuf_size);        //Check how to get ueIDbuf from string
        controlHeader_Fmt1->ueId.size = ueIDbuf_size;

        controlHeader_Fmt1->ric_ControlStyle_Type = ricControlStyleType;
        controlHeader_Fmt1->ric_ControlAction_ID = ricControlActionID;

        controlHeaderIE->choice.controlHeader_Format1 = controlHeader_Fmt1;

        fprintf(stderr, "showing xer of asn_DEF_E2SM_RC_ControlHeader data\n");
        xer_fprint(stderr, &asn_DEF_E2SM_RC_ControlHeader, controlHeaderIE);
        fprintf(stderr, "\n");
        fprintf(stderr, "After xer of asn_DEF_E2SM_RC_ControlHeader data\n");
   
        asn_enc_rval_t encode_result;
        encode_result = aper_encode_to_buffer(&asn_DEF_E2SM_RC_ControlHeader, NULL, controlHeaderIE, buffer, buf_size);
        ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlHeader, controlHeaderIE);
        if(encode_result.encoded == -1)
        {
                fprintf(stderr, "Cannot encode %s: %s\n", encode_result.failed_type->name, strerror(errno));
                return -1;
        }
        else
        {
               return encode_result.encoded;
        }
}



ssize_t e2sm_encode_ric_control_message(void *buffer, size_t buf_size, long targetPrimaryCell, 
                        long targetCell, long nrOrEUtraCell, long nrCGIOrECGI, void* ranParameterValue, size_t  ranParameterValue_size)
{
        E2SM_RC_ControlMessage_t *e2smRcControlMsg = (E2SM_RC_ControlMessage_t*)calloc(1, sizeof(E2SM_RC_ControlMessage_t));
        if(!e2smRcControlMsg) {
            fprintf(stderr, "alloc E2SM_RC_ControlMessage_t failed\n");
        return -1;
        }

        e2smRcControlMsg->present = E2SM_RC_ControlMessage_PR_controlMessage_Format1;

       // E2SM_RC_ControlMessage_Format1_t *e2smRcControlFormat1 = e2smRcControlMsg->choice.controlMessage_Format1;

        E2SM_RC_ControlMessage_Format1_t *e2smRcControlFormat1 = (E2SM_RC_ControlMessage_Format1_t*)calloc(1, sizeof(E2SM_RC_ControlMessage_Format1_t));
        if(!e2smRcControlMsg) {
            fprintf(stderr, "alloc E2SM_RC_ControlMessage_Format1_t failed\n");
        return -1;
        }
        

        e2smRcControlFormat1->ranParameters_List =  
                        (struct E2SM_RC_ControlMessage_Format1__ranParameters_List*)calloc(1, sizeof(struct E2SM_RC_ControlMessage_Format1__ranParameters_List));
	if(!e2smRcControlFormat1->ranParameters_List)
	{
                fprintf(stderr, "alloc e2smRcControlFormat1->ranParameters_List failed\n");
                ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
                return -1;
	}

        // Start Target Primary Cell 
        RANParameter_Item_t *ranParameterItem1 = (RANParameter_Item_t*)calloc(1,sizeof(RANParameter_Item_t));
        if(!ranParameterItem1) {
                fprintf(stderr, "alloc RANParameter_Item_t1 failed\n");
                ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
                return -1;
        }

        
        ranParameterItem1->ranParameterItem_ID = targetPrimaryCell;     // Target Primary Cell ID value = 1
        RANParameter_ValueType_t *ranParameterValueType1 = (RANParameter_ValueType_t*)calloc(1, sizeof(RANParameter_ValueType_t));
        if(!ranParameterValueType1)
        {
                fprintf(stderr, "alloc RANParameter_ValueType_t1 failed\n");
                ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
                return -1;
        }
        
        ranParameterValueType1->present = RANParameter_ValueType_PR_ranParameter_Structure;
        RANParameter_STRUCTURE_t *ranParameterStructure1 = (RANParameter_STRUCTURE_t*)calloc(1, sizeof(RANParameter_STRUCTURE_t));
        if(!ranParameterStructure1)
        {
                fprintf(stderr, "alloc RANParameter_STRUCTURE_t1 failed\n");
                ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
                return -1;
        }

   
         // Start Target Cell 
        RANParameter_Item_t *ranParameterItem2 = (RANParameter_Item_t*)calloc(1,sizeof(RANParameter_Item_t));
        if(!ranParameterItem2)
        {

                ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
                fprintf(stderr, "alloc RANParameter_Item_t2 failed\n");
                return -1;
        }

        ranParameterItem2->ranParameterItem_ID = targetCell;    // Target Cell ID value = 2
        RANParameter_ValueType_t *ranParameterValueType2 = (RANParameter_ValueType_t*)calloc(1, sizeof(RANParameter_ValueType_t));
        if(!ranParameterValueType2)
        {
                ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
                fprintf(stderr, "alloc RANParameter_STRUCTURE_t2 failed\n");
                return -1;
        }
        

        ranParameterValueType2->present = RANParameter_ValueType_PR_ranParameter_Structure;
        RANParameter_STRUCTURE_t *ranParameterStructure2 = (RANParameter_STRUCTURE_t*)calloc(1, sizeof(struct RANParameter_STRUCTURE));
        if(!ranParameterStructure2)
        {
                ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
                fprintf(stderr, "alloc RANParameter_STRUCTURE_t2 failed\n");
                return -1;
        }

      
        // Start NR Cell  (or E-UTRA Cell) 
        RANParameter_Item_t *ranParameterItem3 = (RANParameter_Item_t*)calloc(1,sizeof(RANParameter_Item_t));
        if(!ranParameterItem3)
        {
                ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
                fprintf(stderr, "alloc RANParameter_Item_t3 failed\n");
                return -1;
        }

        ranParameterItem3->ranParameterItem_ID = nrOrEUtraCell; // NR Cell ID (or E-UTRA Cell ID) value = 
        RANParameter_ValueType_t *ranParameterValueType3 = (RANParameter_ValueType_t*)calloc(1, sizeof(RANParameter_ValueType_t));
        if(!ranParameterValueType3)
        {
                ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
                fprintf(stderr, "alloc RANParameter_Item_t3 failed\n");
                return -1;
        }

        ranParameterValueType3->present = RANParameter_ValueType_PR_ranParameter_Structure;
        RANParameter_STRUCTURE_t *ranParameterStructure3 = (struct RANParameter_STRUCTURE*)calloc(1, sizeof(struct RANParameter_STRUCTURE));
        if(!ranParameterStructure3)
        {
                ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
                fprintf(stderr, "alloc RANParameter_Item_t3 failed\n");
                return -1;
        }

        // Start NR CGI (or ECGI) 
        RANParameter_Item_t *ranParameterItem4 = (RANParameter_Item_t*)calloc(1, sizeof(RANParameter_Item_t));
        if(!ranParameterItem4)
        {
                ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
                fprintf(stderr, "alloc RANParameter_Item_t4 failed\n");
                return -1;
        }
        ranParameterItem4->ranParameterItem_ID = nrCGIOrECGI;   // NR CGI ID (or ECGI ID) value = 
        RANParameter_ValueType_t *ranParameterValueType4 = (RANParameter_ValueType_t*)calloc(1, sizeof(RANParameter_ValueType_t));
        if(!ranParameterValueType4)
        {
                ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
                fprintf(stderr, "alloc RANParameter_Item_t4 failed\n");
                return -1;
        }
        ranParameterValueType4->present = RANParameter_ValueType_PR_ranParameter_Element;
        ranParameterValueType4->choice.ranParameter_Element = (RANParameter_ELEMENT_t*)calloc(1, sizeof(RANParameter_ELEMENT_t));
        if(!ranParameterValueType4->choice.ranParameter_Element)
        {
                ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
                fprintf(stderr, "alloc RANParameter_Item_t4 failed\n");
                return -1;
        }
        ranParameterValueType4->choice.ranParameter_Element->keyFlag = 0;
        ranParameterValueType4->choice.ranParameter_Element->ranParameter_Value.present = RANParameter_Value_PR_valueOctS;

        ranParameterValueType4->choice.ranParameter_Element->ranParameter_Value.choice.valueOctS.buf = 
                                                (uint8_t*)calloc(1, ranParameterValue_size);
        if(!ranParameterValueType4->choice.ranParameter_Element->ranParameter_Value.choice.valueOctS.buf)
        {
                ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
                fprintf(stderr, "alloc RANParameter Value failed\n");
                return -1;
        }
	memcpy(ranParameterValueType4->choice.ranParameter_Element->ranParameter_Value.choice.valueOctS.buf, ranParameterValue, ranParameterValue_size);
        ranParameterValueType4->choice.ranParameter_Element->ranParameter_Value.choice.valueOctS.size = ranParameterValue_size;
        ranParameterItem4->ranParameterItem_valueType = ranParameterValueType4; // NR CGI (or ECGI)
        
        ASN_SEQUENCE_ADD(&ranParameterStructure3->sequence_of_ranParameters.list, ranParameterItem4);   // NR CGI (or ECGI)
        ranParameterValueType3->choice.ranParameter_Structure = ranParameterStructure3; // NR Cell  (or E-UTRA Cell)
        ranParameterItem3->ranParameterItem_valueType = ranParameterValueType3;

        ASN_SEQUENCE_ADD(&ranParameterStructure2->sequence_of_ranParameters.list, ranParameterItem3);   // NR Cell  (or E-UTRA Cell)
        ranParameterValueType2->choice.ranParameter_Structure = ranParameterStructure2; // Target Cell
        ranParameterItem2->ranParameterItem_valueType = ranParameterValueType2;

        ASN_SEQUENCE_ADD(&ranParameterStructure1->sequence_of_ranParameters.list, ranParameterItem2);   // Target Cell
        ranParameterValueType1->choice.ranParameter_Structure = ranParameterStructure1; // Target Primary Cell
        ranParameterItem1->ranParameterItem_valueType = ranParameterValueType1;

        ASN_SEQUENCE_ADD(&e2smRcControlFormat1->ranParameters_List->list, ranParameterItem1); // Target Primary Cell
        e2smRcControlMsg->choice.controlMessage_Format1 = e2smRcControlFormat1;


        fprintf(stderr, "showing xer of asn_DEF_E2SM_RC_ControlMessage data\n");
        xer_fprint(stderr, &asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
        fprintf(stderr, "\n");
        fprintf(stderr, "After xer of asn_DEF_E2SM_RC_ControlMessage data\n");

        asn_enc_rval_t encode_result;
        encode_result = aper_encode_to_buffer(&asn_DEF_E2SM_RC_ControlMessage, NULL, e2smRcControlMsg, buffer, buf_size);
        ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, e2smRcControlMsg);
        if(encode_result.encoded == -1)
        {
                fprintf(stderr, "Cannot encode %s: %s\n", encode_result.failed_type->name, strerror(errno));
                return -1;
        }
        else
        {
                return encode_result.encoded;
        }
}

