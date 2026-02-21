package protocols

import (
	"log-analyser/pkg/wireshark"
	"strings"
)

// CAP/SCP operation names (3GPP TS 29.078 / ETSI EN 301 140)
var capOpNames = map[string]string{
	"0":  "InitialDP",
	"1":  "RequestReportBCSMEvent",
	"2":  "EventReportBCSM",
	"3":  "CollectInformation",
	"4":  "Continue",
	"5":  "Connect",
	"6":  "ReleaseCall",
	"7":  "RequestReportBCSMEvent",
	"8":  "CallInformationReport",
	"9":  "CallInformationRequest",
	"10": "SelectFacility",
	"11": "ActivityTest",
	"12": "SelectRoute",
	"13": "ContinueWithArgument",
	"14": "InitiateCallAttempt",
	"16": "ResetTimer",
	"17": "FurnishChargingInformation",
	"18": "Connect",
	"19": "CallGap",
	"20": "ApplyCharging",
	"21": "SpecializedResourceReport",
	"22": "ApplyChargingReport",
	"23": "Cancel",
	"24": "ConnectToResource",
	"25": "DisconnectForwardConnection",
	"26": "PlayAnnouncement",
	"27": "PromptAndCollectUserInformation",
	"28": "SpecializedResourceReport",
	"30": "ReleaseCall",
	"31": "DisconnectLeg",
	"32": "MoveLeg",
	"33": "SplitLeg",
	"34": "EntityReleased",
	"35": "PlayTone",
	"36": "ManageTriggerData",
	"37": "AssistRequestInstructions",
	"38": "ReportUTSI",
	"39": "SendChargingInformation",
	"40": "SendFacilityInformation",
	"41": "RequestCurrentStatusReport",
	"42": "RequestEveryStatusChangeReport",
	"43": "RequestFirstStatusMatchReport",
	"44": "EventNotificationCharging",
	"45": "CollectionInformation",
	"46": "CallGap",
	"47": "InitialDPSMS",
	"48": "RequestReportSMSEvent",
	"49": "EventReportSMS",
	"50": "ConnectSMS",
	"51": "ContinueSMS",
	"52": "ReleaseSMS",
	"53": "ResetTimerSMS",
	"54": "FurnishChargingInformationSMS",
	"55": "SpecializedResourceReport",
	"56": "ActivityTestGPRS",
	"57": "ApplyChargingGPRS",
	"58": "ApplyChargingReportGPRS",
	"59": "CancelGPRS",
	"60": "ConnectGPRS",
	"61": "ContinueGPRS",
	"62": "EntityReleasedGPRS",
	"63": "FurnishChargingInformationGPRS",
	"64": "InitialDPGPRS",
	"65": "ReleaseGPRS",
	"66": "RequestReportGPRSEvent",
	"67": "ResetTimerGPRS",
	"68": "SendChargingInformationGPRS",
	"69": "EventReportGPRS",
	"70": "DisconnectForwardConnectionWithArgument",
}

// DissectCAP extracts CAP (SCP / CAMEL Application Part) information from a packet.
func DissectCAP(pkt *wireshark.Packet) {
	layer, ok := pkt.Layers["cap"]
	if !ok {
		// Some Wireshark builds may label it "camel"
		layer, ok = pkt.Layers["camel"]
		if !ok {
			return
		}
	}

	info := &wireshark.CAPInfo{}

	// Operation code → name
	for _, fname := range []string{"cap.opcode", "cap.op_code", "cap.localValue", "camel.localValue"} {
		if v := wireshark.FieldValue(layer, fname); v != "" {
			if name, found := capOpNames[v]; found {
				info.Operation = name
			} else {
				info.Operation = v
			}
			break
		}
	}

	// Service key
	for _, fname := range []string{"cap.serviceKey", "cap.service_key"} {
		if v := wireshark.FieldValue(layer, fname); v != "" {
			info.ServiceKey = v
			break
		}
	}

	// IMSI
	for _, fname := range []string{"cap.imsi", "e212.imsi"} {
		if v := wireshark.FieldValue(layer, fname); v != "" {
			info.IMSI = v
			break
		}
	}

	// Called number
	for _, fname := range []string{"cap.calledPartyNumber", "cap.called_party_number", "cap.destinationSubscriberNumber"} {
		if v := wireshark.FieldValue(layer, fname); v != "" {
			info.CalledNum = v
			break
		}
	}

	// Calling number
	for _, fname := range []string{"cap.callingPartyNumber", "cap.calling_party_number", "cap.callingPartysCategory"} {
		if v := wireshark.FieldValue(layer, fname); v != "" {
			info.CallingNum = v
			break
		}
	}

	// Event type (for EventReportBCSM etc.)
	for _, fname := range []string{"cap.eventTypeBCSM", "cap.event_type", "cap.eventTypeGPRS"} {
		if v := wireshark.FieldValue(layer, fname); v != "" {
			info.EventType = mapEventType(v)
			break
		}
	}

	pkt.CAP = info
}

func mapEventType(v string) string {
	switch strings.ToLower(v) {
	case "0", "originationattemptauthorized":
		return "OriginationAttemptAuthorized"
	case "1", "collectedinfo":
		return "CollectedInfo"
	case "2", "analyzedinformation":
		return "AnalyzedInformation"
	case "3", "routeselectfailure":
		return "RouteSelectFailure"
	case "4", "oCalledpartybusy", "ocalledpartybusy":
		return "OCalledPartyBusy"
	case "5", "onoanswer":
		return "ONoAnswer"
	case "6", "oanswer":
		return "OAnswer"
	case "7", "omidcall":
		return "OMidCall"
	case "8", "odisconnect":
		return "ODisconnect"
	case "9", "oabandon":
		return "OAbandon"
	case "12", "tbusy":
		return "TBusy"
	case "13", "tnoanswer":
		return "TNoAnswer"
	case "14", "tanswer":
		return "TAnswer"
	case "15", "tmidcall":
		return "TMidCall"
	case "16", "tdisconnect":
		return "TDisconnect"
	case "17", "tabandon":
		return "TAbandon"
	default:
		return v
	}
}
