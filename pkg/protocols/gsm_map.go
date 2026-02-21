package protocols

import (
	"log-analyser/pkg/wireshark"
	"strings"
)

// GSM_MAP operation code names (ITU-T Q.773 / 3GPP TS 29.002)
var gsmMapOpNames = map[string]string{
	"2":  "UpdateLocation",
	"3":  "CancelLocation",
	"4":  "ProvideRoamingNumber",
	"6":  "InsertSubscriberData",
	"7":  "DeleteSubscriberData",
	"8":  "SendParameters",
	"9":  "RegisterSS",
	"10": "EraseSS",
	"11": "ActivateSS",
	"12": "DeactivateSS",
	"13": "InterrogateSS",
	"14": "AuthenticationFailureReport",
	"15": "RegisterPassword",
	"16": "GetPassword",
	"17": "ProcessUnstructuredSS-Request",
	"18": "Unstructured-SS-Request",
	"19": "Unstructured-SS-Notify",
	"20": "releaseResources",
	"21": "mt-ForwardSM",
	"22": "SendRoutingInfo",
	"23": "UpdateGprsLocation",
	"24": "SendRoutingInfoForGprs",
	"25": "FailureReport",
	"26": "NoteMsPresent",
	"29": "SendEndSignal",
	"30": "ProcessAccessRequest",
	"31": "ForwardCheckSS-Indication",
	"32": "PrepareHO",
	"33": "SendAuthenticationInfo",
	"34": "AuthenticationRequest",
	"35": "CheckIMEI",
	"37": "Reset",
	"38": "ForwardSM",
	"39": "RegisterImsi",
	"40": "mo-ForwardSM",
	"41": "ReportSM-DeliveryStatus",
	"43": "AlertServiceCentre",
	"44": "InformServiceCentre",
	"45": "ReadyForSM",
	"46": "PurgeMS",
	"47": "PrepareSubsequentHO",
	"48": "ProvideSubscriberInfo",
	"49": "AnyTimeInterrogation",
	"50": "ss-InvocationNotification",
	"51": "SetReportingState",
	"52": "StatusReport",
	"53": "RemoteUserFree",
	"54": "SubscriberEnquiry",
	"55": "AnyTimeSubscriptionInterrogation",
	"56": "TracSubscriberActivity",
	"57": "AnyTimeModification",
	"58": "DeactivateTraceMode",
	"59": "ActivateTraceMode",
	"60": "SendIMSI",
	"61": "Unstructured-SS-Data",
	"62": "SendRoutingInfoForLCS",
	"63": "SubscriberLocationReport",
	"64": "IstAlert",
	"65": "IstCommand",
	"66": "NoteMM-Event",
	"67": "UpdateVcsgLocation",
	"68": "CancelVcsgLocation",
	"70": "ProvideSubscriberLocation",
	"71": "SendGroupCallEndSignal",
	"72": "ProcessGroupCallSignalling",
	"73": "ForwardGroupCallSignalling",
	"74": "CheckIMEI",
	"75": "mt-ForwardSM-VGCS",
	"76": "ProvideSubscriberLocation",
	"77": "SendRoutingInfoForSM",
	"78": "ActivateTraceMode",
	"79": "DeactivateTraceMode",
	"80": "SendIdentification",
	"81": "RestoreData",
	"82": "SendAuthenticationInfo",
	"83": "InsertSubscriberData",
	"84": "DeleteSubscriberData",
	"85": "UpdateLocation",
	"86": "CancelLocation",
	"87": "PurgeMS",
	"88": "PrepareHO",
	"89": "PrepareSubsequentHO",
	"90": "ProcessAccessRequest",
	"91": "ForwardAccessSignalling",
	"93": "ForwardCheckSS-Indication",
	"94": "UpdateGPRSLocation",
	"95": "SendRoutingInfoForGPRS",
	"96": "FailureReport",
	"97": "NoteMSPresentForGPRS",
	"98": "PerformHandover",
}

// DissectGSMMAP extracts GSM_MAP information from a parsed Wireshark packet.
func DissectGSMMAP(pkt *wireshark.Packet) {
	layer, ok := pkt.Layers["gsm_map"]
	if !ok {
		return
	}

	info := &wireshark.GSMMAPInfo{}

	// Component type
	for _, fname := range []string{"gsm_map.component_type", "gsm_map.comp_type"} {
		if v := wireshark.FieldValue(layer, fname); v != "" {
			switch strings.ToLower(v) {
			case "invoke", "1":
				info.Component = "Invoke"
			case "returnresultlast", "returnresult", "2":
				info.Component = "ReturnResult"
			case "returnerror", "3":
				info.Component = "ReturnError"
			case "reject", "4":
				info.Component = "Reject"
			default:
				info.Component = v
			}
			break
		}
	}

	// Invoke ID
	for _, fname := range []string{"gsm_map.invokeID", "gsm_map.invoke_id"} {
		if v := wireshark.FieldValue(layer, fname); v != "" {
			info.InvokeID = v
			break
		}
	}

	// Operation code
	for _, fname := range []string{"gsm_map.opr_code", "gsm_map.localValue", "gsm_map.opCode", "gsm_map.operationCode"} {
		if v := wireshark.FieldValue(layer, fname); v != "" {
			info.OpCode = v
			if name, found := gsmMapOpNames[v]; found {
				info.OpName = name
			}
			break
		}
	}

	// IMSI
	for _, fname := range []string{"gsm_map.imsi", "e212.imsi", "gsm_map.lmsi"} {
		if v := wireshark.FieldValue(layer, fname); v != "" {
			info.IMSI = v
			break
		}
	}

	// MSISDN
	for _, fname := range []string{"gsm_map.msisdn_digits", "gsm_map.msisdn", "gsm_map.isdn_addressString.address"} {
		if v := wireshark.FieldValue(layer, fname); v != "" {
			info.MSISDN = v
			break
		}
	}

	// GT addresses (SCCP layer)
	if sccp, ok := pkt.Layers["sccp"]; ok {
		for _, f := range sccp.Fields {
			if strings.Contains(f.Name, "called") && strings.Contains(f.Name, "gt_") {
				info.CalledGT = f.ShowValue
			}
			if strings.Contains(f.Name, "calling") && strings.Contains(f.Name, "gt_") {
				info.CallingGT = f.ShowValue
			}
		}
	}

	// Error code (for ReturnError)
	for _, fname := range []string{"gsm_map.error_Code", "gsm_map.errorCode"} {
		if v := wireshark.FieldValue(layer, fname); v != "" {
			info.ErrorCode = v
			break
		}
	}

	pkt.GSMMAP = info
}

// GSMMapOpName returns the human-readable name for a GSM_MAP op code string.
func GSMMapOpName(code string) string {
	if name, ok := gsmMapOpNames[code]; ok {
		return name
	}
	return code
}
