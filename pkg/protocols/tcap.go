package protocols

import (
	"log-analyser/pkg/wireshark"
	"strings"
)

// tcapMsgTypes maps raw numeric/string Wireshark values to human-readable names
var tcapMsgTypes = map[string]string{
	"1":        "Unidirectional",
	"2":        "Begin",
	"4":        "End",
	"5":        "Continue",
	"7":        "Abort",
	"begin":    "Begin",
	"continue": "Continue",
	"end":      "End",
	"abort":    "Abort",
}

var tcapComponentTypes = map[string]string{
	"1":            "Invoke",
	"2":            "ReturnResult",
	"3":            "ReturnError",
	"4":            "Reject",
	"invoke":       "Invoke",
	"returnResult": "ReturnResult",
	"returnError":  "ReturnError",
	"reject":       "Reject",
}

// DissectTCAP extracts TCAP information from a parsed Wireshark packet.
func DissectTCAP(pkt *wireshark.Packet) {
	layer, ok := pkt.Layers["tcap"]
	if !ok {
		return
	}

	info := &wireshark.TCAPInfo{}

	// Message type – try multiple field names Wireshark versions use
	for _, fname := range []string{"tcap.MessageType", "tcap.message_type", "MessageType"} {
		v := wireshark.FieldValue(layer, fname)
		if v == "" {
			continue
		}
		lv := strings.ToLower(v)
		if human, ok := tcapMsgTypes[lv]; ok {
			info.MessageType = human
		} else if human, ok := tcapMsgTypes[v]; ok {
			info.MessageType = human
		} else {
			info.MessageType = v
		}
		break
	}

	// Transaction IDs
	for _, fname := range []string{"tcap.otid", "otid", "tcap.source_transaction_id"} {
		if v := wireshark.FieldValue(layer, fname); v != "" {
			info.OTID = v
			break
		}
	}
	for _, fname := range []string{"tcap.dtid", "dtid", "tcap.destination_transaction_id"} {
		if v := wireshark.FieldValue(layer, fname); v != "" {
			info.DTID = v
			break
		}
	}

	// Application context
	for _, fname := range []string{"tcap.oid", "tcap.application_context", "application_context_name"} {
		if v := wireshark.FieldValue(layer, fname); v != "" {
			info.AppContext = v
			break
		}
	}

	// Components
	for _, f := range layer.Fields {
		if strings.Contains(strings.ToLower(f.Name), "component") {
			comp := wireshark.TCAPComponent{}
			for _, child := range f.Children {
				switch {
				case strings.Contains(child.Name, "invoke_id") || strings.Contains(child.Name, "invokeId"):
					comp.InvokeID = child.ShowValue
				case strings.Contains(child.Name, "opCode") || strings.Contains(child.Name, "op_code"):
					comp.OpCode = child.ShowValue
				case strings.Contains(child.Name, "componentType") || strings.Contains(child.Name, "component_type"):
					ct := strings.ToLower(child.ShowValue)
					if human, ok := tcapComponentTypes[ct]; ok {
						comp.Type = human
					} else {
						comp.Type = child.ShowValue
					}
				}
			}
			info.Components = append(info.Components, comp)
		}
	}

	pkt.TCAP = info
}
