package ray2sing

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func decodeVmess(vmessConfig string) (map[string]string, error) {
	vmessData := vmessConfig[8:]
	decodedData, err := base64.StdEncoding.DecodeString(vmessData)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	err = json.Unmarshal(decodedData, &data)
	if err != nil {
		return nil, err
	}
	strdata := convertToStrings(data)
	return strdata, nil
}

func convertToStrings(data map[string]interface{}) map[string]string {
	stringMap := make(map[string]string)
	for key, value := range data {
		switch v := value.(type) {
		case string:
			stringMap[key] = v
		case float64:
			stringMap[key] = strconv.Itoa(int(v))
		default:
			stringMap[key] = fmt.Sprintf("%v", v)
		}
	}
	return stringMap
}

func VmessSingbox(vmessURL string) (*T.Outbound, error) {
	decoded, err := decodeVmess(vmessURL)
	if err != nil {
		return nil, err
	}

	port := toInt16(decoded["port"], 443)
	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return nil, err
	}
	security := "auto"
	if decoded["scy"] != "" {
		security = decoded["scy"]
	}
	packetEncoding := decoded["packetEncoding"]

	opts := &T.VMessOutboundOptions{
		DialerOptions: getDialerOptions(decoded),
		ServerOptions: T.ServerOptions{
			Server:     decoded["add"],
			ServerPort: port,
		},
		UUID:                        decoded["id"],
		Security:                    security,
		AlterId:                     toInt(decoded["aid"]),
		GlobalPadding:               false,
		AuthenticatedLength:         true,
		PacketEncoding:              packetEncoding,
		OutboundTLSOptionsContainer: getTLSOptions(decoded),
		Transport:                   transportOptions,
		Multiplex:                   getMuxOptions(decoded),
	}
	return newOutbound(C.TypeVMess, decoded["ps"], opts), nil
}
