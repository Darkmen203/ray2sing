package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func VmessXray(vmessURL string) (*T.Outbound, error) {
	decoded, err := decodeVmess(vmessURL)
	if err != nil {
		return nil, err
	}

	port := toInt16(decoded["port"], 443)

	streamSettings, err := getStreamSettingsXray(decoded)
	if err != nil {
		return nil, err
	}

	security := "auto"
	if decoded["scy"] != "" {
		security = decoded["scy"]
	}

	xrayConfig := map[string]any{
		"protocol": "vmess",
		"settings": map[string]any{
			"vnext": []any{
				map[string]any{
					"address": decoded["add"],
					"port":    port,
					"users": []any{
						map[string]any{
							"id":       decoded["id"],
							"security": security,
						},
					},
				},
			},
		},
		"tag":            decoded["ps"],
		"streamSettings": streamSettings,
		"mux":            getMuxOptionsXray(decoded),
	}

	opts := map[string]any{
		"xray_fragment":     getXrayFragmentOptions(decoded),
		"xray_outbound_raw": xrayConfig,
	}

	return newOutbound("xray", decoded["ps"], opts), nil
}
