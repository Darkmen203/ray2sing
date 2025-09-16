package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func TrojanXray(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params

	streamSettings, err := getStreamSettingsXray(decoded)
	if err != nil {
		return nil, err
	}

	xrayConfig := map[string]any{
		"protocol": "trojan",
		"settings": map[string]any{
			"servers": []any{
				map[string]any{
					"address":  u.Hostname,
					"port":     u.Port,
					"password": u.Username,
				},
			},
		},
		"tag":            u.Name,
		"streamSettings": streamSettings,
		"mux":            getMuxOptionsXray(decoded),
	}

	opts := map[string]any{
		"xray_fragment":     getXrayFragmentOptions(decoded),
		"xray_outbound_raw": xrayConfig,
	}

	return newOutbound("xray", u.Name, opts), nil
}
