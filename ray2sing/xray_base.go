package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func removeEmptyNullRecursive(detour map[string]any) map[string]any {
	for key, value := range detour {
		if value == nil || value == "" {
			delete(detour, key)
		} else if nestedMap, ok := value.(map[string]any); ok {
			detour[key] = removeEmptyNullRecursive(nestedMap)
		}
	}
	return detour
}

func makeXrayOptions(decoded map[string]string, detour map[string]any) (*T.Outbound, error) {
	tag, _ := detour["tag"].(string)
	detour = removeEmptyNullRecursive(detour)

	xrayConfig := detour
	fragment := getXrayFragmentOptions(decoded)
	if fragment != nil {
		streamSettings, ok := detour["streamSettings"].(map[string]any)
		if !ok {
			streamSettings = make(map[string]any)
		}
		socketOpt, ok := streamSettings["sockopt"].(map[string]any)
		if !ok {
			socketOpt = make(map[string]any)
		}
		socketOpt["dialerProxy"] = "xray_internal_fragment"
		streamSettings["sockopt"] = socketOpt
		detour["streamSettings"] = streamSettings

		xrayConfig = map[string]any{
			"outbounds": []any{
				detour,
				map[string]any{
					"tag":      "xray_internal_fragment",
					"protocol": "freedom",
					"settings": map[string]any{
						"domainStrategy": "ForceIP",
					},
					"streamSettings": map[string]any{
						"sockopt": map[string]any{
							"tcpNoDelay": true,
						},
					},
				},
			},
		}
	}

	opts := map[string]any{
		"xray_outbound_raw": xrayConfig,
	}
	if fragment != nil {
		opts["xray_fragment"] = fragment
	}

	return newOutbound("xray", tag, opts), nil
}
