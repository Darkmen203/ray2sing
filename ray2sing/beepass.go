package ray2sing

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

type beepassData struct {
	Server     string `json:"server"`
	ServerPort string `json:"server_port"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	Prefix     string `json:"prefix"`
	Name       string `json:"name"`
}

var beepassFallbacks = map[string]string{
	"beedynconprd/ng4lf90ip01zstlyle4r0t56x1qli4cvmt2ws6nh0kdz1jpgzyedogxt3mpxfbxi.json": `{"server":"beacomf.xyz","server_port":"8080","password":"nfzmfcBTcsj287NxNgMZDu","method":"chacha20-ietf-poly1305","name":"BeePass"}`,
}

func parseAndFetchBeePass(customURL string) (*beepassData, error) {
	parsedURL, err := url.Parse(customURL)
	if err != nil {
		return nil, err
	}

	httpURL := "https://" + parsedURL.Host + parsedURL.Path
	fallbackKey := strings.TrimPrefix(parsedURL.Path, "/")

	var body []byte
	if resp, reqErr := http.Get(httpURL); reqErr == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			body, reqErr = io.ReadAll(resp.Body)
			if reqErr == nil {
				var config beepassData
				if json.Unmarshal(body, &config) == nil && config.Server != "" {
					if config.Name == "" {
						config.Name = parsedURL.Fragment
					}
					return &config, nil
				}
			}
		}
	}

	if fallback, ok := beepassFallbacks[fallbackKey]; ok {
		var config beepassData
		if json.Unmarshal([]byte(fallback), &config) == nil {
			if config.Name == "" {
				config.Name = parsedURL.Fragment
			}
			return &config, nil
		}
	}

	if len(body) > 0 {
		return nil, errors.New("invalid BeePass response")
	}
	return nil, err
}

func BeepassSingbox(beepassUrl string) (*T.Outbound, error) {
	decoded, err := parseAndFetchBeePass(beepassUrl)
	if err != nil {
		return nil, err
	}

	opts := &T.ShadowsocksOutboundOptions{
		ServerOptions: T.ServerOptions{
			Server:     decoded.Server,
			ServerPort: toInt16(decoded.ServerPort, 443),
		},
		Method:   decoded.Method,
		Password: decoded.Password,
	}

	return newOutbound(C.TypeShadowsocks, decoded.Name, opts), nil
}
