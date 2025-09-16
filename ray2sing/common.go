package ray2sing

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	badoption "github.com/sagernet/sing/common/json/badoption"
)

type ParserFunc func(string) (*option.Outbound, error)

func getTLSOptions(decoded map[string]string) T.OutboundTLSOptionsContainer {
	if !(decoded["tls"] == "tls" || decoded["security"] == "tls" || decoded["security"] == "reality") {
		return T.OutboundTLSOptionsContainer{TLS: nil}
	}

	serverName := decoded["sni"]
	if serverName == "" {
		serverName = decoded["add"]
	}

	var ECHOpts *option.OutboundECHOptions
	valECH, hasECH := decoded["ech"]
	if hasECH && (valECH != "0") {
		ECHOpts = &option.OutboundECHOptions{
			Enabled: true,
		}
	}

	fp := decoded["fp"]
	if fp == "" {
		fp = "chrome"
	}
	insecure, err := getOneOf(decoded, "insecure", "allowinsecure")
	if err != nil {
		insecure = "false"
	}
	tlsOptions := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   insecure == "true" || insecure == "1",
		DisableSNI: serverName == "",
		ECH:        ECHOpts,
	}
	if decoded["fragment"] != "" || decoded["fgsize"] != "" {
		tlsOptions.Fragment = true
	}
	if fp != "" && !tlsOptions.DisableSNI {
		tlsOptions.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: fp,
		}
	}

	if alpn, ok := decoded["alpn"]; ok && alpn != "" {
		if net, _ := getOneOf(decoded, "type", "net"); net == "httpupgrade" || net == "ws" || net == "grpc" || net == "h2" {
			// tlsOptions.ALPN = []string{"http/1.1"}
		} else {
			tlsOptions.ALPN = strings.Split(alpn, ",")
		}

	}
	return T.OutboundTLSOptionsContainer{
		TLS: tlsOptions,
	}

}

func getMuxOptions(decoded map[string]string) *option.OutboundMultiplexOptions {
	mux := option.OutboundMultiplexOptions{}
	mux.Protocol = decoded["muxtype"]
	if mux.Protocol == "" {
		return nil
	}
	mux.Enabled = true
	mux.MaxConnections = toInt(decoded["muxmaxc"])
	// mux.MinStreams = toInt(decoded["muxsmin"])
	mux.MaxStreams = toInt(decoded["muxsmax"])
	mux.MinStreams = toInt(decoded["mux"])
	mux.Padding = decoded["muxpad"] == "true"

	if decoded["muxup"] != "" && decoded["muxdown"] != "" {
		mux.Brutal = &option.BrutalOptions{
			Enabled:  true,
			UpMbps:   toInt(decoded["muxup"]),
			DownMbps: toInt(decoded["muxdown"]),
		}
	}
	return &mux
}
func getTransportOptions(decoded map[string]string) (*option.V2RayTransportOptions, error) {
	var transportOptions option.V2RayTransportOptions
	host, net, path := decoded["host"], decoded["net"], decoded["path"]
	if net == "" {
		net = decoded["type"]
	}
	if path == "" {
		path = decoded["servicename"]
	}
	// fmoption.Printf("\n\nheaderType:%s, net:%s, type:%s\n\n", decoded["headerType"], net, decoded["type"])
	if (decoded["type"] == "http" || decoded["headertype"] == "http") && net == "tcp" {
		net = "http"
	}

	switch net {
	case "tcp":
		return nil, nil
	case "http":
		transportOptions.Type = C.V2RayTransportTypeHTTP
		if decoded["security"] != "tls" {
			transportOptions.HTTPOptions.Method = "GET"
		}
		if host != "" {
			transportOptions.HTTPOptions.Host = badoption.Listable[string]{host}
		}
		httpPath := path
		if httpPath == "" {
			httpPath = "/"
		}
		transportOptions.HTTPOptions.Path = httpPath
	case "httpupgrade":
		decoded["alpn"] = "http/1.1"
		transportOptions.Type = C.V2RayTransportTypeHTTPUpgrade
		if host != "" {
			transportOptions.HTTPUpgradeOptions.Headers = map[string]badoption.Listable[string]{"Host": {host}}
		}
		if path != "" {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			pathURL, err := url.Parse(path)
			if err != nil {
				return &option.V2RayTransportOptions{}, err
			}
			// pathQuery := pathURL.Query()
			// transportOptions.HTTPUpgradeOptions.MaxEarlyData = 0
			// transportOptions.HTTPUpgradeOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
			// maxEarlyDataString := pathQuery.Get("ed")
			// if maxEarlyDataString != "" {
			// 	maxEarlyDate, err := strconv.ParseUint(maxEarlyDataString, 10, 32)
			// 	if err == nil {
			// 		// transportOptions.HTTPUpgradeOptions.MaxEarlyData = uint32(maxEarlyDate)
			// 		pathQuery.Del("ed")
			// 		pathURL.RawQuery = pathQuery.Encode()
			// 	}
			// }
			transportOptions.HTTPUpgradeOptions.Path = pathURL.String()
		}
	case "ws":
		decoded["alpn"] = "http/1.1"

		transportOptions.Type = C.V2RayTransportTypeWebsocket
		if host != "" {
			transportOptions.WebsocketOptions.Headers = map[string]badoption.Listable[string]{"Host": {host}}
		}
		if path != "" {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			pathURL, err := url.Parse(path)
			if err != nil {
				return &option.V2RayTransportOptions{}, err
			}
			pathQuery := pathURL.Query()
			transportOptions.WebsocketOptions.MaxEarlyData = 0
			transportOptions.WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
			maxEarlyDataString := pathQuery.Get("ed")
			if maxEarlyDataString != "" {
				maxEarlyDate, err := strconv.ParseUint(maxEarlyDataString, 10, 32)
				if err == nil {
					transportOptions.WebsocketOptions.MaxEarlyData = uint32(maxEarlyDate)
					pathQuery.Del("ed")
					pathURL.RawQuery = pathQuery.Encode()
				}
			}
			transportOptions.WebsocketOptions.Path = pathURL.String()
		}
	case "grpc":
		decoded["alpn"] = "h2"
		transportOptions.Type = C.V2RayTransportTypeGRPC
		transportOptions.GRPCOptions = option.V2RayGRPCOptions{
			ServiceName:         path,
			IdleTimeout:         badoption.Duration(15 * time.Second),
			PingTimeout:         badoption.Duration(15 * time.Second),
			PermitWithoutStream: false,
		}
	case "quic":
		decoded["alpn"] = "h3"
		transportOptions.Type = C.V2RayTransportTypeQUIC
	default:
		return nil, E.New("unknown transport type: " + net)
	}

	return &transportOptions, nil
}
func getDialerOptions(decoded map[string]string) option.DialerOptions {
	return T.DialerOptions{}
}

func decodeBase64IfNeeded(b64string string) (string, error) {
	padding := len(b64string) % 4
	b64stringFix := b64string
	if padding != 0 {
		b64stringFix += string("===="[:4-padding])
	}
	decodedBytes, err := base64.StdEncoding.DecodeString(b64stringFix)
	if err != nil {
		return b64string, err
	}

	return string(decodedBytes), nil
}

func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func toInt16(s string, defaultPort uint16) uint16 {
	val, err := strconv.ParseInt(s, 10, 17)
	if err != nil {
		// fmoption.Printf("err %v", err)
		// handle the error appropriately; here we return 0
		return defaultPort
	}
	return uint16(val)
}

func isIPOnly(s string) bool {
	return net.ParseIP(s) != nil
}

func getOneOf(dic map[string]string, headers ...string) (string, error) {
	for _, h := range headers {
		if str, ok := dic[h]; ok {
			return str, nil
		}
	}
	return "", fmt.Errorf("not found")
}

func newOutbound(typ, tag string, options any) *option.Outbound {
	return &option.Outbound{
		Type:    typ,
		Tag:     tag,
		Options: options,
	}
}
