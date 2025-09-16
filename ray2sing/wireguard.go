package ray2sing

import (
	"net/netip"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func WiregaurdSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}

	opts := &T.LegacyWireGuardOutboundOptions{
		ServerOptions: u.GetServerOption(),
	}

	if pk, err := getOneOf(u.Params, "privatekey", "pk"); err == nil {
		opts.PrivateKey = pk
	}

	if pub, err := getOneOf(u.Params, "peerpublickey", "publickey", "pub", "peerpub"); err == nil {
		opts.PeerPublicKey = pub
	}

	if psk, err := getOneOf(u.Params, "presharedkey", "psk"); err == nil {
		opts.PreSharedKey = psk
	}

	if workerStr, ok := u.Params["workers"]; ok {
		if workers, err := strconv.Atoi(workerStr); err == nil {
			opts.Workers = workers
		}
	}

	if mtuStr, ok := u.Params["mtu"]; ok {
		if mtu, err := strconv.ParseUint(mtuStr, 10, 32); err == nil {
			opts.MTU = uint32(mtu)
		}
	}

	if reservedStr, ok := u.Params["reserved"]; ok {
		for _, part := range strings.Split(reservedStr, ",") {
			num, err := strconv.ParseUint(part, 10, 8)
			if err != nil {
				return nil, err
			}
			opts.Reserved = append(opts.Reserved, uint8(num))
		}
	}

	if localAddress, err := getOneOf(u.Params, "localaddress", "ip"); err == nil {
		for _, part := range strings.Split(localAddress, ",") {
			if !strings.Contains(part, "/") {
				part += "/24"
			}
			prefix, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, err
			}
			opts.LocalAddress = append(opts.LocalAddress, prefix)
		}
	}

	return newOutbound(C.TypeWireGuard, u.Name, opts), nil
}
