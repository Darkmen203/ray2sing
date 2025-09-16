package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"

	"strings"
)

func SSHSingbox(sshURL string) (*T.Outbound, error) {
	u, err := ParseUrl(sshURL, 22)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	prefix := "-----BEGIN OPENSSH PRIVATE KEY-----\n"
	suffix := "\n-----END OPENSSH PRIVATE KEY-----\n"

	privkeys := strings.Split(decoded["pk"], ",")
	if len(privkeys) == 1 && privkeys[0] == "" {
		privkeys = []string{}
	}
	for i := 0; i < len(privkeys); i++ {
		privkeys[i] = prefix + privkeys[i] + suffix
	}

	hostkeys := strings.Split(decoded["hk"], ",")

	opts := &T.SSHOutboundOptions{
		ServerOptions: u.GetServerOption(),
		User:          u.Username,
		Password:      u.Password,
		PrivateKey:    privkeys,
		HostKey:       hostkeys,
	}
	return newOutbound(C.TypeSSH, u.Name, opts), nil
}
