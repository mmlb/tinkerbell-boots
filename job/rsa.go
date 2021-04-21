package job

// TODO(SWE-338): move to separate package

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"

	"github.com/packethost/pkg/log"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

var rsaKeypair struct {
	key *rsa.PrivateKey
	pub []byte
}

func initRSA(l log.Logger) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		err := errors.Wrap(err, "generate RSA key")
		l.Package("job").Fatal(err)
	}
	k.Precompute()

	pub, err := ssh.NewPublicKey(k.Public())
	if err != nil {
		err := errors.Wrap(err, "encode SSH public key")
		l.Package("job").Fatal(err)
	}

	rsaKeypair.key = k
	rsaKeypair.pub = ssh.MarshalAuthorizedKey(pub)
}

func decryptPassword(b []byte) (string, error) {
	pass, err := rsaKeypair.key.Decrypt(rand.Reader, b, nil)
	if err != nil {
		return "", errors.Wrap(err, "decrypt submitted password")
	}
	return string(pass), nil
}

func ServePublicKey(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET", "HEAD":
		w.WriteHeader(http.StatusOK)
		w.Write(rsaKeypair.pub)
		return
	default:
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
