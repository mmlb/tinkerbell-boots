package osie

import (
	"net/url"
	"os"

	"github.com/pkg/errors"
	"github.com/tinkerbell/boots/conf"
	"github.com/tinkerbell/boots/installers"
)

const (
	defaultOSIEPath = "/misc/osie"
)

var (
	osieURL          = mustBuildOSIEURL().String()
	mirrorBaseURL    = conf.MirrorBaseUrl
	dockerRegistry   string
	grpcAuthority    string
	registryUsername string
	registryPassword string
	tinkerbellTLS    string
)

func buildOSIEURL() (*url.URL, error) {
	base, err := url.Parse(conf.MirrorBaseUrl)
	if err != nil {
		return nil, errors.Wrap(err, "parsing MirrorBaseUrl")
	}
	if s, ok := os.LookupEnv("OSIE_PATH"); ok {
		u, err := base.Parse(s)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid OSIE_PATH: %s", s)
		}

		return u, nil
	}
	u, err := base.Parse(defaultOSIEPath)
	if err != nil {
		return nil, errors.Wrapf(err, "invalid default osie path: %s", defaultOSIEPath)
	}

	return u, nil
}

func mustBuildOSIEURL() *url.URL {
	u, err := buildOSIEURL()
	if err != nil {
		panic(err)
	}

	return u
}

func buildWorkerParams() {
	dockerRegistry = os.Getenv("DOCKER_REGISTRY")
	grpcAuthority = getParam("TINKERBELL_CERT_URL")
	registryPassword = os.Getenv("REGISTRY_PASSWORD")
	registryUsername = os.Getenv("REGISTRY_USERNAME")
	tinkerbellTLS = os.Getenv("TINKERBELL_TLS")
}

func getParam(key string) string {
	value := os.Getenv(key)
	if value == "" {
		installers.Logger("osie").With("key", key).Fatal(errors.New("invalid key"))
	}

	return value
}
