package job

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"
)

// Component models a single hardware component
type Component struct {
	Type            string      `json:"type"`
	Name            string      `json:"name"`
	Vendor          string      `json:"vendor"`
	Model           string      `json:"model"`
	Serial          string      `json:"serial"`
	FirmwareVersion string      `json:"firmware_version"`
	Data            interface{} `json:"data"`
}

type ComponentsResponse struct {
	Components []Component `json:"components"`
}

// AddHardware - Add hardware component(s)
func (j Job) AddHardware(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	var response ComponentsResponse
	if err := json.NewDecoder(req.Body).Decode(&response); err != nil {
		j.Error(errors.Wrap(err, "parsing hardware component as json"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var buf = &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(response); err != nil {
		j.Error(errors.Wrap(err, "marshalling componenents as json"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if _, err := client.PostHardwareComponent(j.hardware.HardwareID(), buf); err != nil {
		j.With("error", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte{})
}
