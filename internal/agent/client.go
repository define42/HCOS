package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/define42/HCOS/internal/protocol"
)

const maxDesiredBody = 8 << 20

func (a *Agent) desired(ctx context.Context) (protocol.DesiredState, error) {
	var desired protocol.DesiredState
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint("desired"), nil)
	if err != nil {
		return desired, err
	}
	a.authorize(req)
	resp, err := a.client.Do(req)
	if err != nil {
		return desired, fmt.Errorf("fetch desired state: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return desired, fmt.Errorf("fetch desired state: HTTP %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, maxDesiredBody+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return desired, fmt.Errorf("read desired state: %w", err)
	}
	if len(data) > maxDesiredBody {
		return desired, errors.New("desired state exceeds 8 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&desired); err != nil {
		return desired, fmt.Errorf("decode desired state: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return desired, errors.New("desired state must contain one JSON object")
	}
	return desired, nil
}

func (a *Agent) report(ctx context.Context, report protocol.Report) error {
	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode node report: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint("report"), bytes.NewReader(data))
	if err != nil {
		return err
	}
	a.authorize(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("post node report: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("post node report: HTTP %d", resp.StatusCode)
	}
	return nil
}

func (a *Agent) endpoint(resource string) string {
	u := *a.controller
	u.Path = "/v1/nodes/" + a.config.NodeID + "/" + resource
	return u.String()
}

func (a *Agent) authorize(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+a.config.ControllerToken)
}
