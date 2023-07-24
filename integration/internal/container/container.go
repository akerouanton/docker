package container

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gotest.tools/v3/assert"
)

// TestContainerConfig holds container configuration struct that
// are used in api calls.
type TestContainerConfig struct {
	Name             string
	Config           *container.Config
	HostConfig       *container.HostConfig
	NetworkingConfig *network.NetworkingConfig
	Platform         *ocispec.Platform
}

// create creates a container with the specified options
func create(ctx context.Context, t *testing.T, client client.APIClient, ops ...func(*TestContainerConfig)) (container.CreateResponse, error) {
	t.Helper()
	cmd := []string{"top"}
	if runtime.GOOS == "windows" {
		cmd = []string{"sleep", "240"}
	}
	config := &TestContainerConfig{
		Config: &container.Config{
			Image: "busybox",
			Cmd:   cmd,
		},
		HostConfig:       &container.HostConfig{},
		NetworkingConfig: &network.NetworkingConfig{},
	}

	for _, op := range ops {
		op(config)
	}

	return client.ContainerCreate(ctx, config.Config, config.HostConfig, config.NetworkingConfig, config.Platform, config.Name)
}

// Create creates a container with the specified options, asserting that there was no error
func Create(ctx context.Context, t *testing.T, client client.APIClient, ops ...func(*TestContainerConfig)) string {
	t.Helper()
	c, err := create(ctx, t, client, ops...)
	assert.NilError(t, err)

	return c.ID
}

// CreateExpectingErr creates a container, expecting an error with the specified message
func CreateExpectingErr(ctx context.Context, t *testing.T, client client.APIClient, errMsg string, ops ...func(*TestContainerConfig)) {
	_, err := create(ctx, t, client, ops...)
	assert.ErrorContains(t, err, errMsg)
}

// Run creates and start a container with the specified options
func Run(ctx context.Context, t *testing.T, client client.APIClient, ops ...func(*TestContainerConfig)) string {
	t.Helper()
	id := Create(ctx, t, client, ops...)

	err := client.ContainerStart(ctx, id, types.ContainerStartOptions{})
	assert.NilError(t, err)

	return id
}

func Inspect(ctx context.Context, t *testing.T, cli client.APIClient, cid string) types.ContainerJSON {
	t.Helper()

	c, err := cli.ContainerInspect(ctx, cid)
	assert.NilError(t, err)

	return c
}

type RunResult struct {
	ContainerID string
	ExitCode    int
	Stdout      *bytes.Buffer
	Stderr      *bytes.Buffer
}

func RunAttach(ctx context.Context, t *testing.T, client client.APIClient, ops ...func(config *TestContainerConfig)) RunResult {
	t.Helper()

	ops = append(ops, func(c *TestContainerConfig) {
		c.Config.AttachStdout = true
		c.Config.AttachStderr = true
	})
	id := Create(ctx, t, client, ops...)

	aresp, err := client.ContainerAttach(ctx, id, types.ContainerAttachOptions{
		Stream: true,
		Stdout: true,
		Stderr: true,
	})
	assert.NilError(t, err)
	defer aresp.Close()

	err = client.ContainerStart(ctx, id, types.ContainerStartOptions{})
	assert.NilError(t, err)

	s, err := demultiplexStreams(ctx, aresp.Reader)
	if !errors.Is(err, context.DeadlineExceeded) {
		assert.NilError(t, err)
	}

	// Inspect to get the exit code. A new context is used here to make sure that if the context passed as argument as
	// reached timeout during the demultiplexStream call, we still return a RunResult.
	resp, err := client.ContainerInspect(context.Background(), id)
	assert.NilError(t, err)

	return RunResult{ContainerID: id, ExitCode: resp.State.ExitCode, Stdout: s.stdout, Stderr: s.stderr}
}

type streams struct {
	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

func demultiplexStreams(ctx context.Context, src io.Reader) (streams, error) {
	s := streams{
		stdout: &bytes.Buffer{},
		stderr: &bytes.Buffer{},
	}
	outputDone := make(chan error, 1)

	go func() {
		_, err := stdcopy.StdCopy(s.stdout, s.stderr, src)
		outputDone <- err
	}()

	select {
	case err := <-outputDone:
		if err != nil {
			return s, err
		}
		break
	case <-ctx.Done():
		return s, ctx.Err()
	}

	return s, nil
}
