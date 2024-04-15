package runconfig // import "github.com/docker/docker/runconfig"

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/pkg/sysinfo"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

type f struct {
	file       string
	entrypoint strslice.StrSlice
}

func TestDecodeContainerConfig(t *testing.T) {
	var (
		fixtures []f
		imgName  string
	)

	// FIXME (thaJeztah): update fixtures for more current versions.
	if runtime.GOOS != "windows" {
		imgName = "ubuntu"
		fixtures = []f{
			{"fixtures/unix/container_config_1_19.json", strslice.StrSlice{"bash"}},
		}
	} else {
		imgName = "windows"
		fixtures = []f{
			{"fixtures/windows/container_config_1_19.json", strslice.StrSlice{"cmd"}},
		}
	}

	for _, f := range fixtures {
		f := f
		t.Run(f.file, func(t *testing.T) {
			b, err := os.ReadFile(f.file)
			if err != nil {
				t.Fatal(err)
			}

			c, h, _, err := decodeContainerConfig(bytes.NewReader(b), sysinfo.New())
			if err != nil {
				t.Fatal(err)
			}

			if c.Image != imgName {
				t.Fatalf("Expected %s image, found %s", imgName, c.Image)
			}

			if len(c.Entrypoint) != len(f.entrypoint) {
				t.Fatalf("Expected %v, found %v", f.entrypoint, c.Entrypoint)
			}

			if h != nil && h.Memory != 1000 {
				t.Fatalf("Expected memory to be 1000, found %d", h.Memory)
			}
		})
	}
}

// TestDecodeContainerConfigIsolation validates isolation passed
// to the daemon in the hostConfig structure. Note this is platform specific
// as to what level of container isolation is supported.
func TestDecodeContainerConfigIsolation(t *testing.T) {
	isolation := func(v string) ContainerConfigWrapper {
		return ContainerConfigWrapper{
			Config: &container.Config{},
			HostConfig: &container.HostConfig{
				NetworkMode: "none",
				Isolation:   container.Isolation(v),
			},
		}
	}

	// An Invalid isolation level
	assert.Check(t, is.ErrorContains(callDecodeContainerConfig(t, isolation("invalid")), `Invalid isolation: "invalid"`))
	// Blank isolation (== default)
	assert.Check(t, is.Nil(callDecodeContainerConfig(t, isolation(""))))
	// Default isolation
	assert.Check(t, is.Nil(callDecodeContainerConfig(t, isolation("default"))))

	if runtime.GOOS == "windows" {
		// Process isolation (Valid on Windows only)
		assert.Check(t, is.Nil(callDecodeContainerConfig(t, isolation("process"))))
		// Hyper-V Containers isolation (Valid on Windows only)
		assert.Check(t, is.Nil(callDecodeContainerConfig(t, isolation("hyperv"))))
	} else {
		assert.Check(t, is.ErrorContains(callDecodeContainerConfig(t, isolation("process")), `Invalid isolation: "process"`))
		assert.Check(t, is.ErrorContains(callDecodeContainerConfig(t, isolation("hyperv")), `Invalid isolation: "hyperv"`))
	}
}

// callDecodeContainerConfig is a utility function that marshals a
// ContainerConfigWrapper and pass it to decodeContainerConfig. It returns any
// error if the decode process failed.
func callDecodeContainerConfig(t *testing.T, w ContainerConfigWrapper) error {
	b, err := json.Marshal(w)
	assert.NilError(t, err)

	_, _, _, err = decodeContainerConfig(bytes.NewReader(b), sysinfo.New())
	return err
}
