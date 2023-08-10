package multierror

import (
	"errors"
	"fmt"
	"testing"

	"gotest.tools/v3/assert"
)

func TestErrorJoin(t *testing.T) {
	err := Join(errors.New("foobar"), fmt.Errorf("invalid config:\n%w", Join(errors.New("foo"), errors.New("bar"))))
	assert.Equal(t, err.Error(), `* foobar
* invalid config:
	* foo
	* bar`)
}
