//go:build !darwin || no_vz

package vz

import (
	"context"
	"errors"

	"github.com/lima-vm/lima/pkg/driver"
)

var ErrUnsupported = errors.New("vm driver 'vz' needs macOS 13 or later (Hint: try recompiling Lima if you are seeing this error on macOS 13)")

const Enabled = false

type LimaVzDriver struct {
	*driver.BaseDriver
}

func New(driver *driver.BaseDriver) *LimaVzDriver {
	return &LimaVzDriver{
		BaseDriver: driver,
	}
}

func (l *LimaVzDriver) Validate() error {
	return ErrUnsupported
}

func (l *LimaVzDriver) CreateDisk(_ context.Context) error {
	return ErrUnsupported
}

func (l *LimaVzDriver) Start(_ context.Context) (chan error, error) {
	return nil, ErrUnsupported
}

func (l *LimaVzDriver) Stop(_ context.Context) error {
	return ErrUnsupported
}
