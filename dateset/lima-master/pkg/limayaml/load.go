package limayaml

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
	"github.com/lima-vm/lima/pkg/store/dirnames"
	"github.com/lima-vm/lima/pkg/store/filenames"
	"github.com/sirupsen/logrus"
	yamlv3 "gopkg.in/yaml.v3"
)

func unmarshalDisk(dst *Disk, b []byte) error {
	var s string
	if err := yaml.Unmarshal(b, &s); err == nil {
		*dst = Disk{Name: s}
		return nil
	}
	return yaml.Unmarshal(b, dst)
}

func (d *Disk) UnmarshalYAML(value *yamlv3.Node) error {
	var v interface{}
	if err := value.Decode(&v); err != nil {
		return err
	}
	if s, ok := v.(string); ok {
		*d = Disk{Name: s}
	}
	return nil
}

func unmarshalYAML(data []byte, v interface{}, comment string) error {
	if err := yaml.UnmarshalWithOptions(data, v, yaml.DisallowDuplicateKey(), yaml.CustomUnmarshaler[Disk](unmarshalDisk)); err != nil {
		return fmt.Errorf("failed to unmarshal YAML (%s): %w", comment, err)
	}
	// the go-yaml library doesn't catch all markup errors, unfortunately
	// make sure to get a "second opinion", using the same library as "yq"
	if err := yamlv3.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to unmarshal YAML (%s): %w", comment, err)
	}
	if err := yaml.UnmarshalWithOptions(data, v, yaml.Strict(), yaml.CustomUnmarshaler[Disk](unmarshalDisk)); err != nil {
		logrus.WithField("comment", comment).WithError(err).Warn("Non-strict YAML is deprecated and will be unsupported in a future version of Lima")
		// Non-strict YAML is known to be used by Rancher Desktop:
		// https://github.com/rancher-sandbox/rancher-desktop/blob/c7ea7508a0191634adf16f4675f64c73198e8d37/src/backend/lima.ts#L114-L117
	}
	return nil
}

// Load loads the yaml and fulfills unspecified fields with the default values.
//
// Load does not validate. Use Validate for validation.
func Load(b []byte, filePath string) (*LimaYAML, error) {
	var y, d, o LimaYAML

	if err := unmarshalYAML(b, &y, fmt.Sprintf("main file %q", filePath)); err != nil {
		return nil, err
	}
	configDir, err := dirnames.LimaConfigDir()
	if err != nil {
		return nil, err
	}

	defaultPath := filepath.Join(configDir, filenames.Default)
	bytes, err := os.ReadFile(defaultPath)
	if err == nil {
		logrus.Debugf("Mixing %q into %q", defaultPath, filePath)
		if err := unmarshalYAML(bytes, &d, fmt.Sprintf("default file %q", defaultPath)); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	overridePath := filepath.Join(configDir, filenames.Override)
	bytes, err = os.ReadFile(overridePath)
	if err == nil {
		logrus.Debugf("Mixing %q into %q", overridePath, filePath)
		if err := unmarshalYAML(bytes, &o, fmt.Sprintf("override file %q", overridePath)); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	FillDefault(&y, &d, &o, filePath)
	return &y, nil
}
