package ironic

import (
	"testing"

	"github.com/stretchr/testify/assert"

	metal3api "github.com/metal3-io/baremetal-operator/apis/metal3.io/v1alpha1"
	"github.com/metal3-io/baremetal-operator/pkg/hardwareutils/bmc"
	"github.com/metal3-io/baremetal-operator/pkg/provisioner/ironic/clients"
	"github.com/metal3-io/baremetal-operator/pkg/provisioner/ironic/testserver"
)

func TestGetFirmwareSettings(t *testing.T) {
	nodeUUID := "158c5d59-9ace-9631-ed51-d842a45f1c52"
	iTrue := true
	iFalse := false
	minLength := 0
	maxLength := 16
	lowerBound := 0
	upperBound := 20

	cases := []struct {
		name                string
		expectedSettingsMap metal3api.SettingsMap
		expectedSchemaMap   map[string]metal3api.SettingSchema
		includeSchema       bool
		ironic              *testserver.IronicMock
		expectedError       string
	}{
		{
			name: "no-schema",
			expectedSettingsMap: metal3api.SettingsMap{
				"L2Cache":            "10x256 KB",
				"NumCores":           "10",
				"ProcVirtualization": "Enabled",
			},
			expectedSchemaMap: map[string]metal3api.SettingSchema{},
			ironic:            testserver.NewIronic(t).BIOSSettings(nodeUUID),
			includeSchema:     false,
			expectedError:     "",
		},
		{
			name: "include-schema",
			expectedSettingsMap: metal3api.SettingsMap{
				"L2Cache":            "10x256 KB",
				"NumCores":           "10",
				"ProcVirtualization": "Enabled",
			},
			expectedSchemaMap: map[string]metal3api.SettingSchema{
				"L2Cache": {
					AttributeType:   "String",
					AllowableValues: []string{},
					LowerBound:      nil,
					UpperBound:      nil,
					MinLength:       &minLength,
					MaxLength:       &maxLength,
					ReadOnly:        &iTrue,
					Unique:          nil,
				},
				"NumCores": {
					AttributeType:   "Integer",
					AllowableValues: []string{},
					LowerBound:      &lowerBound,
					UpperBound:      &upperBound,
					MinLength:       nil,
					MaxLength:       nil,
					ReadOnly:        &iTrue,
					Unique:          nil,
				},
				"ProcVirtualization": {
					AttributeType:   "Enumeration",
					AllowableValues: []string{"Enabled", "Disabled"},
					LowerBound:      nil,
					UpperBound:      nil,
					MinLength:       nil,
					MaxLength:       nil,
					ReadOnly:        &iFalse,
					Unique:          nil,
				},
			},
			ironic:        testserver.NewIronic(t).BIOSDetailSettings(nodeUUID),
			includeSchema: true,
			expectedError: "",
		},
		{
			name:                "error404",
			expectedSettingsMap: metal3api.SettingsMap(nil),
			expectedSchemaMap:   map[string]metal3api.SettingSchema(nil),
			ironic:              testserver.NewIronic(t).NoBIOS(nodeUUID),
			includeSchema:       false,
			expectedError:       "could not get node for BIOS settings: host not registered",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.ironic.Start()
			defer tc.ironic.Stop()

			host := makeHost()
			host.Name = "node-1"
			host.Status.Provisioning.ID = nodeUUID

			auth := clients.AuthConfig{Type: clients.NoAuth}

			prov, err := newProvisionerWithSettings(host, bmc.Credentials{}, nullEventPublisher, tc.ironic.Endpoint(), auth)
			if err != nil {
				t.Fatalf("could not create provisioner: %s", err)
			}

			settingsMap, schemaMap, err := prov.GetFirmwareSettings(tc.includeSchema)

			assert.Equal(t, tc.expectedSettingsMap, settingsMap)
			assert.Equal(t, tc.expectedSchemaMap, schemaMap)

			if tc.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Regexp(t, tc.expectedError, err.Error())
			}
		})
	}
}
