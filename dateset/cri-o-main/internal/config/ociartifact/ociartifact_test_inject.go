//go:build test
// +build test

// All *_inject.go files are meant to be used by tests only. Purpose of this
// files is to provide a way to inject mocked data into the current setup.

package ociartifact

// SetOCIArtifactImpl sets the OCI artifact implementation.
func (o *OCIArtifact) SetImpl(impl Impl) {
	o.impl = impl
}
