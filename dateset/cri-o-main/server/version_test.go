package server_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The actual test suite
var _ = t.Describe("Version", func() {
	// Prepare the sut
	BeforeEach(func() {
		beforeEach()
		setupSUT()
	})
	AfterEach(afterEach)

	t.Describe("Version", func() {
		It("should succeed", func() {
			// Given
			// When
			response, err := sut.Version(context.Background(), nil)

			// Then
			Expect(err).ToNot(HaveOccurred())
			Expect(response).NotTo(BeNil())
			Expect(response.Version).NotTo(BeEmpty())
			Expect(response.RuntimeName).NotTo(BeEmpty())
			Expect(response.RuntimeName).NotTo(BeEmpty())
			Expect(response.RuntimeApiVersion).To(Equal("v1"))
		})
	})
})
