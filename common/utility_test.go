package common_test

import (
	. "github.com/maximilien/bosh-softlayer-cpi/common"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Utility", func() {
	var (
		result bool
	)

	Context("#GetOSEnvVariable", func() {
		It("returns the default value if the environment variable is not set", func() {
			result = GetOSEnvVariable("VAR_NAME_NOT_SET", "theDefaultValue")
			Expect(result).To(Equal("theDefaultValue"))
		})
	})
})
