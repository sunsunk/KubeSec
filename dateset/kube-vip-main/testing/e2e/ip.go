//go:build e2e
// +build e2e

package e2e

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	kindconfigv1alpha4 "sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	"sigs.k8s.io/kind/pkg/cluster"
)

func EnsureKindNetwork() {
	By("checking if the Docker \"kind\" network exists")
	cmd := exec.Command("docker", "inspect", "kind")
	session, err := gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session).Should(gexec.Exit())
	if session.ExitCode() == 0 {
		return
	}

	By("Docker \"kind\" network was not found. Creating dummy Kind cluster to ensure creation")
	clusterConfig := kindconfigv1alpha4.Cluster{
		Networking: kindconfigv1alpha4.Networking{
			IPFamily: kindconfigv1alpha4.IPv6Family,
		},
	}

	provider := cluster.NewProvider(
		cluster.ProviderWithDocker(),
	)
	dummyClusterName := fmt.Sprintf("dummy-cluster-%d", time.Now().Unix())
	Expect(provider.Create(
		dummyClusterName,
		cluster.CreateWithV1Alpha4Config(&clusterConfig),
	)).To(Succeed())

	By("deleting dummy Kind cluster")
	Expect(provider.Delete(dummyClusterName, ""))

	By("checking if the Docker \"kind\" network was successfully created")
	cmd = exec.Command("docker", "inspect", "kind")
	session, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).NotTo(HaveOccurred())
	Eventually(session).Should(gexec.Exit(0))
}

func GenerateIPv6VIP() string {
	cidrs := getKindNetworkSubnetCIDRs()

	for _, cidr := range cidrs {
		ip, ipNet, parseErr := net.ParseCIDR(cidr)
		Expect(parseErr).NotTo(HaveOccurred())

		if ip.To4() == nil {
			lowerMask := binary.BigEndian.Uint64(ipNet.Mask[8:])
			lowerStart := binary.BigEndian.Uint64(ipNet.IP[8:])
			lowerEnd := (lowerStart & lowerMask) | (^lowerMask)

			chosenVIP := make([]byte, 16)
			// Copy upper half into chosenVIP
			copy(chosenVIP, ipNet.IP[0:8])
			// Copy lower half into chosenVIP
			binary.BigEndian.PutUint64(chosenVIP[8:], lowerEnd-5)
			return net.IP(chosenVIP).String()
		}
	}
	Fail("Could not find any IPv6 CIDRs in the Docker \"kind\" network")
	return ""
}

func GenerateIPv4VIP() string {
	cidrs := getKindNetworkSubnetCIDRs()

	for _, cidr := range cidrs {
		ip, ipNet, parseErr := net.ParseCIDR(cidr)
		Expect(parseErr).NotTo(HaveOccurred())

		if ip.To4() != nil {
			mask := binary.BigEndian.Uint32(ipNet.Mask)
			start := binary.BigEndian.Uint32(ipNet.IP)
			end := (start & mask) | (^mask)

			chosenVIP := make([]byte, 4)
			binary.BigEndian.PutUint32(chosenVIP, end-5)
			return net.IP(chosenVIP).String()
		}
	}
	Fail("Could not find any IPv4 CIDRs in the Docker \"kind\" network")
	return ""
}

func GenerateDualStackVIP() string {
	return GenerateIPv4VIP() + "," + GenerateIPv6VIP()
}

func getKindNetworkSubnetCIDRs() []string {
	cmd := exec.Command(
		"docker", "inspect", "kind",
		"--format", `{{ range $i, $a := .IPAM.Config }}{{ println .Subnet }}{{ end }}`,
	)
	cmdOut := new(bytes.Buffer)
	cmd.Stdout = cmdOut
	Expect(cmd.Run()).To(Succeed(), "The Docker \"kind\" network was not found.")
	reader := bufio.NewReader(cmdOut)

	cidrs := []string{}
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			Expect(readErr).NotTo(HaveOccurred(), "Error finding subnet CIDRs in the Docker \"kind\" network")
		}

		cidrs = append(cidrs, strings.TrimSpace(line))
		if readErr == io.EOF {
			break
		}
	}

	return cidrs
}
