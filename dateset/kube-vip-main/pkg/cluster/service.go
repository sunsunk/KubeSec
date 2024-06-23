package cluster

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kube-vip/kube-vip/pkg/bgp"
	"github.com/kube-vip/kube-vip/pkg/equinixmetal"
	"github.com/kube-vip/kube-vip/pkg/kubevip"
	"github.com/kube-vip/kube-vip/pkg/loadbalancer"
	"github.com/kube-vip/kube-vip/pkg/vip"
	"github.com/packethost/packngo"
	log "github.com/sirupsen/logrus"
)

func (cluster *Cluster) vipService(ctxArp, ctxDNS context.Context, c *kubevip.Config, sm *Manager, bgpServer *bgp.Server, packetClient *packngo.Client) error {
	id, err := os.Hostname()
	if err != nil {
		return err
	}

	// listen for interrupts or the Linux SIGTERM signal and cancel
	// our context, which the leader election code will observe and
	// step down
	signalChan := make(chan os.Signal, 1)
	// Add Notification for Userland interrupt
	signal.Notify(signalChan, syscall.SIGINT)

	// Add Notification for SIGTERM (sent from Kubernetes)
	signal.Notify(signalChan, syscall.SIGTERM)

	for i := range cluster.Network {

		if cluster.Network[i].IsDDNS() {
			if err := cluster.StartDDNS(ctxDNS); err != nil {
				log.Error(err)
			}
		}

		// start the dns updater if address is dns
		if cluster.Network[i].IsDNS() {
			log.Infof("starting the DNS updater for the address %s", cluster.Network[i].DNSName())
			ipUpdater := vip.NewIPUpdater(cluster.Network[i])
			ipUpdater.Run(ctxDNS)
		}

		err = cluster.Network[i].AddIP()
		if err != nil {
			log.Fatalf("%v", err)
		}

		if c.EnableMetal {
			// We're not using Equinix Metal with BGP
			if !c.EnableBGP {
				// Attempt to attach the EIP in the standard manner
				log.Debugf("Attaching the Equinix Metal EIP through the API to this host")
				err = equinixmetal.AttachEIP(packetClient, c, id)
				if err != nil {
					log.Error(err)
				}
			}
		}

		if c.EnableBGP {
			// Lets advertise the VIP over BGP, the host needs to be passed using CIDR notation
			cidrVip := fmt.Sprintf("%s/%s", cluster.Network[i].IP(), c.VIPCIDR)
			log.Debugf("Attempting to advertise the address [%s] over BGP", cidrVip)

			err = bgpServer.AddHost(cidrVip)
			if err != nil {
				log.Error(err)
			}
		}

		if c.EnableLoadBalancer {

			log.Infof("Starting IPVS LoadBalancer")

			lb, err := loadbalancer.NewIPVSLB(cluster.Network[i].IP(), c.LoadBalancerPort, c.LoadBalancerForwardingMethod)
			if err != nil {
				log.Errorf("Error creating IPVS LoadBalancer [%s]", err)
			}

			go func() {
				err = sm.NodeWatcher(lb, c.Port)
				if err != nil {
					log.Errorf("Error watching node labels [%s]", err)
				}
			}()
			// Shutdown function that will wait on this signal, unless we call it ourselves
			go func() {
				<-signalChan
				err = lb.RemoveIPVSLB()
				if err != nil {
					log.Errorf("Error stopping IPVS LoadBalancer [%s]", err)
				}
				log.Info("Stopping IPVS LoadBalancer")
			}()
		}

		if c.EnableARP {
			// ctxArp, cancelArp = context.WithCancel(context.Background())

			go func(ctx context.Context) {
				ipString := cluster.Network[i].IP()
				isIPv6 := vip.IsIPv6(ipString)

				var ndp *vip.NdpResponder
				if isIPv6 {
					ndp, err = vip.NewNDPResponder(c.Interface)
					if err != nil {
						log.Fatalf("failed to create new NDP Responder")
					}
				}

				if ndp != nil {
					defer ndp.Close()
				}
				log.Infof("Gratuitous Arp broadcast will repeat every 3 seconds for [%s]", ipString)
				for {
					select {
					case <-ctx.Done(): // if cancel() execute
						return
					default:
						cluster.ensureIPAndSendGratuitous(c.Interface, ndp)
					}
					time.Sleep(3 * time.Second)
				}
			}(ctxArp)
		}

		if c.EnableRoutingTable {
			err = cluster.Network[i].AddRoute()
			if err != nil {
				log.Warnf("%v", err)
			}
		}
	}

	return nil
}

// StartLoadBalancerService will start a VIP instance and leave it for kube-proxy to handle
func (cluster *Cluster) StartLoadBalancerService(c *kubevip.Config, bgp *bgp.Server) {
	// use a Go context so we can tell the arp loop code when we
	// want to step down
	//nolint
	ctxArp, cancelArp := context.WithCancel(context.Background())

	cluster.stop = make(chan bool, 1)
	cluster.completed = make(chan bool, 1)

	for i := range cluster.Network {
		network := cluster.Network[i]

		err := network.DeleteIP()
		if err != nil {
			log.Warnf("Attempted to clean existing VIP => %v", err)
		}
		if c.EnableRoutingTable && (c.EnableLeaderElection || c.EnableServicesElection) {
			err = network.AddRoute()
			if err != nil {
				log.Warnf("%v", err)
			}
		} else if !c.EnableRoutingTable {
			err = network.AddIP()
			if err != nil {
				log.Warnf("%v", err)
			}
		}

		if c.EnableARP {
			// ctxArp, cancelArp = context.WithCancel(context.Background())

			ipString := network.IP()

			var ndp *vip.NdpResponder
			if vip.IsIPv6(ipString) {
				ndp, err = vip.NewNDPResponder(c.Interface)
				if err != nil {
					log.Fatalf("failed to create new NDP Responder")
				}
			}
			go func(ctx context.Context) {
				if ndp != nil {
					defer ndp.Close()
				}
				log.Debugf("(svcs) broadcasting ARP update for %s via %s, every %dms", ipString, c.Interface, c.ArpBroadcastRate)

				for {
					select {
					case <-ctx.Done(): // if cancel() execute
						log.Debugf("(svcs) ending ARP update for %s via %s, every %dms", ipString, c.Interface, c.ArpBroadcastRate)
						return
					default:
						cluster.ensureIPAndSendGratuitous(c.Interface, ndp)
					}
					if c.ArpBroadcastRate < 500 {
						log.Errorf("arp broadcast rate is [%d], this shouldn't be lower that 300ms (defaulting to 3000)", c.ArpBroadcastRate)
						c.ArpBroadcastRate = 3000
					}
					time.Sleep(time.Duration(c.ArpBroadcastRate) * time.Millisecond)
				}
			}(ctxArp)
		}

		if c.EnableBGP && (c.EnableLeaderElection || c.EnableServicesElection) {
			// Lets advertise the VIP over BGP, the host needs to be passed using CIDR notation
			cidrVip := fmt.Sprintf("%s/%s", network.IP(), c.VIPCIDR)
			log.Debugf("(svcs) attempting to advertise the address [%s] over BGP", cidrVip)
			err = bgp.AddHost(cidrVip)
			if err != nil {
				log.Error(err)
			}
		}
	}

	go func() {
		<-cluster.stop
		// Stop the Arp context if it is running
		cancelArp()

		if c.EnableRoutingTable && (c.EnableLeaderElection || c.EnableServicesElection) {
			for i := range cluster.Network {
				if err := cluster.Network[i].DeleteRoute(); err != nil {
					log.Warnf("%v", err)
				}
			}

			close(cluster.completed)
			return
		}

		log.Info("[LOADBALANCER] Stopping load balancers")

		for i := range cluster.Network {
			log.Infof("[VIP] Releasing the Virtual IP [%s]", cluster.Network[i].IP())
			if err := cluster.Network[i].DeleteIP(); err != nil {
				log.Warnf("%v", err)
			}
		}

		close(cluster.completed)
	}()
}

// ensureIPAndSendGratuitous - adds IP to the interface if missing, and send
// either a gratuitous ARP or gratuitous NDP. Re-adds the interface if it is IPv6
// and in a dadfailed state.
func (cluster *Cluster) ensureIPAndSendGratuitous(iface string, ndp *vip.NdpResponder) {
	for i := range cluster.Network {
		ipString := cluster.Network[i].IP()
		isIPv6 := vip.IsIPv6(ipString)
		// Check if IP is dadfailed
		if cluster.Network[i].IsDADFAIL() {
			log.Warnf("IP address is in dadfailed state, removing [%s] from interface [%s]", ipString, iface)
			err := cluster.Network[i].DeleteIP()
			if err != nil {
				log.Warnf("%v", err)
			}
		}

		// Ensure the address exists on the interface before attempting to ARP
		set, err := cluster.Network[i].IsSet()
		if err != nil {
			log.Warnf("%v", err)
		}
		if !set {
			log.Warnf("Re-applying the VIP configuration [%s] to the interface [%s]", ipString, iface)
			err = cluster.Network[i].AddIP()
			if err != nil {
				log.Warnf("%v", err)
			}
		}

		if isIPv6 {
			// Gratuitous NDP, will broadcast new MAC <-> IPv6 address
			err := ndp.SendGratuitous(ipString)
			if err != nil {
				log.Warnf("%v", err)
			}
		} else {
			// Gratuitous ARP, will broadcast to new MAC <-> IPv4 address
			err := vip.ARPSendGratuitous(ipString, iface)
			if err != nil {
				log.Warnf("%v", err)
			}
		}
	}

}
