// Copyright 2020-2023 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !skip_js_tests && !skip_js_cluster_tests_2
// +build !skip_js_tests,!skip_js_cluster_tests_2

package server

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestJetStreamClusterJSAPIImport(t *testing.T) {
	c := createJetStreamClusterWithTemplate(t, jsClusterImportsTempl, "C1", 3)
	defer c.shutdown()

	// Client based API - This will connect to the non-js account which imports JS.
	// Connect below does an AccountInfo call.
	s := c.randomNonLeader()
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	if _, err := js.AddStream(&nats.StreamConfig{Name: "TEST", Replicas: 2}); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Note if this was ephemeral we would need to setup export/import for that subject.
	sub, err := js.SubscribeSync("TEST", nats.Durable("dlc"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Make sure we can look up both.
	if _, err := js.StreamInfo("TEST"); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if _, err := sub.ConsumerInfo(); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Names list..
	var names []string
	for name := range js.StreamNames() {
		names = append(names, name)
	}
	if len(names) != 1 {
		t.Fatalf("Expected only 1 stream but got %d", len(names))
	}

	// Now send to stream.
	if _, err := js.Publish("TEST", []byte("OK")); err != nil {
		t.Fatalf("Unexpected publish error: %v", err)
	}

	sub, err = js.PullSubscribe("TEST", "tr")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	msgs := fetchMsgs(t, sub, 1, 5*time.Second)

	m := msgs[0]
	if m.Subject != "TEST" {
		t.Fatalf("Expected subject of %q, got %q", "TEST", m.Subject)
	}
	if m.Header != nil {
		t.Fatalf("Expected no header on the message, got: %v", m.Header)
	}
	meta, err := m.Metadata()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if meta.Sequence.Consumer != 1 || meta.Sequence.Stream != 1 || meta.NumDelivered != 1 || meta.NumPending != 0 {
		t.Fatalf("Bad meta: %+v", meta)
	}

	js.Publish("TEST", []byte("Second"))
	js.Publish("TEST", []byte("Third"))

	checkFor(t, time.Second, 15*time.Millisecond, func() error {
		ci, err := js.ConsumerInfo("TEST", "tr")
		if err != nil {
			return fmt.Errorf("Error getting consumer info: %v", err)
		}
		if ci.NumPending != 2 {
			return fmt.Errorf("NumPending still not 1: %v", ci.NumPending)
		}
		return nil
	})

	// Ack across accounts.
	m, err = nc.Request("$JS.API.CONSUMER.MSG.NEXT.TEST.tr", []byte("+NXT"), 2*time.Second)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	meta, err = m.Metadata()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if meta.Sequence.Consumer != 2 || meta.Sequence.Stream != 2 || meta.NumDelivered != 1 || meta.NumPending != 1 {
		t.Fatalf("Bad meta: %+v", meta)
	}

	// AckNext
	_, err = nc.Request(m.Reply, []byte("+NXT"), 2*time.Second)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestJetStreamClusterMultiRestartBug(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3", 3)
	defer c.shutdown()

	// Client based API
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo", "bar"},
		Replicas: 3,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Send in 10000 messages.
	msg, toSend := make([]byte, 4*1024), 10000
	crand.Read(msg)

	for i := 0; i < toSend; i++ {
		if _, err = js.Publish("foo", msg); err != nil {
			t.Fatalf("Unexpected publish error: %v", err)
		}
	}

	checkFor(t, 10*time.Second, 250*time.Millisecond, func() error {
		si, err := js.StreamInfo("TEST")
		if err != nil {
			return fmt.Errorf("Unexpected error: %v", err)
		}
		if si.State.Msgs != uint64(toSend) {
			return fmt.Errorf("Expected to have %d messages, got %d", toSend, si.State.Msgs)
		}
		return nil
	})

	// For this bug, we will stop and remove the complete state from one server.
	s := c.randomServer()
	opts := s.getOpts()
	s.Shutdown()
	removeDir(t, opts.StoreDir)

	// Then restart it.
	c.restartAll()
	c.waitOnAllCurrent()
	c.waitOnStreamLeader("$G", "TEST")

	s = c.serverByName(s.Name())
	c.waitOnStreamCurrent(s, "$G", "TEST")

	// Now restart them all..
	c.stopAll()
	c.restartAll()
	c.waitOnLeader()
	c.waitOnStreamLeader("$G", "TEST")

	// Create new client.
	nc, js = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	// Make sure the replicas are current.
	js2, err := nc.JetStream(nats.MaxWait(250 * time.Millisecond))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	checkFor(t, 20*time.Second, 250*time.Millisecond, func() error {
		si, _ := js2.StreamInfo("TEST")
		if si == nil || si.Cluster == nil {
			return fmt.Errorf("No stream info or cluster")
		}
		for _, pi := range si.Cluster.Replicas {
			if !pi.Current {
				return fmt.Errorf("Peer not current: %+v", pi)
			}
		}
		return nil
	})
}

func TestJetStreamClusterServerLimits(t *testing.T) {
	// 2MB memory, 8MB disk
	c := createJetStreamClusterWithTemplate(t, jsClusterLimitsTempl, "R3L", 3)
	defer c.shutdown()

	// Client based API
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	msg, toSend := make([]byte, 4*1024), 5000
	crand.Read(msg)

	// Memory first.
	max_mem := uint64(2*1024*1024) + uint64(len(msg))

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TM",
		Replicas: 3,
		Storage:  nats.MemoryStorage,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Grab stream leader.
	sl := c.streamLeader("ONE", "TM")
	require_True(t, sl != nil)

	for i := 0; i < toSend; i++ {
		if _, err = js.Publish("TM", msg); err != nil {
			break
		}
	}
	if err == nil || !strings.HasPrefix(err.Error(), "nats: insufficient resources") {
		t.Fatalf("Expected a ErrJetStreamResourcesExceeded error, got %v", err)
	}

	// Since we have run all servers out of resources, no leader will be elected to respond to stream info.
	// So check manually.
	acc, err := sl.LookupAccount("ONE")
	require_NoError(t, err)
	mset, err := acc.lookupStream("TM")
	require_NoError(t, err)
	if state := mset.state(); state.Bytes > max_mem {
		t.Fatalf("Expected bytes of %v to not be greater then %v",
			friendlyBytes(int64(state.Bytes)),
			friendlyBytes(int64(max_mem)),
		)
	}

	c.waitOnLeader()

	// Now disk.
	max_disk := uint64(8*1024*1024) + uint64(len(msg))

	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "TF",
		Replicas: 3,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Grab stream leader.
	sl = c.streamLeader("ONE", "TF")
	require_True(t, sl != nil)

	for i := 0; i < toSend; i++ {
		if _, err = js.Publish("TF", msg); err != nil {
			break
		}
	}
	if err == nil || !strings.HasPrefix(err.Error(), "nats: insufficient resources") {
		t.Fatalf("Expected a ErrJetStreamResourcesExceeded error, got %v", err)
	}

	// Since we have run all servers out of resources, no leader will be elected to respond to stream info.
	// So check manually.
	acc, err = sl.LookupAccount("ONE")
	require_NoError(t, err)
	mset, err = acc.lookupStream("TF")
	require_NoError(t, err)
	if state := mset.state(); state.Bytes > max_disk {
		t.Fatalf("Expected bytes of %v to not be greater then %v",
			friendlyBytes(int64(state.Bytes)),
			friendlyBytes(int64(max_disk)),
		)
	}
}

func TestJetStreamClusterAccountLoadFailure(t *testing.T) {
	c := createJetStreamClusterWithTemplate(t, jsClusterLimitsTempl, "R3L", 3)
	defer c.shutdown()

	// Client based API
	nc, js := jsClientConnect(t, c.leader())
	defer nc.Close()

	// Remove the "ONE" account from non-leader
	s := c.randomNonLeader()
	s.mu.Lock()
	s.accounts.Delete("ONE")
	s.mu.Unlock()

	_, err := js.AddStream(&nats.StreamConfig{Name: "F", Replicas: 3})
	if err == nil || !strings.Contains(err.Error(), "account not found") {
		t.Fatalf("Expected an 'account not found' error but got %v", err)
	}
}

func TestJetStreamClusterAckPendingWithExpired(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3", 3)
	defer c.shutdown()

	// Client based API
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo", "bar"},
		Replicas: 3,
		MaxAge:   500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Send in 100 messages.
	msg, toSend := make([]byte, 256), 100
	crand.Read(msg)

	for i := 0; i < toSend; i++ {
		if _, err = js.Publish("foo", msg); err != nil {
			t.Fatalf("Unexpected publish error: %v", err)
		}
	}

	sub, err := js.SubscribeSync("foo")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	checkSubsPending(t, sub, toSend)
	ci, err := sub.ConsumerInfo()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if ci.NumAckPending != toSend {
		t.Fatalf("Expected %d to be pending, got %d", toSend, ci.NumAckPending)
	}

	// Wait for messages to expire.
	checkFor(t, 2*time.Second, 100*time.Millisecond, func() error {
		si, err := js.StreamInfo("TEST")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if si.State.Msgs != 0 {
			return fmt.Errorf("Expected 0 msgs, got state: %+v", si.State)
		}
		return nil
	})

	// Once expired these messages can not be redelivered so should not be considered ack pending at this point.
	// Now ack..
	ci, err = sub.ConsumerInfo()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if ci.NumAckPending != 0 {
		t.Fatalf("Expected nothing to be ack pending, got %d", ci.NumAckPending)
	}
}

func TestJetStreamClusterAckPendingWithMaxRedelivered(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3", 3)
	defer c.shutdown()

	// Client based API
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo", "bar"},
		Replicas: 3,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Send in 100 messages.
	msg, toSend := []byte("HELLO"), 100

	for i := 0; i < toSend; i++ {
		if _, err = js.Publish("foo", msg); err != nil {
			t.Fatalf("Unexpected publish error: %v", err)
		}
	}

	sub, err := js.SubscribeSync("foo",
		nats.MaxDeliver(2),
		nats.Durable("dlc"),
		nats.AckWait(10*time.Millisecond),
		nats.MaxAckPending(50),
	)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	checkSubsPending(t, sub, toSend*2)

	checkFor(t, 5*time.Second, 100*time.Millisecond, func() error {
		ci, err := sub.ConsumerInfo()
		if err != nil {
			return err
		}
		if ci.NumAckPending != 0 {
			return fmt.Errorf("Expected nothing to be ack pending, got %d", ci.NumAckPending)
		}
		return nil
	})
}

func TestJetStreamClusterMixedMode(t *testing.T) {
	for _, test := range []struct {
		name string
		tmpl string
	}{
		{"multi-account", jsClusterLimitsTempl},
		{"global-account", jsMixedModeGlobalAccountTempl},
	} {
		t.Run(test.name, func(t *testing.T) {

			c := createMixedModeCluster(t, test.tmpl, "MM5", _EMPTY_, 3, 2, true)
			defer c.shutdown()

			// Client based API - Non-JS server.
			nc, js := jsClientConnect(t, c.serverByName("S-5"))
			defer nc.Close()

			_, err := js.AddStream(&nats.StreamConfig{
				Name:     "TEST",
				Subjects: []string{"foo", "bar"},
				Replicas: 3,
			})
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			ml := c.leader()
			if ml == nil {
				t.Fatalf("No metaleader")
			}

			// Make sure we are tracking only the JS peers.
			checkFor(t, 5*time.Second, 100*time.Millisecond, func() error {
				peers := ml.JetStreamClusterPeers()
				if len(peers) == 3 {
					return nil
				}
				return fmt.Errorf("Not correct number of peers, expected %d, got %d", 3, len(peers))
			})

			// Grab the underlying raft structure and make sure the system adjusts its cluster set size.
			meta := ml.getJetStream().getMetaGroup().(*raft)
			checkFor(t, 5*time.Second, 100*time.Millisecond, func() error {
				ps := meta.currentPeerState()
				if len(ps.knownPeers) != 3 {
					return fmt.Errorf("Expected known peers to be 3, but got %+v", ps.knownPeers)
				}
				if ps.clusterSize < 3 {
					return fmt.Errorf("Expected cluster size to be 3, but got %+v", ps)
				}
				return nil
			})
		})
	}
}

func TestJetStreamClusterLeafnodeSpokes(t *testing.T) {
	c := createJetStreamCluster(t, jsClusterTempl, "HUB", _EMPTY_, 3, 22020, false)
	defer c.shutdown()

	lnc1 := c.createLeafNodesWithStartPortAndDomain("R1", 3, 22110, _EMPTY_)
	defer lnc1.shutdown()

	lnc2 := c.createLeafNodesWithStartPortAndDomain("R2", 3, 22120, _EMPTY_)
	defer lnc2.shutdown()

	lnc3 := c.createLeafNodesWithStartPortAndDomain("R3", 3, 22130, _EMPTY_)
	defer lnc3.shutdown()

	// Wait on all peers.
	c.waitOnPeerCount(12)

	// Make sure shrinking works.
	lnc3.shutdown()
	c.waitOnPeerCount(9)

	lnc3 = c.createLeafNodesWithStartPortAndDomain("LNC3", 3, 22130, _EMPTY_)
	defer lnc3.shutdown()

	c.waitOnPeerCount(12)
}

func TestJetStreamClusterLeafNodeDenyNoDupe(t *testing.T) {
	tmpl := strings.Replace(jsClusterAccountsTempl, "store_dir:", "domain: CORE, store_dir:", 1)
	c := createJetStreamCluster(t, tmpl, "CORE", _EMPTY_, 3, 18033, true)
	defer c.shutdown()

	tmpl = strings.Replace(jsClusterTemplWithSingleLeafNode, "store_dir:", "domain: SPOKE, store_dir:", 1)
	ln := c.createLeafNodeWithTemplate("LN-SPOKE", tmpl)
	defer ln.Shutdown()

	checkLeafNodeConnectedCount(t, ln, 2)

	// Now disconnect our leafnode connections by restarting the server we are connected to..
	for _, s := range c.servers {
		if s.ClusterName() != c.name {
			continue
		}
		if nln := s.NumLeafNodes(); nln > 0 {
			s.Shutdown()
			c.restartServer(s)
		}
	}
	// Make sure we are back connected.
	checkLeafNodeConnectedCount(t, ln, 2)

	// Now grab leaf varz and make sure we have no dupe deny clauses.
	vz, err := ln.Varz(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Grab the correct remote.
	for _, remote := range vz.LeafNode.Remotes {
		if remote.LocalAccount == ln.SystemAccount().Name {
			if remote.Deny != nil && len(remote.Deny.Exports) > 3 { // denyAll := []string{jscAllSubj, raftAllSubj, jsAllAPI}
				t.Fatalf("Dupe entries found: %+v", remote.Deny)
			}
			break
		}
	}
}

// Multiple JS domains.
func TestJetStreamClusterSingleLeafNodeWithoutSharedSystemAccount(t *testing.T) {
	c := createJetStreamCluster(t, strings.Replace(jsClusterAccountsTempl, "store_dir", "domain: CORE, store_dir", 1), "HUB", _EMPTY_, 3, 14333, true)
	defer c.shutdown()

	ln := c.createSingleLeafNodeNoSystemAccount()
	defer ln.Shutdown()

	// The setup here has a single leafnode server with two accounts. One has JS, the other does not.
	// We want to to test the following.
	// 1. For the account without JS, we simply will pass through to the HUB. Meaning since our local account
	//    does not have it, we simply inherit the hub's by default.
	// 2. For the JS enabled account, we are isolated and use our local one only.

	// Check behavior of the account without JS.
	// Normally this should fail since our local account is not enabled. However, since we are bridging
	// via the leafnode we expect this to work here.
	nc, js := jsClientConnectEx(t, ln, []nats.JSOpt{nats.Domain("CORE")}, nats.UserInfo("n", "p"))
	defer nc.Close()

	si, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 2,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if si.Cluster == nil || si.Cluster.Name != "HUB" {
		t.Fatalf("Expected stream to be placed in %q", "HUB")
	}
	// Do some other API calls.
	_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{Durable: "C1", AckPolicy: nats.AckExplicitPolicy})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	seen := 0
	for name := range js.StreamNames() {
		seen++
		if name != "TEST" {
			t.Fatalf("Expected only %q but got %q", "TEST", name)
		}
	}
	if seen != 1 {
		t.Fatalf("Expected only 1 stream, got %d", seen)
	}
	if _, err := js.StreamInfo("TEST"); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if err := js.PurgeStream("TEST"); err != nil {
		t.Fatalf("Unexpected purge error: %v", err)
	}
	if err := js.DeleteConsumer("TEST", "C1"); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if _, err := js.UpdateStream(&nats.StreamConfig{Name: "TEST", Subjects: []string{"bar"}, Replicas: 2}); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if err := js.DeleteStream("TEST"); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Now check the enabled account.
	// Check the enabled account only talks to its local JS domain by default.
	nc, js = jsClientConnect(t, ln, nats.UserInfo("y", "p"))
	defer nc.Close()

	sub, err := nc.SubscribeSync(JSAdvisoryStreamCreatedPre + ".>")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	si, err = js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if si.Cluster != nil {
		t.Fatalf("Expected no cluster designation for stream since created on single LN server")
	}

	// Wait for a bit and make sure we only get one of these.
	// The HUB domain should be cut off by default.
	time.Sleep(250 * time.Millisecond)
	checkSubsPending(t, sub, 1)
	// Drain.
	for _, err := sub.NextMsg(0); err == nil; _, err = sub.NextMsg(0) {
	}

	// Now try to talk to the HUB JS domain through a new context that uses a different mapped subject.
	// This is similar to how we let users cross JS domains between accounts as well.
	js, err = nc.JetStream(nats.APIPrefix("$JS.HUB.API"))
	if err != nil {
		t.Fatalf("Unexpected error getting JetStream context: %v", err)
	}
	// This should fail here with jetstream not enabled.
	if _, err := js.AccountInfo(); err != nats.ErrJetStreamNotEnabled {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Now add in a mapping to the connected account in the HUB.
	// This aligns with the APIPrefix context above and works across leafnodes.
	// TODO(dlc) - Should we have a mapping section for leafnode solicit?
	c.addSubjectMapping("ONE", "$JS.HUB.API.>", "$JS.API.>")

	// Now it should work.
	if _, err := js.AccountInfo(); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Make sure we can add a stream, etc.
	si, err = js.AddStream(&nats.StreamConfig{
		Name:     "TEST22",
		Subjects: []string{"bar"},
		Replicas: 2,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if si.Cluster == nil || si.Cluster.Name != "HUB" {
		t.Fatalf("Expected stream to be placed in %q", "HUB")
	}

	jsLocal, err := nc.JetStream()
	if err != nil {
		t.Fatalf("Unexpected error getting JetStream context: %v", err)
	}

	// Create a mirror on the local leafnode for stream TEST22.
	_, err = jsLocal.AddStream(&nats.StreamConfig{
		Name: "M",
		Mirror: &nats.StreamSource{
			Name:     "TEST22",
			External: &nats.ExternalStream{APIPrefix: "$JS.HUB.API"},
		},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Publish a message to the HUB's TEST22 stream.
	if _, err := js.Publish("bar", []byte("OK")); err != nil {
		t.Fatalf("Unexpected publish error: %v", err)
	}
	// Make sure the message arrives in our mirror.
	checkFor(t, 5*time.Second, 100*time.Millisecond, func() error {
		si, err := jsLocal.StreamInfo("M")
		if err != nil {
			return fmt.Errorf("Could not get stream info: %v", err)
		}
		if si.State.Msgs != 1 {
			return fmt.Errorf("Expected 1 msg, got state: %+v", si.State)
		}
		return nil
	})

	// Now do the reverse and create a sourced stream in the HUB from our local stream on leafnode.
	// Inside the HUB we need to be able to find our local leafnode JetStream assets, so we need
	// a mapping in the LN server to allow this to work. Normally this will just be in server config.
	acc, err := ln.LookupAccount("JSY")
	if err != nil {
		c.t.Fatalf("Unexpected error on %v: %v", ln, err)
	}
	if err := acc.AddMapping("$JS.LN.API.>", "$JS.API.>"); err != nil {
		c.t.Fatalf("Error adding mapping: %v", err)
	}

	// js is the HUB JetStream context here.
	_, err = js.AddStream(&nats.StreamConfig{
		Name: "S",
		Sources: []*nats.StreamSource{{
			Name:     "M",
			External: &nats.ExternalStream{APIPrefix: "$JS.LN.API"},
		}},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Make sure the message arrives in our sourced stream.
	checkFor(t, 2*time.Second, 100*time.Millisecond, func() error {
		si, err := js.StreamInfo("S")
		if err != nil {
			return fmt.Errorf("Could not get stream info: %v", err)
		}
		if si.State.Msgs != 1 {
			return fmt.Errorf("Expected 1 msg, got state: %+v", si.State)
		}
		return nil
	})
}

// JetStream Domains
func TestJetStreamClusterDomains(t *testing.T) {
	// This adds in domain config option to template.
	tmpl := strings.Replace(jsClusterAccountsTempl, "store_dir:", "domain: CORE, store_dir:", 1)
	c := createJetStreamCluster(t, tmpl, "CORE", _EMPTY_, 3, 12232, true)
	defer c.shutdown()

	// This leafnode is a single server with no domain but sharing the system account.
	// This extends the CORE domain through this leafnode.
	ln := c.createLeafNodeWithTemplate("LN-SYS",
		strings.ReplaceAll(jsClusterTemplWithSingleLeafNode, "store_dir:", "extension_hint: will_extend, domain: CORE, store_dir:"))
	defer ln.Shutdown()

	checkLeafNodeConnectedCount(t, ln, 2)

	// This shows we have extended this system.
	c.waitOnPeerCount(4)
	if ml := c.leader(); ml == ln {
		t.Fatalf("Detected a meta-leader in the leafnode: %s", ml)
	}

	// Now create another LN but with a domain defined.
	tmpl = strings.Replace(jsClusterTemplWithSingleLeafNode, "store_dir:", "domain: SPOKE, store_dir:", 1)
	spoke := c.createLeafNodeWithTemplate("LN-SPOKE", tmpl)
	defer spoke.Shutdown()

	checkLeafNodeConnectedCount(t, spoke, 2)

	// Should be the same, should not extend the CORE domain.
	c.waitOnPeerCount(4)

	// The domain signals to the system that we are our own JetStream domain and should not extend CORE.
	// We want to check to make sure we have all the deny properly setup.
	spoke.mu.Lock()
	// var hasDE, hasDI bool
	for _, ln := range spoke.leafs {
		ln.mu.Lock()
		remote := ln.leaf.remote
		ln.mu.Unlock()
		remote.RLock()
		if remote.RemoteLeafOpts.LocalAccount == "$SYS" {
			for _, s := range denyAllJs {
				if r := ln.perms.pub.deny.Match(s); len(r.psubs) != 1 {
					t.Fatalf("Expected to have deny permission for %s", s)
				}
				if r := ln.perms.sub.deny.Match(s); len(r.psubs) != 1 {
					t.Fatalf("Expected to have deny permission for %s", s)
				}
			}
		}
		remote.RUnlock()
	}
	spoke.mu.Unlock()

	// Now do some operations.
	// Check the enabled account only talks to its local JS domain by default.
	nc, js := jsClientConnect(t, spoke)
	defer nc.Close()

	si, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if si.Cluster != nil {
		t.Fatalf("Expected no cluster designation for stream since created on single LN server")
	}

	// Now try to talk to the CORE JS domain through a new context that uses a different mapped subject.
	jsCore, err := nc.JetStream(nats.APIPrefix("$JS.CORE.API"))
	if err != nil {
		t.Fatalf("Unexpected error getting JetStream context: %v", err)
	}
	if _, err := jsCore.AccountInfo(); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Make sure we can add a stream, etc.
	si, err = jsCore.AddStream(&nats.StreamConfig{
		Name:     "TEST22",
		Subjects: []string{"bar"},
		Replicas: 2,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if si.Cluster == nil || si.Cluster.Name != "CORE" {
		t.Fatalf("Expected stream to be placed in %q, got %q", "CORE", si.Cluster.Name)
	}

	jsLocal, err := nc.JetStream()
	if err != nil {
		t.Fatalf("Unexpected error getting JetStream context: %v", err)
	}

	// Create a mirror on our local leafnode for stream TEST22.
	_, err = jsLocal.AddStream(&nats.StreamConfig{
		Name: "M",
		Mirror: &nats.StreamSource{
			Name:     "TEST22",
			External: &nats.ExternalStream{APIPrefix: "$JS.CORE.API"},
		},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Publish a message to the CORE's TEST22 stream.
	if _, err := jsCore.Publish("bar", []byte("OK")); err != nil {
		t.Fatalf("Unexpected publish error: %v", err)
	}

	// Make sure the message arrives in our mirror.
	checkFor(t, 2*time.Second, 100*time.Millisecond, func() error {
		si, err := jsLocal.StreamInfo("M")
		if err != nil {
			return fmt.Errorf("Could not get stream info: %v", err)
		}
		if si.State.Msgs != 1 {
			return fmt.Errorf("Expected 1 msg, got state: %+v", si.State)
		}
		return nil
	})

	// jsCore is the CORE JetStream domain.
	// Create a sourced stream in the CORE that is sourced from our mirror stream in our leafnode.
	_, err = jsCore.AddStream(&nats.StreamConfig{
		Name: "S",
		Sources: []*nats.StreamSource{{
			Name:     "M",
			External: &nats.ExternalStream{APIPrefix: "$JS.SPOKE.API"},
		}},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Make sure the message arrives in our sourced stream.
	checkFor(t, 2*time.Second, 100*time.Millisecond, func() error {
		si, err := jsCore.StreamInfo("S")
		if err != nil {
			return fmt.Errorf("Could not get stream info: %v", err)
		}
		if si.State.Msgs != 1 {
			return fmt.Errorf("Expected 1 msg, got state: %+v", si.State)
		}
		return nil
	})

	// Now connect directly to the CORE cluster and make sure we can operate there.
	nc, jsLocal = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	// Create the js contexts again.
	jsSpoke, err := nc.JetStream(nats.APIPrefix("$JS.SPOKE.API"))
	if err != nil {
		t.Fatalf("Unexpected error getting JetStream context: %v", err)
	}

	// Publish a message to the CORE's TEST22 stream.
	if _, err := jsLocal.Publish("bar", []byte("OK")); err != nil {
		t.Fatalf("Unexpected publish error: %v", err)
	}

	// Make sure the message arrives in our mirror.
	checkFor(t, 2*time.Second, 100*time.Millisecond, func() error {
		si, err := jsSpoke.StreamInfo("M")
		if err != nil {
			return fmt.Errorf("Could not get stream info: %v", err)
		}
		if si.State.Msgs != 2 {
			return fmt.Errorf("Expected 2 msgs, got state: %+v", si.State)
		}
		return nil
	})

	// Make sure the message arrives in our sourced stream.
	checkFor(t, 2*time.Second, 100*time.Millisecond, func() error {
		si, err := jsLocal.StreamInfo("S")
		if err != nil {
			return fmt.Errorf("Could not get stream info: %v", err)
		}
		if si.State.Msgs != 2 {
			return fmt.Errorf("Expected 2 msgs, got state: %+v", si.State)
		}
		return nil
	})

	// We are connected to the CORE domain/system. Create a JetStream context referencing ourselves.
	jsCore, err = nc.JetStream(nats.APIPrefix("$JS.CORE.API"))
	if err != nil {
		t.Fatalf("Unexpected error getting JetStream context: %v", err)
	}

	si, err = jsCore.StreamInfo("S")
	if err != nil {
		t.Fatalf("Could not get stream info: %v", err)
	}
	if si.State.Msgs != 2 {
		t.Fatalf("Expected 2 msgs, got state: %+v", si.State)
	}
}

func TestJetStreamClusterDomainsWithNoJSHub(t *testing.T) {
	// Create our hub cluster with no JetStream defined.
	c := createMixedModeCluster(t, jsClusterAccountsTempl, "NOJS5", _EMPTY_, 0, 5, false)
	defer c.shutdown()

	ln := c.createSingleLeafNodeNoSystemAccountAndEnablesJetStream()
	defer ln.Shutdown()

	lnd := c.createSingleLeafNodeNoSystemAccountAndEnablesJetStreamWithDomain("SPOKE", "nojs")
	defer lnd.Shutdown()

	// Client based API - Connected to the core cluster with no JS but account has JS.
	s := c.randomServer()
	// Make sure the JS interest from the LNs has made it to this server.
	checkSubInterest(t, s, "NOJS", "$JS.SPOKE.API.INFO", time.Second)
	nc, _ := jsClientConnect(t, s, nats.UserInfo("nojs", "p"))
	defer nc.Close()

	cfg := &nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
	}
	req, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Do by hand to make sure we only get one response.
	sis := fmt.Sprintf(strings.ReplaceAll(JSApiStreamCreateT, JSApiPrefix, "$JS.SPOKE.API"), "TEST")
	rs := nats.NewInbox()
	sub, _ := nc.SubscribeSync(rs)
	nc.PublishRequest(sis, rs, req)
	// Wait for response.
	checkSubsPending(t, sub, 1)
	// Double check to make sure we only have 1.
	if nr, _, err := sub.Pending(); err != nil || nr != 1 {
		t.Fatalf("Expected 1 response, got %d and %v", nr, err)
	}
	resp, err := sub.NextMsg(time.Second)
	require_NoError(t, err)

	// This StreamInfo should *not* have a domain set.
	// Do by hand until this makes it to the Go client.
	var si StreamInfo
	if err = json.Unmarshal(resp.Data, &si); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if si.Domain != _EMPTY_ {
		t.Fatalf("Expected to have NO domain set but got %q", si.Domain)
	}

	// Now let's create a stream specifically on the SPOKE domain.
	js, err := nc.JetStream(nats.Domain("SPOKE"))
	if err != nil {
		t.Fatalf("Unexpected error getting JetStream context: %v", err)
	}
	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "TEST22",
		Subjects: []string{"bar"},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Now lookup by hand to check domain.
	resp, err = nc.Request("$JS.SPOKE.API.STREAM.INFO.TEST22", nil, time.Second)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if err = json.Unmarshal(resp.Data, &si); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if si.Domain != "SPOKE" {
		t.Fatalf("Expected to have domain set to %q but got %q", "SPOKE", si.Domain)
	}
}

// Issue #2205
func TestJetStreamClusterDomainsAndAPIResponses(t *testing.T) {
	// This adds in domain config option to template.
	tmpl := strings.Replace(jsClusterAccountsTempl, "store_dir:", "domain: CORE, store_dir:", 1)
	c := createJetStreamCluster(t, tmpl, "CORE", _EMPTY_, 3, 12232, true)
	defer c.shutdown()

	// Now create spoke LN cluster.
	tmpl = strings.Replace(jsClusterTemplWithLeafNode, "store_dir:", "domain: SPOKE, store_dir:", 1)
	lnc := c.createLeafNodesWithTemplateAndStartPort(tmpl, "SPOKE", 5, 23913)
	defer lnc.shutdown()

	lnc.waitOnClusterReady()

	// Make the physical connection to the CORE.
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 2,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Now create JS domain context and try to do same in LN cluster.
	// The issue referenced above details a bug where we can not receive a positive response.
	nc, _ = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	jsSpoke, err := nc.JetStream(nats.APIPrefix("$JS.SPOKE.API"))
	if err != nil {
		t.Fatalf("Unexpected error getting JetStream context: %v", err)
	}

	si, err := jsSpoke.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 2,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if si.Cluster.Name != "SPOKE" {
		t.Fatalf("Expected %q as the cluster, got %q", "SPOKE", si.Cluster.Name)
	}
}

// Issue #2202
func TestJetStreamClusterDomainsAndSameNameSources(t *testing.T) {
	tmpl := strings.Replace(jsClusterAccountsTempl, "store_dir:", "domain: CORE, store_dir:", 1)
	c := createJetStreamCluster(t, tmpl, "CORE", _EMPTY_, 3, 9323, true)
	defer c.shutdown()

	tmpl = strings.Replace(jsClusterTemplWithSingleLeafNode, "store_dir:", "domain: SPOKE-1, store_dir:", 1)
	spoke1 := c.createLeafNodeWithTemplate("LN-SPOKE-1", tmpl)
	defer spoke1.Shutdown()

	tmpl = strings.Replace(jsClusterTemplWithSingleLeafNode, "store_dir:", "domain: SPOKE-2, store_dir:", 1)
	spoke2 := c.createLeafNodeWithTemplate("LN-SPOKE-2", tmpl)
	defer spoke2.Shutdown()

	checkLeafNodeConnectedCount(t, spoke1, 2)
	checkLeafNodeConnectedCount(t, spoke2, 2)

	subjFor := func(s *Server) string {
		switch s {
		case spoke1:
			return "foo"
		case spoke2:
			return "bar"
		}
		return "TEST"
	}

	// Create the same name stream in both spoke domains.
	for _, s := range []*Server{spoke1, spoke2} {
		nc, js := jsClientConnect(t, s)
		defer nc.Close()
		_, err := js.AddStream(&nats.StreamConfig{
			Name:     "TEST",
			Subjects: []string{subjFor(s)},
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		nc.Close()
	}

	// Now connect to the hub and create a sourced stream from both leafnode streams.
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name: "S",
		Sources: []*nats.StreamSource{
			{
				Name:     "TEST",
				External: &nats.ExternalStream{APIPrefix: "$JS.SPOKE-1.API"},
			},
			{
				Name:     "TEST",
				External: &nats.ExternalStream{APIPrefix: "$JS.SPOKE-2.API"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Publish a message to each spoke stream and we will check that our sourced stream gets both.
	for _, s := range []*Server{spoke1, spoke2} {
		nc, js := jsClientConnect(t, s)
		defer nc.Close()
		js.Publish(subjFor(s), []byte("DOUBLE TROUBLE"))
		si, err := js.StreamInfo("TEST")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if si.State.Msgs != 1 {
			t.Fatalf("Expected 1 msg, got %d", si.State.Msgs)
		}
		nc.Close()
	}

	// Now make sure we have 2 msgs in our sourced stream.
	checkFor(t, 2*time.Second, 50*time.Millisecond, func() error {
		si, err := js.StreamInfo("S")
		require_NoError(t, err)
		if si.State.Msgs != 2 {
			return fmt.Errorf("Expected 2 msgs, got %d", si.State.Msgs)
		}
		return nil
	})

	// Make sure we can see our external information.
	// This not in the Go client yet so manual for now.
	resp, err := nc.Request(fmt.Sprintf(JSApiStreamInfoT, "S"), nil, time.Second)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	var ssi StreamInfo
	if err = json.Unmarshal(resp.Data, &ssi); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(ssi.Sources) != 2 {
		t.Fatalf("Expected 2 source streams, got %d", len(ssi.Sources))
	}
	if ssi.Sources[0].External == nil {
		t.Fatalf("Expected a non-nil external designation")
	}
	pre := ssi.Sources[0].External.ApiPrefix
	if pre != "$JS.SPOKE-1.API" && pre != "$JS.SPOKE-2.API" {
		t.Fatalf("Expected external api of %q, got %q", "$JS.SPOKE-[1|2].API", ssi.Sources[0].External.ApiPrefix)
	}

	// Also create a mirror.
	_, err = js.AddStream(&nats.StreamConfig{
		Name: "M",
		Mirror: &nats.StreamSource{
			Name:     "TEST",
			External: &nats.ExternalStream{APIPrefix: "$JS.SPOKE-1.API"},
		},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	resp, err = nc.Request(fmt.Sprintf(JSApiStreamInfoT, "M"), nil, time.Second)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if err = json.Unmarshal(resp.Data, &ssi); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if ssi.Mirror == nil || ssi.Mirror.External == nil {
		t.Fatalf("Expected a non-nil external designation for our mirror")
	}
	if ssi.Mirror.External.ApiPrefix != "$JS.SPOKE-1.API" {
		t.Fatalf("Expected external api of %q, got %q", "$JS.SPOKE-1.API", ssi.Sources[0].External.ApiPrefix)
	}
}

// When a leafnode enables JS on an account that is not enabled on the remote cluster account this should fail
// Accessing a jet stream in a different availability domain requires the client provide a damain name, or
// the server having set up appropriate defaults (default_js_domain. tested in leafnode_test.go)
func TestJetStreamClusterSingleLeafNodeEnablingJetStream(t *testing.T) {
	tmpl := strings.Replace(jsClusterAccountsTempl, "store_dir:", "domain: HUB, store_dir:", 1)
	c := createJetStreamCluster(t, tmpl, "HUB", _EMPTY_, 3, 11322, true)
	defer c.shutdown()

	ln := c.createSingleLeafNodeNoSystemAccountAndEnablesJetStream()
	defer ln.Shutdown()

	// Check that we have JS in the $G account on the leafnode.
	nc, js := jsClientConnect(t, ln)
	defer nc.Close()

	if _, err := js.AccountInfo(); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Connect our client to the "nojs" account in the cluster but make sure JS works since its enabled via the leafnode.
	s := c.randomServer()
	nc, js = jsClientConnect(t, s, nats.UserInfo("nojs", "p"))
	defer nc.Close()
	_, err := js.AccountInfo()
	// error is context deadline exceeded as the local account has no js and can't reach the remote one
	require_True(t, err == context.DeadlineExceeded)
}

func TestJetStreamClusterLeafNodesWithoutJS(t *testing.T) {
	tmpl := strings.Replace(jsClusterAccountsTempl, "store_dir:", "domain: HUB, store_dir:", 1)
	c := createJetStreamCluster(t, tmpl, "HUB", _EMPTY_, 3, 11233, true)
	defer c.shutdown()

	testJS := func(s *Server, domain string, doDomainAPI bool) {
		nc, js := jsClientConnect(t, s)
		defer nc.Close()
		if doDomainAPI {
			var err error
			apiPre := fmt.Sprintf("$JS.%s.API", domain)
			if js, err = nc.JetStream(nats.APIPrefix(apiPre)); err != nil {
				t.Fatalf("Unexpected error getting JetStream context: %v", err)
			}
		}
		ai, err := js.AccountInfo()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if ai.Domain != domain {
			t.Fatalf("Expected domain of %q, got %q", domain, ai.Domain)
		}
	}

	ln := c.createLeafNodeWithTemplate("LN-SYS-S-NOJS", jsClusterTemplWithSingleLeafNodeNoJS)
	defer ln.Shutdown()

	checkLeafNodeConnectedCount(t, ln, 2)

	// Check that we can access JS in the $G account on the cluster through the leafnode.
	testJS(ln, "HUB", true)
	ln.Shutdown()

	// Now create a leafnode cluster with No JS and make sure that works.
	lnc := c.createLeafNodesNoJS("LN-SYS-C-NOJS", 3)
	defer lnc.shutdown()

	testJS(lnc.randomServer(), "HUB", true)
	lnc.shutdown()

	// Do mixed mode but with a JS config block that specifies domain and just sets it to disabled.
	// This is the preferred method for mixed mode, always define JS server config block just disable
	// in those you do not want it running.
	// e.g. jetstream: {domain: "SPOKE", enabled: false}
	tmpl = strings.Replace(jsClusterTemplWithLeafNode, "store_dir:", "domain: SPOKE, store_dir:", 1)
	lncm := c.createLeafNodesWithTemplateMixedMode(tmpl, "SPOKE", 3, 2, true)
	defer lncm.shutdown()

	// Now grab a non-JS server, last two are non-JS.
	sl := lncm.servers[0]
	testJS(sl, "SPOKE", false)

	// Test that mappings work as well and we can access the hub.
	testJS(sl, "HUB", true)
}

func TestJetStreamClusterLeafNodesWithSameDomainNames(t *testing.T) {
	tmpl := strings.Replace(jsClusterAccountsTempl, "store_dir:", "domain: HUB, store_dir:", 1)
	c := createJetStreamCluster(t, tmpl, "HUB", _EMPTY_, 3, 11233, true)
	defer c.shutdown()

	tmpl = strings.Replace(jsClusterTemplWithLeafNode, "store_dir:", "domain: HUB, store_dir:", 1)
	lnc := c.createLeafNodesWithTemplateAndStartPort(tmpl, "SPOKE", 3, 11311)
	defer lnc.shutdown()

	c.waitOnPeerCount(6)
}

func TestJetStreamClusterLeafDifferentAccounts(t *testing.T) {
	c := createJetStreamCluster(t, jsClusterAccountsTempl, "HUB", _EMPTY_, 2, 23133, false)
	defer c.shutdown()

	ln := c.createLeafNodesWithStartPortAndDomain("LN", 2, 22110, _EMPTY_)
	defer ln.shutdown()

	// Wait on all peers.
	c.waitOnPeerCount(4)

	nc, js := jsClientConnect(t, ln.randomServer())
	defer nc.Close()

	// Make sure we can properly identify the right account when the leader received the request.
	// We need to map the client info header to the new account once received by the hub.
	if _, err := js.AccountInfo(); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestJetStreamClusterStreamInfoDeletedDetails(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R2", 2)
	defer c.shutdown()

	// Client based API
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 1,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Send in 10 messages.
	msg, toSend := []byte("HELLO"), 10

	for i := 0; i < toSend; i++ {
		if _, err = js.Publish("foo", msg); err != nil {
			t.Fatalf("Unexpected publish error: %v", err)
		}
	}

	// Now remove some messages.
	deleteMsg := func(seq uint64) {
		if err := js.DeleteMsg("TEST", seq); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	}
	deleteMsg(2)
	deleteMsg(4)
	deleteMsg(6)

	// Need to do these via direct server request for now.
	resp, err := nc.Request(fmt.Sprintf(JSApiStreamInfoT, "TEST"), nil, time.Second)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	var si StreamInfo
	if err = json.Unmarshal(resp.Data, &si); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if si.State.NumDeleted != 3 {
		t.Fatalf("Expected %d deleted, got %d", 3, si.State.NumDeleted)
	}
	if len(si.State.Deleted) != 0 {
		t.Fatalf("Expected not deleted details, but got %+v", si.State.Deleted)
	}

	// Now request deleted details.
	req := JSApiStreamInfoRequest{DeletedDetails: true}
	b, _ := json.Marshal(req)

	resp, err = nc.Request(fmt.Sprintf(JSApiStreamInfoT, "TEST"), b, time.Second)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if err = json.Unmarshal(resp.Data, &si); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if si.State.NumDeleted != 3 {
		t.Fatalf("Expected %d deleted, got %d", 3, si.State.NumDeleted)
	}
	if len(si.State.Deleted) != 3 {
		t.Fatalf("Expected deleted details, but got %+v", si.State.Deleted)
	}
}

func TestJetStreamClusterMirrorAndSourceExpiration(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "MSE", 3)
	defer c.shutdown()

	// Client for API requests.
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	// Origin
	if _, err := js.AddStream(&nats.StreamConfig{Name: "TEST"}); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	bi := 1
	sendBatch := func(n int) {
		t.Helper()
		// Send a batch to a given subject.
		for i := 0; i < n; i++ {
			msg := fmt.Sprintf("ID: %d", bi)
			bi++
			if _, err := js.PublishAsync("TEST", []byte(msg)); err != nil {
				t.Fatalf("Unexpected publish error: %v", err)
			}
		}
	}

	checkStream := func(stream string, num uint64) {
		t.Helper()
		checkFor(t, 5*time.Second, 50*time.Millisecond, func() error {
			si, err := js.StreamInfo(stream)
			if err != nil {
				return err
			}
			if si.State.Msgs != num {
				return fmt.Errorf("Expected %d msgs, got %d", num, si.State.Msgs)
			}
			return nil
		})
	}

	checkSource := func(num uint64) { t.Helper(); checkStream("S", num) }
	checkMirror := func(num uint64) { t.Helper(); checkStream("M", num) }
	checkTest := func(num uint64) { t.Helper(); checkStream("TEST", num) }

	var err error

	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "M",
		Mirror:   &nats.StreamSource{Name: "TEST"},
		Replicas: 2,
		MaxAge:   500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// We want this to not be same as TEST leader for this test.
	sl := c.streamLeader("$G", "TEST")
	for ss := sl; ss == sl; {
		_, err = js.AddStream(&nats.StreamConfig{
			Name:     "S",
			Sources:  []*nats.StreamSource{{Name: "TEST"}},
			Replicas: 2,
			MaxAge:   500 * time.Millisecond,
		})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if ss = c.streamLeader("$G", "S"); ss == sl {
			// Delete and retry.
			js.DeleteStream("S")
		}
	}

	sendBatch(100)
	checkTest(100)
	checkMirror(100)
	checkSource(100)

	// Make sure they expire.
	checkMirror(0)
	checkSource(0)

	// Now stop the server housing the leader of the source stream.
	sl.Shutdown()
	c.restartServer(sl)
	checkClusterFormed(t, c.servers...)
	c.waitOnStreamLeader("$G", "S")
	c.waitOnStreamLeader("$G", "M")

	// Make sure can process correctly after we have expired all of the messages.
	sendBatch(100)
	// Need to check both in parallel.
	scheck, mcheck := uint64(0), uint64(0)
	checkFor(t, 10*time.Second, 50*time.Millisecond, func() error {
		if scheck != 100 {
			if si, _ := js.StreamInfo("S"); si != nil {
				scheck = si.State.Msgs
			}
		}
		if mcheck != 100 {
			if si, _ := js.StreamInfo("M"); si != nil {
				mcheck = si.State.Msgs
			}
		}
		if scheck == 100 && mcheck == 100 {
			return nil
		}
		return fmt.Errorf("Both not at 100 yet, S=%d, M=%d", scheck, mcheck)
	})

	checkTest(200)
}

func TestJetStreamClusterMirrorAndSourceSubLeaks(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "MSL", 3)
	defer c.shutdown()

	// Client for API requests.
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	startSubs := c.stableTotalSubs()

	var ss []*nats.StreamSource

	// Create 10 origin streams
	for i := 0; i < 10; i++ {
		sn := fmt.Sprintf("ORDERS-%d", i+1)
		ss = append(ss, &nats.StreamSource{Name: sn})
		if _, err := js.AddStream(&nats.StreamConfig{Name: sn}); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	}

	// Create mux'd stream that sources all of the origin streams.
	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "MUX",
		Replicas: 2,
		Sources:  ss,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Now create a mirror of the mux stream.
	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "MIRROR",
		Replicas: 2,
		Mirror:   &nats.StreamSource{Name: "MUX"},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Get stable subs count.
	afterSubs := c.stableTotalSubs()

	js.DeleteStream("MIRROR")
	js.DeleteStream("MUX")

	for _, si := range ss {
		js.DeleteStream(si.Name)
	}

	// Some subs take longer to settle out so we give ourselves a small buffer.
	// There will be 1 sub for client on each server (such as _INBOX.IvVJ2DOXUotn4RUSZZCFvp.*)
	// and 2 or 3 subs such as `_R_.xxxxx.>` on each server, so a total of 12 subs.
	if deleteSubs := c.stableTotalSubs(); deleteSubs > startSubs+12 {
		t.Fatalf("Expected subs to return to %d from a high of %d, but got %d", startSubs, afterSubs, deleteSubs)
	}
}

func TestJetStreamClusterCreateConcurrentDurableConsumers(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "MSL", 3)
	defer c.shutdown()

	// Client for API requests.
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	// Create origin stream, must be R > 1
	if _, err := js.AddStream(&nats.StreamConfig{Name: "ORDERS", Replicas: 3}); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if _, err := js.QueueSubscribeSync("ORDERS", "wq", nats.Durable("shared")); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Now try to create durables concurrently.
	start := make(chan struct{})
	var wg sync.WaitGroup
	created := uint32(0)
	errs := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			<-start
			_, err := js.QueueSubscribeSync("ORDERS", "wq", nats.Durable("shared"))
			if err == nil {
				atomic.AddUint32(&created, 1)
			} else if !strings.Contains(err.Error(), "consumer name already") {
				errs <- err
			}
		}()
	}

	close(start)
	wg.Wait()

	if lc := atomic.LoadUint32(&created); lc != 10 {
		t.Fatalf("Expected all 10 to be created, got %d", lc)
	}
	if len(errs) > 0 {
		t.Fatalf("Failed to create some sub: %v", <-errs)
	}
}

// https://github.com/nats-io/nats-server/issues/2144
func TestJetStreamClusterUpdateStreamToExisting(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "MSL", 3)
	defer c.shutdown()

	// Client for API requests.
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "ORDERS1",
		Replicas: 3,
		Subjects: []string{"foo"},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "ORDERS2",
		Replicas: 3,
		Subjects: []string{"bar"},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	_, err = js.UpdateStream(&nats.StreamConfig{
		Name:     "ORDERS2",
		Replicas: 3,
		Subjects: []string{"foo"},
	})
	if err == nil {
		t.Fatalf("Expected an error but got none")
	}
}

func TestJetStreamClusterCrossAccountInterop(t *testing.T) {
	template := `
	listen: 127.0.0.1:-1
	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 2GB, domain: HUB, store_dir: '%s'}

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	accounts {
		JS {
			jetstream: enabled
			users = [ { user: "rip", pass: "pass" } ]
			exports [
				{ service: "$JS.API.CONSUMER.INFO.>" }
				{ service: "$JS.HUB.API.CONSUMER.>", response: stream }
				{ stream: "M.SYNC.>" } # For the mirror
			]
		}
		IA {
			jetstream: enabled
			users = [ { user: "dlc", pass: "pass" } ]
			imports [
				{ service: { account: JS, subject: "$JS.API.CONSUMER.INFO.TEST.DLC"}, to: "FROM.DLC" }
				{ service: { account: JS, subject: "$JS.HUB.API.CONSUMER.>"}, to: "js.xacc.API.CONSUMER.>" }
				{ stream: { account: JS, subject: "M.SYNC.>"} }
			]
		}
		$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
	}
	`

	c := createJetStreamClusterWithTemplate(t, template, "HUB", 3)
	defer c.shutdown()

	// Create the stream and the consumer under the JS/rip user.
	s := c.randomServer()
	nc, js := jsClientConnect(t, s, nats.UserInfo("rip", "pass"))
	defer nc.Close()

	if _, err := js.AddStream(&nats.StreamConfig{Name: "TEST", Replicas: 2}); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	_, err := js.AddConsumer("TEST", &nats.ConsumerConfig{Durable: "DLC", AckPolicy: nats.AckExplicitPolicy})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Also create a stream via the domain qualified API.
	js, err = nc.JetStream(nats.APIPrefix("$JS.HUB.API"))
	if err != nil {
		t.Fatalf("Unexpected error getting JetStream context: %v", err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{Name: "ORDERS", Replicas: 2}); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Now we want to access the consumer info from IA/dlc.
	nc2, js2 := jsClientConnect(t, c.randomServer(), nats.UserInfo("dlc", "pass"))
	defer nc2.Close()

	if _, err := nc2.Request("FROM.DLC", nil, time.Second); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Make sure domain mappings etc work across accounts.
	// Setup a mirror.
	_, err = js2.AddStream(&nats.StreamConfig{
		Name: "MIRROR",
		Mirror: &nats.StreamSource{
			Name: "ORDERS",
			External: &nats.ExternalStream{
				APIPrefix:     "js.xacc.API",
				DeliverPrefix: "M.SYNC",
			},
		},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Send 10 messages..
	msg, toSend := []byte("Hello mapped domains"), 10
	for i := 0; i < toSend; i++ {
		if _, err = js.Publish("ORDERS", msg); err != nil {
			t.Fatalf("Unexpected publish error: %v", err)
		}
	}

	checkFor(t, 2*time.Second, 100*time.Millisecond, func() error {
		si, err := js2.StreamInfo("MIRROR")
		if err != nil {
			return fmt.Errorf("Unexpected error: %v", err)
		}
		if si.State.Msgs != 10 {
			return fmt.Errorf("Expected 10 msgs, got state: %+v", si.State)
		}
		return nil
	})
}

// https://github.com/nats-io/nats-server/issues/2242
func TestJetStreamClusterMsgIdDuplicateBug(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "MSL", 3)
	defer c.shutdown()

	// Client for API requests.
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 2,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	sendMsgID := func(id string) (*nats.PubAck, error) {
		t.Helper()
		m := nats.NewMsg("foo")
		m.Header.Add(JSMsgId, id)
		m.Data = []byte("HELLO WORLD")
		return js.PublishMsg(m)
	}

	if _, err := sendMsgID("1"); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// This should fail with duplicate detected.
	if pa, _ := sendMsgID("1"); pa == nil || !pa.Duplicate {
		t.Fatalf("Expected duplicate but got none: %+v", pa)
	}
	// This should be fine.
	if _, err := sendMsgID("2"); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestJetStreamClusterNilMsgWithHeaderThroughSourcedStream(t *testing.T) {
	tmpl := strings.Replace(jsClusterAccountsTempl, "store_dir:", "domain: HUB, store_dir:", 1)
	c := createJetStreamCluster(t, tmpl, "HUB", _EMPTY_, 3, 12232, true)
	defer c.shutdown()

	tmpl = strings.Replace(jsClusterTemplWithSingleLeafNode, "store_dir:", "domain: SPOKE, store_dir:", 1)
	spoke := c.createLeafNodeWithTemplate("SPOKE", tmpl)
	defer spoke.Shutdown()

	checkLeafNodeConnectedCount(t, spoke, 2)

	// Client for API requests.
	nc, js := jsClientConnect(t, spoke)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	jsHub, err := nc.JetStream(nats.APIPrefix("$JS.HUB.API"))
	if err != nil {
		t.Fatalf("Unexpected error getting JetStream context: %v", err)
	}

	_, err = jsHub.AddStream(&nats.StreamConfig{
		Name:     "S",
		Replicas: 2,
		Sources: []*nats.StreamSource{{
			Name:     "TEST",
			External: &nats.ExternalStream{APIPrefix: "$JS.SPOKE.API"},
		}},
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Now send a message to the origin stream with nil body and a header.
	m := nats.NewMsg("foo")
	m.Header.Add("X-Request-ID", "e9a639b4-cecb-4fbe-8376-1ef511ae1f8d")
	m.Data = []byte("HELLO WORLD")

	if _, err = jsHub.PublishMsg(m); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	sub, err := jsHub.SubscribeSync("foo", nats.BindStream("S"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	msg, err := sub.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if string(msg.Data) != "HELLO WORLD" {
		t.Fatalf("Message corrupt? Expecting %q got %q", "HELLO WORLD", msg.Data)
	}
}

// Make sure varz reports the server usage not replicated usage etc.
func TestJetStreamClusterVarzReporting(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	s := c.randomServer()
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Replicas: 3,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// ~100k per message.
	msg := []byte(strings.Repeat("A", 99_960))
	msz := fileStoreMsgSize("TEST", nil, msg)
	total := msz * 10

	for i := 0; i < 10; i++ {
		if _, err := js.Publish("TEST", msg); err != nil {
			t.Fatalf("Unexpected publish error: %v", err)
		}
	}
	// To show the bug we need this to allow remote usage to replicate.
	time.Sleep(2 * usageTick)

	v, err := s.Varz(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if v.JetStream.Stats.Store > total {
		t.Fatalf("Single server varz JetStream store usage should be <= %d, got %d", total, v.JetStream.Stats.Store)
	}

	info, err := js.AccountInfo()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if info.Store < total*3 {
		t.Fatalf("Expected account information to show usage ~%d, got %d", total*3, info.Store)
	}
}

func TestJetStreamClusterPurgeBySequence(t *testing.T) {
	for _, st := range []StorageType{FileStorage, MemoryStorage} {
		t.Run(st.String(), func(t *testing.T) {

			c := createJetStreamClusterExplicit(t, "JSC", 3)
			defer c.shutdown()

			nc, js := jsClientConnect(t, c.randomServer())
			defer nc.Close()

			cfg := StreamConfig{
				Name:       "KV",
				Subjects:   []string{"kv.*.*"},
				Storage:    st,
				Replicas:   2,
				MaxMsgsPer: 5,
			}
			req, err := json.Marshal(cfg)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			nc.Request(fmt.Sprintf(JSApiStreamCreateT, cfg.Name), req, time.Second)
			for i := 0; i < 20; i++ {
				if _, err = js.Publish("kv.myapp.username", []byte(fmt.Sprintf("value %d", i))); err != nil {
					t.Fatalf("request failed: %s", err)
				}
			}
			for i := 0; i < 20; i++ {
				if _, err = js.Publish("kv.myapp.password", []byte(fmt.Sprintf("value %d", i))); err != nil {
					t.Fatalf("request failed: %s", err)
				}
			}
			expectSequences := func(t *testing.T, subject string, seq ...int) {
				sub, err := js.SubscribeSync(subject)
				if err != nil {
					t.Fatalf("sub failed: %s", err)
				}
				defer sub.Unsubscribe()
				for _, i := range seq {
					msg, err := sub.NextMsg(time.Second)
					if err != nil {
						t.Fatalf("didn't get message: %s", err)
					}
					meta, err := msg.Metadata()
					if err != nil {
						t.Fatalf("didn't get metadata: %s", err)
					}
					if meta.Sequence.Stream != uint64(i) {
						t.Fatalf("expected sequence %d got %d", i, meta.Sequence.Stream)
					}
				}
			}
			expectSequences(t, "kv.myapp.username", 16, 17, 18, 19, 20)
			expectSequences(t, "kv.myapp.password", 36, 37, 38, 39, 40)

			// delete up to but not including 18 of username...
			jr, _ := json.Marshal(&JSApiStreamPurgeRequest{Subject: "kv.myapp.username", Sequence: 18})
			_, err = nc.Request(fmt.Sprintf(JSApiStreamPurgeT, "KV"), jr, time.Second)
			if err != nil {
				t.Fatalf("request failed: %s", err)
			}
			// 18 should still be there
			expectSequences(t, "kv.myapp.username", 18, 19, 20)
		})
	}
}

func TestJetStreamClusterMaxConsumers(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	cfg := &nats.StreamConfig{
		Name:         "MAXC",
		Storage:      nats.MemoryStorage,
		Subjects:     []string{"in.maxc.>"},
		MaxConsumers: 1,
	}
	if _, err := js.AddStream(cfg); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	si, err := js.StreamInfo("MAXC")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if si.Config.MaxConsumers != 1 {
		t.Fatalf("Expected max of 1, got %d", si.Config.MaxConsumers)
	}
	// Make sure we get the right error.
	// This should succeed.
	if _, err := js.SubscribeSync("in.maxc.foo"); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if _, err := js.SubscribeSync("in.maxc.bar"); err == nil {
		t.Fatalf("Eexpected error but got none")
	}
}

func TestJetStreamClusterMaxConsumersMultipleConcurrentRequests(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	cfg := &nats.StreamConfig{
		Name:         "MAXCC",
		Storage:      nats.MemoryStorage,
		Subjects:     []string{"in.maxcc.>"},
		MaxConsumers: 1,
		Replicas:     3,
	}
	if _, err := js.AddStream(cfg); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	si, err := js.StreamInfo("MAXCC")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if si.Config.MaxConsumers != 1 {
		t.Fatalf("Expected max of 1, got %d", si.Config.MaxConsumers)
	}

	startCh := make(chan bool)
	var wg sync.WaitGroup
	wg.Add(10)
	for n := 0; n < 10; n++ {
		nc, js := jsClientConnect(t, c.randomServer())
		defer nc.Close()
		go func(js nats.JetStreamContext) {
			defer wg.Done()
			<-startCh
			js.SubscribeSync("in.maxcc.foo")
		}(js)
	}
	// Wait for Go routines.
	time.Sleep(250 * time.Millisecond)

	close(startCh)
	wg.Wait()

	var names []string
	for n := range js.ConsumerNames("MAXCC") {
		names = append(names, n)
	}
	if nc := len(names); nc > 1 {
		t.Fatalf("Expected only 1 consumer, got %d", nc)
	}
}

func TestJetStreamClusterAccountMaxStreamsAndConsumersMultipleConcurrentRequests(t *testing.T) {
	tmpl := `
	listen: 127.0.0.1:-1
	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

	leaf {
		listen: 127.0.0.1:-1
	}

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	accounts {
		A {
			jetstream {
				max_file: 9663676416
				max_streams: 2
				max_consumers: 1
			}
			users = [ { user: "a", pass: "pwd" } ]
		}
		$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
	}
	`
	c := createJetStreamClusterWithTemplate(t, tmpl, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer(), nats.UserInfo("a", "pwd"))
	defer nc.Close()

	cfg := &nats.StreamConfig{
		Name:     "MAXCC",
		Storage:  nats.MemoryStorage,
		Subjects: []string{"in.maxcc.>"},
		Replicas: 3,
	}
	if _, err := js.AddStream(cfg); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	si, err := js.StreamInfo("MAXCC")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if si.Config.MaxConsumers != -1 {
		t.Fatalf("Expected max of -1, got %d", si.Config.MaxConsumers)
	}

	startCh := make(chan bool)
	var wg sync.WaitGroup
	wg.Add(10)
	for n := 0; n < 10; n++ {
		nc, js := jsClientConnect(t, c.randomServer(), nats.UserInfo("a", "pwd"))
		defer nc.Close()
		go func(js nats.JetStreamContext, idx int) {
			defer wg.Done()
			<-startCh
			// Test adding new streams
			js.AddStream(&nats.StreamConfig{
				Name:     fmt.Sprintf("OTHER_%d", idx),
				Replicas: 3,
			})
			// Test adding consumers to MAXCC stream
			js.SubscribeSync("in.maxcc.foo", nats.BindStream("MAXCC"))
		}(js, n)
	}
	// Wait for Go routines.
	time.Sleep(250 * time.Millisecond)

	close(startCh)
	wg.Wait()

	var names []string
	for n := range js.StreamNames() {
		names = append(names, n)
	}
	if nc := len(names); nc > 2 {
		t.Fatalf("Expected only 2 streams, got %d", nc)
	}
	names = names[:0]
	for n := range js.ConsumerNames("MAXCC") {
		names = append(names, n)
	}
	if nc := len(names); nc > 1 {
		t.Fatalf("Expected only 1 consumer, got %d", nc)
	}
}

func TestJetStreamClusterPanicDecodingConsumerState(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	rch := make(chan struct{}, 2)
	nc, js := jsClientConnect(t, c.randomServer(),
		nats.ReconnectWait(50*time.Millisecond),
		nats.MaxReconnects(-1),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			rch <- struct{}{}
		}),
	)
	defer nc.Close()

	if _, err := js.AddStream(&nats.StreamConfig{
		Name:      "TEST",
		Subjects:  []string{"ORDERS.*"},
		Storage:   nats.FileStorage,
		Replicas:  3,
		Retention: nats.WorkQueuePolicy,
		Discard:   nats.DiscardNew,
		MaxMsgs:   -1,
		MaxAge:    time.Hour * 24 * 365,
	}); err != nil {
		t.Fatalf("Error creating stream: %v", err)
	}

	sub, err := js.PullSubscribe("ORDERS.created", "durable", nats.MaxAckPending(1000))

	if err != nil {
		t.Fatalf("Error creating pull subscriber: %v", err)
	}

	sendMsg := func(subject string) {
		t.Helper()
		if _, err := js.Publish(subject, []byte("msg")); err != nil {
			t.Fatalf("Error on publish: %v", err)
		}
	}

	for i := 0; i < 100; i++ {
		sendMsg("ORDERS.something")
		sendMsg("ORDERS.created")
	}

	for total := 0; total != 100; {
		msgs, err := sub.Fetch(100-total, nats.MaxWait(2*time.Second))
		if err != nil {
			t.Fatalf("Failed to fetch message: %v", err)
		}
		for _, m := range msgs {
			m.AckSync()
			total++
		}
	}

	c.stopAll()
	c.restartAllSamePorts()
	c.waitOnStreamLeader("$G", "TEST")
	c.waitOnConsumerLeader("$G", "TEST", "durable")

	select {
	case <-rch:
	case <-time.After(2 * time.Second):
		t.Fatal("Did not reconnect")
	}

	for i := 0; i < 100; i++ {
		sendMsg("ORDERS.something")
		sendMsg("ORDERS.created")
	}

	for total := 0; total != 100; {
		msgs, err := sub.Fetch(100-total, nats.MaxWait(2*time.Second))
		if err != nil {
			t.Fatalf("Error on fetch: %v", err)
		}
		for _, m := range msgs {
			m.AckSync()
			total++
		}
	}
}

// Had a report of leaked subs with pull subscribers.
func TestJetStreamClusterPullConsumerLeakedSubs(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	if _, err := js.AddStream(&nats.StreamConfig{
		Name:      "TEST",
		Subjects:  []string{"Domains.*"},
		Replicas:  1,
		Retention: nats.InterestPolicy,
	}); err != nil {
		t.Fatalf("Error creating stream: %v", err)
	}

	sub, err := js.PullSubscribe("Domains.Domain", "Domains-Api", nats.MaxAckPending(20_000))
	if err != nil {
		t.Fatalf("Error creating pull subscriber: %v", err)
	}
	defer sub.Unsubscribe()

	// Load up a bunch of requests.
	numRequests := 20
	for i := 0; i < numRequests; i++ {
		js.PublishAsync("Domains.Domain", []byte("QUESTION"))
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}
	numSubs := c.stableTotalSubs()

	// With batch of 1 we do not see any issues, so set to 10.
	// Currently Go client uses auto unsub based on the batch size.
	for i := 0; i < numRequests/10; i++ {
		msgs, err := sub.Fetch(10)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		for _, m := range msgs {
			m.AckSync()
		}
	}

	// Make sure the stream is empty..
	si, err := js.StreamInfo("TEST")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if si.State.Msgs != 0 {
		t.Fatalf("Stream should be empty, got %+v", si)
	}

	// Make sure we did not leak any subs.
	if numSubsAfter := c.stableTotalSubs(); numSubsAfter != numSubs {
		t.Fatalf("Subs leaked: %d before, %d after", numSubs, numSubsAfter)
	}
}

func TestJetStreamClusterPushConsumerQueueGroup(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	if _, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 3,
	}); err != nil {
		t.Fatalf("Error creating stream: %v", err)
	}

	js.Publish("foo", []byte("QG"))

	// Do consumer by hand for now.
	inbox := nats.NewInbox()
	obsReq := CreateConsumerRequest{
		Stream: "TEST",
		Config: ConsumerConfig{
			Durable:        "dlc",
			DeliverSubject: inbox,
			DeliverGroup:   "22",
			AckPolicy:      AckNone,
		},
	}
	req, err := json.Marshal(obsReq)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	resp, err := nc.Request(fmt.Sprintf(JSApiDurableCreateT, "TEST", "dlc"), req, 2*time.Second)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	var ccResp JSApiConsumerCreateResponse
	if err = json.Unmarshal(resp.Data, &ccResp); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if ccResp.Error != nil {
		t.Fatalf("Unexpected error, got %+v", ccResp.Error)
	}

	sub, _ := nc.SubscribeSync(inbox)
	if _, err := sub.NextMsg(100 * time.Millisecond); err == nil {
		t.Fatalf("Expected a timeout, we should not get messages here")
	}
	qsub, _ := nc.QueueSubscribeSync(inbox, "22")
	checkSubsPending(t, qsub, 1)

	// Test deleting the plain sub has not affect.
	sub.Unsubscribe()
	js.Publish("foo", []byte("QG"))
	checkSubsPending(t, qsub, 2)

	qsub.Unsubscribe()
	qsub2, _ := nc.QueueSubscribeSync(inbox, "22")
	js.Publish("foo", []byte("QG"))
	checkSubsPending(t, qsub2, 1)

	// Catch all sub.
	sub, _ = nc.SubscribeSync(inbox)
	qsub2.Unsubscribe() // Should be no more interest.
	// Send another, make sure we do not see the message flow here.
	js.Publish("foo", []byte("QG"))
	if _, err := sub.NextMsg(100 * time.Millisecond); err == nil {
		t.Fatalf("Expected a timeout, we should not get messages here")
	}
}

func TestJetStreamClusterConsumerLastActiveReporting(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	// Client based API
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	cfg := &nats.StreamConfig{Name: "foo", Replicas: 2}
	if _, err := js.AddStream(cfg); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	sendMsg := func() {
		t.Helper()
		if _, err := js.Publish("foo", []byte("OK")); err != nil {
			t.Fatalf("Unexpected publish error: %v", err)
		}
	}

	sub, err := js.SubscribeSync("foo", nats.Durable("dlc"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// TODO(dlc) - Do by hand for now until Go client has this.
	consumerInfo := func(name string) *ConsumerInfo {
		t.Helper()
		resp, err := nc.Request(fmt.Sprintf(JSApiConsumerInfoT, "foo", name), nil, time.Second)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		var cinfo JSApiConsumerInfoResponse
		if err := json.Unmarshal(resp.Data, &cinfo); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if cinfo.ConsumerInfo == nil || cinfo.Error != nil {
			t.Fatalf("Got a bad response %+v", cinfo)
		}
		return cinfo.ConsumerInfo
	}

	if ci := consumerInfo("dlc"); ci.Delivered.Last != nil || ci.AckFloor.Last != nil {
		t.Fatalf("Expected last to be nil by default, got %+v", ci)
	}

	checkTimeDiff := func(t1, t2 *time.Time) {
		t.Helper()
		// Compare on a seconds level
		rt1, rt2 := t1.UTC().Round(time.Second), t2.UTC().Round(time.Second)
		if rt1 != rt2 {
			d := rt1.Sub(rt2)
			if d > time.Second || d < -time.Second {
				t.Fatalf("Times differ too much, expected %v got %v", rt1, rt2)
			}
		}
	}

	checkDelivered := func(name string) {
		t.Helper()
		now := time.Now()
		ci := consumerInfo(name)
		if ci.Delivered.Last == nil {
			t.Fatalf("Expected delivered last to not be nil after activity, got %+v", ci.Delivered)
		}
		checkTimeDiff(&now, ci.Delivered.Last)
	}

	checkLastAck := func(name string, m *nats.Msg) {
		t.Helper()
		now := time.Now()
		if err := m.AckSync(); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		ci := consumerInfo(name)
		if ci.AckFloor.Last == nil {
			t.Fatalf("Expected ack floor last to not be nil after ack, got %+v", ci.AckFloor)
		}
		// Compare on a seconds level
		checkTimeDiff(&now, ci.AckFloor.Last)
	}

	checkAck := func(name string) {
		t.Helper()
		m, err := sub.NextMsg(time.Second)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		checkLastAck(name, m)
	}

	// Push
	sendMsg()
	checkSubsPending(t, sub, 1)
	checkDelivered("dlc")
	checkAck("dlc")

	// Check pull.
	sub, err = js.PullSubscribe("foo", "rip")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	sendMsg()
	// Should still be nil since pull.
	if ci := consumerInfo("rip"); ci.Delivered.Last != nil || ci.AckFloor.Last != nil {
		t.Fatalf("Expected last to be nil by default, got %+v", ci)
	}
	msgs, err := sub.Fetch(1)
	if err != nil || len(msgs) == 0 {
		t.Fatalf("Unexpected error: %v", err)
	}
	checkDelivered("rip")
	checkLastAck("rip", msgs[0])

	// Now test to make sure this state is held correctly across a cluster.
	ci := consumerInfo("rip")
	nc.Request(fmt.Sprintf(JSApiConsumerLeaderStepDownT, "foo", "rip"), nil, time.Second)
	c.waitOnConsumerLeader("$G", "foo", "rip")
	nci := consumerInfo("rip")
	if nci.Delivered.Last == nil {
		t.Fatalf("Expected delivered last to not be nil, got %+v", nci.Delivered)
	}
	if nci.AckFloor.Last == nil {
		t.Fatalf("Expected ack floor last to not be nil, got %+v", nci.AckFloor)
	}

	checkTimeDiff(ci.Delivered.Last, nci.Delivered.Last)
	checkTimeDiff(ci.AckFloor.Last, nci.AckFloor.Last)
}

func TestJetStreamClusterRaceOnRAFTCreate(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	srv := c.servers[0]
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 3,
	}); err != nil {
		t.Fatalf("Error creating stream: %v", err)
	}

	c.waitOnStreamLeader(globalAccountName, "TEST")

	js, err = nc.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}

	size := 10
	wg := sync.WaitGroup{}
	wg.Add(size)
	for i := 0; i < size; i++ {
		go func() {
			defer wg.Done()
			// We don't care about possible failures here, we just want
			// parallel creation of a consumer.
			js.PullSubscribe("foo", "shared")
		}()
	}
	wg.Wait()
}

func TestJetStreamClusterDeadlockOnVarz(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	srv := c.servers[0]
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		t.Fatal(err)
	}

	size := 10
	wg := sync.WaitGroup{}
	wg.Add(size)
	ch := make(chan struct{})
	for i := 0; i < size; i++ {
		go func(i int) {
			defer wg.Done()
			<-ch
			js.AddStream(&nats.StreamConfig{
				Name:     fmt.Sprintf("TEST%d", i),
				Subjects: []string{"foo"},
				Replicas: 3,
			})
		}(i)
	}

	close(ch)
	for i := 0; i < 10; i++ {
		srv.Varz(nil)
		time.Sleep(time.Millisecond)
	}
	wg.Wait()
}

// Issue #2397
func TestJetStreamClusterStreamCatchupNoState(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R2S", 2)
	defer c.shutdown()

	// Client based API
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo.*"},
		Replicas: 2,
	})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Hold onto servers.
	sl := c.streamLeader("$G", "TEST")
	if sl == nil {
		t.Fatalf("Did not get a server")
	}
	nsl := c.randomNonStreamLeader("$G", "TEST")
	if nsl == nil {
		t.Fatalf("Did not get a server")
	}
	// Grab low level stream and raft node.
	mset, err := nsl.GlobalAccount().lookupStream("TEST")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	node := mset.raftNode()
	if node == nil {
		t.Fatalf("Could not get stream group name")
	}
	gname := node.Group()

	numRequests := 100
	for i := 0; i < numRequests; i++ {
		// This will force a snapshot which will prune the normal log.
		// We will remove the snapshot to simulate the error condition.
		if i == 10 {
			if err := node.InstallSnapshot(mset.stateSnapshot()); err != nil {
				t.Fatalf("Error installing snapshot: %v", err)
			}
		}
		_, err := js.Publish("foo.created", []byte("REQ"))
		require_NoError(t, err)
	}

	config := nsl.JetStreamConfig()
	if config == nil {
		t.Fatalf("No config")
	}
	lconfig := sl.JetStreamConfig()
	if lconfig == nil {
		t.Fatalf("No config")
	}

	nc.Close()
	c.stopAll()
	// Remove all state by truncating for the non-leader.
	for _, fn := range []string{"1.blk", "1.idx", "1.fss"} {
		fname := filepath.Join(config.StoreDir, "$G", "streams", "TEST", "msgs", fn)
		fd, err := os.OpenFile(fname, os.O_RDWR, defaultFilePerms)
		if err != nil {
			continue
		}
		fd.Truncate(0)
		fd.Close()
	}
	// For both make sure we have no raft snapshots.
	snapDir := filepath.Join(lconfig.StoreDir, "$SYS", "_js_", gname, "snapshots")
	os.RemoveAll(snapDir)
	snapDir = filepath.Join(config.StoreDir, "$SYS", "_js_", gname, "snapshots")
	os.RemoveAll(snapDir)

	// Now restart.
	c.restartAll()
	for _, cs := range c.servers {
		c.waitOnStreamCurrent(cs, "$G", "TEST")
	}

	nc, js = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	c.waitOnStreamLeader("$G", "TEST")

	_, err = js.Publish("foo.created", []byte("ZZZ"))
	require_NoError(t, err)

	si, err := js.StreamInfo("TEST")
	require_NoError(t, err)

	if si.State.LastSeq != 101 {
		t.Fatalf("bad state after restart: %+v", si.State)
	}
}

// Issue #2525
func TestJetStreamClusterLargeHeaders(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 3,
	})
	if err != nil {
		t.Fatalf("add stream failed: %s", err)
	}

	// We use u16 to encode msg header len. Make sure we do the right thing when > 65k.
	data := make([]byte, 8*1024)
	crand.Read(data)
	val := hex.EncodeToString(data)[:8*1024]
	m := nats.NewMsg("foo")
	for i := 1; i <= 10; i++ {
		m.Header.Add(fmt.Sprintf("LargeHeader-%d", i), val)
	}
	m.Data = []byte("Hello Large Headers!")
	if _, err = js.PublishMsg(m); err == nil {
		t.Fatalf("Expected an error but got none")
	}
}

func TestJetStreamClusterFlowControlRequiresHeartbeats(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	if _, err := js.AddStream(&nats.StreamConfig{Name: "TEST"}); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if _, err := js.AddConsumer("TEST", &nats.ConsumerConfig{
		Durable:        "dlc",
		DeliverSubject: nats.NewInbox(),
		FlowControl:    true,
	}); err == nil || IsNatsErr(err, JSConsumerWithFlowControlNeedsHeartbeats) {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestJetStreamClusterMixedModeColdStartPrune(t *testing.T) {
	// Purposely make this unbalanced. Without changes this will never form a quorum to elect the meta-leader.
	c := createMixedModeCluster(t, jsMixedModeGlobalAccountTempl, "MMCS5", _EMPTY_, 3, 4, false)
	defer c.shutdown()

	// Make sure we report cluster size.
	checkClusterSize := func(s *Server) {
		t.Helper()
		jsi, err := s.Jsz(nil)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if jsi.Meta == nil {
			t.Fatalf("Expected a cluster info")
		}
		if jsi.Meta.Size != 3 {
			t.Fatalf("Expected cluster size to be adjusted to %d, but got %d", 3, jsi.Meta.Size)
		}
	}

	checkClusterSize(c.leader())
	checkClusterSize(c.randomNonLeader())
}

func TestJetStreamClusterMirrorAndSourceCrossNonNeighboringDomain(t *testing.T) {
	storeDir1 := t.TempDir()
	conf1 := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		jetstream: {max_mem_store: 256MB, max_file_store: 256MB, domain: domain1, store_dir: '%s'}
		accounts {
			A:{   jetstream: enable, users:[ {user:a1,password:a1}]},
			SYS:{ users:[ {user:s1,password:s1}]},
		}
		system_account = SYS
		no_auth_user: a1
		leafnodes: {
			listen: 127.0.0.1:-1
		}
	`, storeDir1)))
	s1, _ := RunServerWithConfig(conf1)
	defer s1.Shutdown()
	storeDir2 := t.TempDir()
	conf2 := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		jetstream: {max_mem_store: 256MB, max_file_store: 256MB, domain: domain2, store_dir: '%s'}
		accounts {
			A:{   jetstream: enable, users:[ {user:a1,password:a1}]},
			SYS:{ users:[ {user:s1,password:s1}]},
		}
		system_account = SYS
		no_auth_user: a1
		leafnodes:{
			remotes:[{ url:nats://a1:a1@127.0.0.1:%d, account: A},
					 { url:nats://s1:s1@127.0.0.1:%d, account: SYS}]
		}
	`, storeDir2, s1.opts.LeafNode.Port, s1.opts.LeafNode.Port)))
	s2, _ := RunServerWithConfig(conf2)
	defer s2.Shutdown()
	storeDir3 := t.TempDir()
	conf3 := createConfFile(t, []byte(fmt.Sprintf(`
		listen: 127.0.0.1:-1
		jetstream: {max_mem_store: 256MB, max_file_store: 256MB, domain: domain3, store_dir: '%s'}
		accounts {
			A:{   jetstream: enable, users:[ {user:a1,password:a1}]},
			SYS:{ users:[ {user:s1,password:s1}]},
		}
		system_account = SYS
		no_auth_user: a1
		leafnodes:{
			remotes:[{ url:nats://a1:a1@127.0.0.1:%d, account: A},
					 { url:nats://s1:s1@127.0.0.1:%d, account: SYS}]
		}
	`, storeDir3, s1.opts.LeafNode.Port, s1.opts.LeafNode.Port)))
	s3, _ := RunServerWithConfig(conf3)
	defer s3.Shutdown()

	checkLeafNodeConnectedCount(t, s1, 4)
	checkLeafNodeConnectedCount(t, s2, 2)
	checkLeafNodeConnectedCount(t, s3, 2)

	c2 := natsConnect(t, s2.ClientURL())
	defer c2.Close()
	js2, err := c2.JetStream(nats.Domain("domain2"))
	require_NoError(t, err)
	ai2, err := js2.AccountInfo()
	require_NoError(t, err)
	require_Equal(t, ai2.Domain, "domain2")
	_, err = js2.AddStream(&nats.StreamConfig{
		Name:     "disk",
		Storage:  nats.FileStorage,
		Subjects: []string{"disk"},
	})
	require_NoError(t, err)
	_, err = js2.Publish("disk", nil)
	require_NoError(t, err)
	si, err := js2.StreamInfo("disk")
	require_NoError(t, err)
	require_True(t, si.State.Msgs == 1)

	c3 := natsConnect(t, s3.ClientURL())
	defer c3.Close()
	js3, err := c3.JetStream(nats.Domain("domain3"))
	require_NoError(t, err)
	ai3, err := js3.AccountInfo()
	require_NoError(t, err)
	require_Equal(t, ai3.Domain, "domain3")

	_, err = js3.AddStream(&nats.StreamConfig{
		Name:    "stream-mirror",
		Storage: nats.FileStorage,
		Mirror: &nats.StreamSource{
			Name:     "disk",
			External: &nats.ExternalStream{APIPrefix: "$JS.domain2.API"},
		},
	})
	require_NoError(t, err)

	_, err = js3.AddStream(&nats.StreamConfig{
		Name:    "stream-source",
		Storage: nats.FileStorage,
		Sources: []*nats.StreamSource{{
			Name:     "disk",
			External: &nats.ExternalStream{APIPrefix: "$JS.domain2.API"},
		}},
	})
	require_NoError(t, err)
	checkFor(t, 10*time.Second, 250*time.Millisecond, func() error {
		if si, _ := js3.StreamInfo("stream-mirror"); si.State.Msgs != 1 {
			return fmt.Errorf("Expected 1 msg for mirror, got %d", si.State.Msgs)
		}
		if si, _ := js3.StreamInfo("stream-source"); si.State.Msgs != 1 {
			return fmt.Errorf("Expected 1 msg for source, got %d", si.State.Msgs)
		}
		return nil
	})
}

func TestJetStreamClusterSeal(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	// Need to be done by hand until makes its way to Go client.
	createStream := func(t *testing.T, nc *nats.Conn, cfg *StreamConfig) *JSApiStreamCreateResponse {
		t.Helper()
		req, err := json.Marshal(cfg)
		require_NoError(t, err)
		resp, err := nc.Request(fmt.Sprintf(JSApiStreamCreateT, cfg.Name), req, time.Second)
		require_NoError(t, err)
		var scResp JSApiStreamCreateResponse
		err = json.Unmarshal(resp.Data, &scResp)
		require_NoError(t, err)
		return &scResp
	}

	updateStream := func(t *testing.T, nc *nats.Conn, cfg *StreamConfig) *JSApiStreamUpdateResponse {
		t.Helper()
		req, err := json.Marshal(cfg)
		require_NoError(t, err)
		resp, err := nc.Request(fmt.Sprintf(JSApiStreamUpdateT, cfg.Name), req, time.Second)
		require_NoError(t, err)
		var scResp JSApiStreamUpdateResponse
		err = json.Unmarshal(resp.Data, &scResp)
		require_NoError(t, err)
		return &scResp
	}

	testSeal := func(t *testing.T, s *Server, replicas int) {
		nc, js := jsClientConnect(t, s)
		defer nc.Close()
		// Should not be able to create a stream that starts sealed.
		scr := createStream(t, nc, &StreamConfig{Name: "SEALED", Replicas: replicas, Storage: MemoryStorage, Sealed: true})
		if scr.Error == nil {
			t.Fatalf("Expected an error but got none")
		}
		// Create our stream.
		scr = createStream(t, nc, &StreamConfig{Name: "SEALED", Replicas: replicas, MaxAge: time.Minute, Storage: MemoryStorage})
		if scr.Error != nil {
			t.Fatalf("Unexpected error: %v", scr.Error)
		}
		for i := 0; i < 100; i++ {
			js.Publish("SEALED", []byte("OK"))
		}
		// Update to sealed.
		sur := updateStream(t, nc, &StreamConfig{Name: "SEALED", Replicas: replicas, MaxAge: time.Minute, Storage: MemoryStorage, Sealed: true})
		if sur.Error != nil {
			t.Fatalf("Unexpected error: %v", sur.Error)
		}

		// Grab stream info and make sure its reflected as sealed.
		resp, err := nc.Request(fmt.Sprintf(JSApiStreamInfoT, "SEALED"), nil, time.Second)
		require_NoError(t, err)
		var sir JSApiStreamInfoResponse
		err = json.Unmarshal(resp.Data, &sir)
		require_NoError(t, err)
		if sir.Error != nil {
			t.Fatalf("Unexpected error: %v", sir.Error)
		}
		si := sir.StreamInfo
		if !si.Config.Sealed {
			t.Fatalf("Expected the stream to be marked sealed, got %+v\n", si.Config)
		}
		// Make sure we also updated any max age and moved to discard new.
		if si.Config.MaxAge != 0 {
			t.Fatalf("Expected MaxAge to be cleared, got %v", si.Config.MaxAge)
		}
		if si.Config.Discard != DiscardNew {
			t.Fatalf("Expected DiscardPolicy to be set to new, got %v", si.Config.Discard)
		}
		// Also make sure we set denyDelete and denyPurge.
		if !si.Config.DenyDelete {
			t.Fatalf("Expected the stream to be marked as DenyDelete, got %+v\n", si.Config)
		}
		if !si.Config.DenyPurge {
			t.Fatalf("Expected the stream to be marked as DenyPurge, got %+v\n", si.Config)
		}
		if si.Config.AllowRollup {
			t.Fatalf("Expected the stream to be marked as not AllowRollup, got %+v\n", si.Config)
		}

		// Sealing is not reversible, so make sure we get an error trying to undo.
		sur = updateStream(t, nc, &StreamConfig{Name: "SEALED", Replicas: replicas, Storage: MemoryStorage, Sealed: false})
		if sur.Error == nil {
			t.Fatalf("Expected an error but got none")
		}

		// Now test operations like publish a new msg, delete, purge etc all fail.
		if _, err := js.Publish("SEALED", []byte("OK")); err == nil {
			t.Fatalf("Expected a publish to fail")
		}
		if err := js.DeleteMsg("SEALED", 1); err == nil {
			t.Fatalf("Expected a delete to fail")
		}
		if err := js.PurgeStream("SEALED"); err == nil {
			t.Fatalf("Expected a purge to fail")
		}
		if err := js.DeleteStream("SEALED"); err != nil {
			t.Fatalf("Expected a delete to succeed, got %v", err)
		}
	}

	t.Run("Single", func(t *testing.T) { testSeal(t, s, 1) })
	t.Run("Clustered", func(t *testing.T) { testSeal(t, c.randomServer(), 3) })
}

// Issue #2568
func TestJetStreamClusteredStreamCreateIdempotent(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, _ := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	cfg := &StreamConfig{
		Name:       "AUDIT",
		Storage:    MemoryStorage,
		Subjects:   []string{"foo"},
		Replicas:   3,
		DenyDelete: true,
		DenyPurge:  true,
	}
	addStream(t, nc, cfg)
	addStream(t, nc, cfg)
}

func TestJetStreamClusterRollupsRequirePurge(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, _ := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	cfg := &StreamConfig{
		Name:        "SENSORS",
		Storage:     FileStorage,
		Subjects:    []string{"sensor.*.temp"},
		MaxMsgsPer:  10,
		AllowRollup: true,
		DenyPurge:   true,
		Replicas:    2,
	}

	j, err := json.Marshal(cfg)
	require_NoError(t, err)
	resp, err := nc.Request(fmt.Sprintf(JSApiStreamCreateT, cfg.Name), j, time.Second)
	require_NoError(t, err)

	var cr JSApiStreamCreateResponse
	err = json.Unmarshal(resp.Data, &cr)
	require_NoError(t, err)
	if cr.Error == nil || cr.Error.Description != "roll-ups require the purge permission" {
		t.Fatalf("unexpected error: %v", cr.Error)
	}
}

func TestJetStreamClusterRollups(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	cfg := &StreamConfig{
		Name:        "SENSORS",
		Storage:     FileStorage,
		Subjects:    []string{"sensor.*.temp"},
		MaxMsgsPer:  10,
		AllowRollup: true,
		Replicas:    2,
	}
	addStream(t, nc, cfg)

	var bt [16]byte
	var le = binary.LittleEndian

	// Generate 1000 random measurements for 10 sensors
	for i := 0; i < 1000; i++ {
		id, temp := strconv.Itoa(rand.Intn(9)+1), rand.Int31n(42)+60 // 60-102 degrees.
		le.PutUint16(bt[0:], uint16(temp))
		js.PublishAsync(fmt.Sprintf("sensor.%v.temp", id), bt[:])
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	// Grab random sensor and do a rollup by averaging etc.
	sensor := fmt.Sprintf("sensor.%v.temp", strconv.Itoa(rand.Intn(9)+1))
	sub, err := js.SubscribeSync(sensor)
	require_NoError(t, err)

	var total, samples int
	for m, err := sub.NextMsg(time.Second); err == nil; m, err = sub.NextMsg(time.Second) {
		total += int(le.Uint16(m.Data))
		samples++
	}
	sub.Unsubscribe()
	avg := uint16(total / samples)
	le.PutUint16(bt[0:], avg)

	rollup := nats.NewMsg(sensor)
	rollup.Data = bt[:]
	rollup.Header.Set(JSMsgRollup, JSMsgRollupSubject)
	_, err = js.PublishMsg(rollup)
	require_NoError(t, err)
	sub, err = js.SubscribeSync(sensor)
	require_NoError(t, err)
	// Make sure only 1 left.
	checkSubsPending(t, sub, 1)
	sub.Unsubscribe()

	// Now do all.
	rollup.Header.Set(JSMsgRollup, JSMsgRollupAll)
	_, err = js.PublishMsg(rollup)
	require_NoError(t, err)
	// Same thing as above should hold true.
	sub, err = js.SubscribeSync(sensor)
	require_NoError(t, err)
	// Make sure only 1 left.
	checkSubsPending(t, sub, 1)
	sub.Unsubscribe()

	// Also should only be 1 msgs in total stream left with JSMsgRollupAll
	si, err := js.StreamInfo("SENSORS")
	require_NoError(t, err)
	if si.State.Msgs != 1 {
		t.Fatalf("Expected only 1 msg left after rollup all, got %+v", si.State)
	}
}

func TestJetStreamClusterRollupSubjectAndWatchers(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	cfg := &StreamConfig{
		Name:        "KVW",
		Storage:     FileStorage,
		Subjects:    []string{"kv.*"},
		MaxMsgsPer:  10,
		AllowRollup: true,
		Replicas:    2,
	}
	addStream(t, nc, cfg)

	sub, err := js.SubscribeSync("kv.*")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	send := func(key, value string) {
		t.Helper()
		_, err := js.Publish("kv."+key, []byte(value))
		require_NoError(t, err)
	}

	rollup := func(key, value string) {
		t.Helper()
		m := nats.NewMsg("kv." + key)
		m.Data = []byte(value)
		m.Header.Set(JSMsgRollup, JSMsgRollupSubject)
		_, err := js.PublishMsg(m)
		require_NoError(t, err)
	}

	expectUpdate := func(key, value string, seq uint64) {
		t.Helper()
		m, err := sub.NextMsg(time.Second)
		require_NoError(t, err)
		if m.Subject != "kv."+key {
			t.Fatalf("Keys don't match: %q vs %q", m.Subject[3:], key)
		}
		if string(m.Data) != value {
			t.Fatalf("Values don't match: %q vs %q", m.Data, value)
		}
		meta, err := m.Metadata()
		require_NoError(t, err)
		if meta.Sequence.Consumer != seq {
			t.Fatalf("Sequences don't match: %v vs %v", meta.Sequence.Consumer, value)
		}
	}

	rollup("name", "derek")
	expectUpdate("name", "derek", 1)
	rollup("age", "22")
	expectUpdate("age", "22", 2)

	send("name", "derek")
	expectUpdate("name", "derek", 3)
	send("age", "22")
	expectUpdate("age", "22", 4)
	send("age", "33")
	expectUpdate("age", "33", 5)
	send("name", "ivan")
	expectUpdate("name", "ivan", 6)
	send("name", "rip")
	expectUpdate("name", "rip", 7)
	rollup("age", "50")
	expectUpdate("age", "50", 8)
}

func TestJetStreamClusterAppendOnly(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	cfg := &StreamConfig{
		Name:       "AUDIT",
		Storage:    MemoryStorage,
		Subjects:   []string{"foo"},
		Replicas:   3,
		DenyDelete: true,
		DenyPurge:  true,
	}
	si := addStream(t, nc, cfg)
	if !si.Config.DenyDelete || !si.Config.DenyPurge {
		t.Fatalf("Expected DenyDelete and DenyPurge to be set, got %+v", si.Config)
	}
	for i := 0; i < 10; i++ {
		js.Publish("foo", []byte("ok"))
	}
	// Delete should not be allowed.
	if err := js.DeleteMsg("AUDIT", 1); err == nil {
		t.Fatalf("Expected an error for delete but got none")
	}
	if err := js.PurgeStream("AUDIT"); err == nil {
		t.Fatalf("Expected an error for purge but got none")
	}

	cfg.DenyDelete = false
	cfg.DenyPurge = false

	req, err := json.Marshal(cfg)
	require_NoError(t, err)
	rmsg, err := nc.Request(fmt.Sprintf(JSApiStreamUpdateT, cfg.Name), req, time.Second)
	require_NoError(t, err)
	var resp JSApiStreamCreateResponse
	err = json.Unmarshal(rmsg.Data, &resp)
	require_NoError(t, err)
	if resp.Error == nil {
		t.Fatalf("Expected an error")
	}
}

// Related to #2642
func TestJetStreamClusterStreamUpdateSyncBug(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	// Client based API
	s := c.randomServer()
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	cfg := &nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo", "bar"},
		Replicas: 3,
	}

	if _, err := js.AddStream(cfg); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	msg, toSend := []byte("OK"), 100
	for i := 0; i < toSend; i++ {
		if _, err := js.PublishAsync("foo", msg); err != nil {
			t.Fatalf("Unexpected publish error: %v", err)
		}
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	cfg.Subjects = []string{"foo", "bar", "baz"}
	if _, err := js.UpdateStream(cfg); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Shutdown a server. The bug is that the update wiped the sync subject used to catchup a stream that has the RAFT layer snapshotted.
	nsl := c.randomNonStreamLeader("$G", "TEST")
	nsl.Shutdown()
	// make sure a leader exists
	c.waitOnStreamLeader("$G", "TEST")

	for i := 0; i < toSend*4; i++ {
		if _, err := js.PublishAsync("foo", msg); err != nil {
			t.Fatalf("Unexpected publish error: %v", err)
		}
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	// Throw in deletes as well.
	for seq := uint64(200); seq < uint64(300); seq += 4 {
		if err := js.DeleteMsg("TEST", seq); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	}

	// We need to snapshot to force upper layer catchup vs RAFT layer.
	c.waitOnAllCurrent()
	mset, err := c.streamLeader("$G", "TEST").GlobalAccount().lookupStream("TEST")
	if err != nil {
		t.Fatalf("Expected to find a stream for %q", "TEST")
	}
	if err := mset.raftNode().InstallSnapshot(mset.stateSnapshot()); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	c.waitOnAllCurrent()
	nsl = c.restartServer(nsl)
	c.waitOnStreamLeader("$G", "TEST")
	c.waitOnStreamCurrent(nsl, "$G", "TEST")

	mset, _ = nsl.GlobalAccount().lookupStream("TEST")
	cloneState := mset.state()

	mset, _ = c.streamLeader("$G", "TEST").GlobalAccount().lookupStream("TEST")
	leaderState := mset.state()

	if !reflect.DeepEqual(cloneState, leaderState) {
		t.Fatalf("States do not match: %+v vs %+v", cloneState, leaderState)
	}
}

// Issue #2666
func TestJetStreamClusterKVMultipleConcurrentCreate(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	// Client based API
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	kv, err := js.CreateKeyValue(&nats.KeyValueConfig{Bucket: "TEST", History: 1, TTL: 150 * time.Millisecond, Replicas: 3})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	startCh := make(chan bool)
	var wg sync.WaitGroup

	for n := 0; n < 5; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startCh
			if r, err := kv.Create("name", []byte("dlc")); err == nil {
				if _, err = kv.Update("name", []byte("rip"), r); err != nil {
					t.Log("Unexpected Update error: ", err)
				}
			}
		}()
	}
	// Wait for Go routines to start.
	time.Sleep(100 * time.Millisecond)
	close(startCh)
	wg.Wait()
	// Just make sure its there and picks up the phone.
	if _, err := js.StreamInfo("KV_TEST"); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Now make sure we do ok when servers are restarted and we need to deal with dangling clfs state.
	// First non-leader.
	rs := c.randomNonStreamLeader("$G", "KV_TEST")
	rs.Shutdown()
	rs = c.restartServer(rs)
	c.waitOnStreamCurrent(rs, "$G", "KV_TEST")

	if _, err := kv.Put("name", []byte("ik")); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Now the actual leader.
	sl := c.streamLeader("$G", "KV_TEST")
	sl.Shutdown()
	sl = c.restartServer(sl)
	c.waitOnStreamLeader("$G", "KV_TEST")
	c.waitOnStreamCurrent(sl, "$G", "KV_TEST")

	if _, err := kv.Put("name", []byte("mh")); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	time.Sleep(time.Second)
}

func TestJetStreamClusterAccountInfoForSystemAccount(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	// Client based API
	nc, js := jsClientConnect(t, c.randomServer(), nats.UserInfo("admin", "s3cr3t!"))
	defer nc.Close()

	_, err := js.AccountInfo()
	require_Error(t, err, nats.ErrJetStreamNotEnabledForAccount)
}

func TestJetStreamClusterListFilter(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	testList := func(t *testing.T, srv *Server, r int) {
		nc, js := jsClientConnect(t, srv)
		defer nc.Close()

		_, err := js.AddStream(&nats.StreamConfig{
			Name:     "ONE",
			Subjects: []string{"one.>"},
			Replicas: r,
		})
		require_NoError(t, err)

		_, err = js.AddStream(&nats.StreamConfig{
			Name:     "TWO",
			Subjects: []string{"two.>"},
			Replicas: r,
		})
		require_NoError(t, err)

		resp, err := nc.Request(JSApiStreamList, []byte("{}"), time.Second)
		require_NoError(t, err)

		list := &JSApiStreamListResponse{}
		err = json.Unmarshal(resp.Data, list)
		require_NoError(t, err)

		if len(list.Streams) != 2 {
			t.Fatalf("Expected 2 responses got %d", len(list.Streams))
		}

		resp, err = nc.Request(JSApiStreamList, []byte(`{"subject":"two.x"}`), time.Second)
		require_NoError(t, err)
		list = &JSApiStreamListResponse{}
		err = json.Unmarshal(resp.Data, list)
		require_NoError(t, err)
		if len(list.Streams) != 1 {
			t.Fatalf("Expected 1 response got %d", len(list.Streams))
		}
		if list.Streams[0].Config.Name != "TWO" {
			t.Fatalf("Expected stream TWO in result got %#v", list.Streams[0])
		}
	}

	t.Run("Single", func(t *testing.T) { testList(t, s, 1) })
	t.Run("Clustered", func(t *testing.T) { testList(t, c.randomServer(), 3) })
}

func TestJetStreamClusterConsumerUpdates(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	c := createJetStreamClusterExplicit(t, "JSC", 5)
	defer c.shutdown()

	testConsumerUpdate := func(t *testing.T, s *Server, replicas int) {
		nc, js := jsClientConnect(t, s)
		defer nc.Close()

		// Create a stream.
		_, err := js.AddStream(&nats.StreamConfig{
			Name:     "TEST",
			Subjects: []string{"foo", "bar"},
			Replicas: replicas,
		})
		require_NoError(t, err)

		for i := 0; i < 100; i++ {
			js.PublishAsync("foo", []byte("OK"))
		}

		cfg := &nats.ConsumerConfig{
			Durable:        "dlc",
			Description:    "Update TEST",
			FilterSubject:  "foo",
			DeliverSubject: "d.foo",
			AckPolicy:      nats.AckExplicitPolicy,
			AckWait:        time.Minute,
			MaxDeliver:     5,
			MaxAckPending:  50,
		}
		_, err = js.AddConsumer("TEST", cfg)
		require_NoError(t, err)

		// Update delivery subject, which worked before, but upon review had issues unless replica count == clustered size.
		cfg.DeliverSubject = "d.bar"
		_, err = js.AddConsumer("TEST", cfg)
		require_NoError(t, err)

		// Bind deliver subject.
		sub, err := nc.SubscribeSync("d.bar")
		require_NoError(t, err)
		defer sub.Unsubscribe()

		ncfg := *cfg
		// Deliver Subject
		ncfg.DeliverSubject = "d.baz"
		// Description
		cfg.Description = "New Description"
		_, err = js.UpdateConsumer("TEST", cfg)
		require_NoError(t, err)

		// MaxAckPending
		checkSubsPending(t, sub, 50)
		cfg.MaxAckPending = 75
		_, err = js.UpdateConsumer("TEST", cfg)
		require_NoError(t, err)
		checkSubsPending(t, sub, 75)

		// Drain sub, do not ack first ten though so we can test shortening AckWait.
		for i := 0; i < 100; i++ {
			m, err := sub.NextMsg(time.Second)
			require_NoError(t, err)
			if i >= 10 {
				m.AckSync()
			}
		}

		// AckWait
		checkSubsPending(t, sub, 0)
		cfg.AckWait = 200 * time.Millisecond
		_, err = js.UpdateConsumer("TEST", cfg)
		require_NoError(t, err)
		checkSubsPending(t, sub, 10)

		// Rate Limit
		cfg.RateLimit = 8 * 1024
		_, err = js.UpdateConsumer("TEST", cfg)
		require_NoError(t, err)

		cfg.RateLimit = 0
		_, err = js.UpdateConsumer("TEST", cfg)
		require_NoError(t, err)

		// These all should fail.
		ncfg = *cfg
		ncfg.DeliverPolicy = nats.DeliverLastPolicy
		_, err = js.UpdateConsumer("TEST", &ncfg)
		require_Error(t, err)

		ncfg = *cfg
		ncfg.OptStartSeq = 22
		_, err = js.UpdateConsumer("TEST", &ncfg)
		require_Error(t, err)

		ncfg = *cfg
		now := time.Now()
		ncfg.OptStartTime = &now
		_, err = js.UpdateConsumer("TEST", &ncfg)
		require_Error(t, err)

		ncfg = *cfg
		ncfg.AckPolicy = nats.AckAllPolicy
		_, err = js.UpdateConsumer("TEST", &ncfg)
		require_Error(t, err)

		ncfg = *cfg
		ncfg.ReplayPolicy = nats.ReplayOriginalPolicy
		_, err = js.UpdateConsumer("TEST", &ncfg)
		require_Error(t, err)

		ncfg = *cfg
		ncfg.Heartbeat = time.Second
		_, err = js.UpdateConsumer("TEST", &ncfg)
		require_Error(t, err)

		ncfg = *cfg
		ncfg.FlowControl = true
		_, err = js.UpdateConsumer("TEST", &ncfg)
		require_Error(t, err)

	}

	t.Run("Single", func(t *testing.T) { testConsumerUpdate(t, s, 1) })
	t.Run("Clustered", func(t *testing.T) { testConsumerUpdate(t, c.randomServer(), 2) })
}

func TestJetStreamClusterConsumerMaxDeliverUpdate(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{Name: "TEST", Subjects: []string{"foo"}, Replicas: 3})
	require_NoError(t, err)

	maxDeliver := 2
	_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{
		Durable:       "ard",
		AckPolicy:     nats.AckExplicitPolicy,
		FilterSubject: "foo",
		MaxDeliver:    maxDeliver,
	})
	require_NoError(t, err)

	sub, err := js.PullSubscribe("foo", "ard")
	require_NoError(t, err)

	checkMaxDeliver := func() {
		t.Helper()
		for i := 0; i <= maxDeliver; i++ {
			msgs, err := sub.Fetch(2, nats.MaxWait(100*time.Millisecond))
			if i < maxDeliver {
				require_NoError(t, err)
				require_Len(t, 1, len(msgs))
				_ = msgs[0].Nak()
			} else {
				require_Error(t, err, nats.ErrTimeout)
			}
		}
	}

	_, err = js.Publish("foo", []byte("Hello"))
	require_NoError(t, err)
	checkMaxDeliver()

	// update maxDeliver
	maxDeliver++
	_, err = js.UpdateConsumer("TEST", &nats.ConsumerConfig{
		Durable:       "ard",
		AckPolicy:     nats.AckExplicitPolicy,
		FilterSubject: "foo",
		MaxDeliver:    maxDeliver,
	})
	require_NoError(t, err)

	_, err = js.Publish("foo", []byte("Hello"))
	require_NoError(t, err)
	checkMaxDeliver()
}

func TestJetStreamClusterAccountReservations(t *testing.T) {
	c := createJetStreamClusterWithTemplate(t, jsClusterMaxBytesAccountLimitTempl, "C1", 3)
	defer c.shutdown()

	s := c.randomServer()
	nc, js := jsClientConnect(t, s)
	defer nc.Close()
	accMax := 3

	errResources := errors.New("nats: insufficient storage resources available")

	test := func(t *testing.T, replica int) {
		mb := int64((1+accMax)-replica) * 1024 * 1024 * 1024 // GB, corrected for replication factor
		_, err := js.AddStream(&nats.StreamConfig{Name: "S1", Subjects: []string{"s1"}, MaxBytes: mb, Replicas: replica})
		require_NoError(t, err)

		_, err = js.AddStream(&nats.StreamConfig{Name: "S2", Subjects: []string{"s2"}, MaxBytes: 1024, Replicas: replica})
		require_Error(t, err, errResources)

		_, err = js.UpdateStream(&nats.StreamConfig{Name: "S1", Subjects: []string{"s1"}, MaxBytes: mb / 2, Replicas: replica})
		require_NoError(t, err)

		_, err = js.AddStream(&nats.StreamConfig{Name: "S2", Subjects: []string{"s2"}, MaxBytes: mb / 2, Replicas: replica})
		require_NoError(t, err)

		_, err = js.AddStream(&nats.StreamConfig{Name: "S3", Subjects: []string{"s3"}, MaxBytes: 1024, Replicas: replica})
		require_Error(t, err, errResources)

		_, err = js.UpdateStream(&nats.StreamConfig{Name: "S2", Subjects: []string{"s2"}, MaxBytes: mb/2 + 1, Replicas: replica})
		require_Error(t, err, errResources)

		require_NoError(t, js.DeleteStream("S1"))
		require_NoError(t, js.DeleteStream("S2"))
	}
	test(t, 3)
	test(t, 1)
}

func TestJetStreamClusterConcurrentAccountLimits(t *testing.T) {
	c := createJetStreamClusterWithTemplate(t, jsClusterMaxBytesAccountLimitTempl, "cluster", 3)
	defer c.shutdown()

	startCh := make(chan bool)
	var wg sync.WaitGroup
	var swg sync.WaitGroup
	failCount := int32(0)

	start := func(name string) {
		wg.Add(1)
		defer wg.Done()

		s := c.randomServer()
		nc, js := jsClientConnect(t, s)
		defer nc.Close()

		swg.Done()
		<-startCh

		_, err := js.AddStream(&nats.StreamConfig{
			Name:     name,
			Replicas: 3,
			MaxBytes: 1024 * 1024 * 1024,
		})
		if err != nil {
			atomic.AddInt32(&failCount, 1)
			require_Equal(t, err.Error(), "nats: insufficient storage resources available")
		}
	}

	swg.Add(2)
	go start("foo")
	go start("bar")
	swg.Wait()
	// Now start both at same time.
	close(startCh)
	wg.Wait()
	require_True(t, failCount == 1)
}

func TestJetStreamClusterBalancedPlacement(t *testing.T) {
	c := createJetStreamClusterWithTemplate(t, jsClusterMaxBytesTempl, "CB", 5)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	// We have 10GB (2GB X 5) available.
	// Use MaxBytes for ease of test (used works too) and place 5 1GB streams with R=2.
	for i := 1; i <= 5; i++ {
		_, err := js.AddStream(&nats.StreamConfig{
			Name:     fmt.Sprintf("S-%d", i),
			Replicas: 2,
			MaxBytes: 1 * 1024 * 1024 * 1024,
		})
		require_NoError(t, err)
	}
	// Make sure the next one fails properly.
	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "FAIL",
		Replicas: 2,
		MaxBytes: 1 * 1024 * 1024 * 1024,
	})
	require_Contains(t, err.Error(), "no suitable peers for placement", "insufficient storage")
}

func TestJetStreamClusterConsumerPendingBug(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	nc2, js2 := jsClientConnect(t, c.randomServer())
	defer nc2.Close()

	_, err := js.AddStream(&nats.StreamConfig{Name: "foo", Replicas: 3})
	require_NoError(t, err)

	startCh, doneCh := make(chan bool), make(chan error)
	go func() {
		<-startCh
		_, err := js2.AddConsumer("foo", &nats.ConsumerConfig{
			Durable:        "dlc",
			FilterSubject:  "foo",
			DeliverSubject: "x",
		})
		doneCh <- err
	}()

	n := 10_000
	for i := 0; i < n; i++ {
		nc.Publish("foo", []byte("ok"))
		if i == 222 {
			startCh <- true
		}
	}
	// Wait for them to all be there.
	checkFor(t, 5*time.Second, 100*time.Millisecond, func() error {
		si, err := js.StreamInfo("foo")
		require_NoError(t, err)
		if si.State.Msgs != uint64(n) {
			return fmt.Errorf("Not received all messages")
		}
		return nil
	})

	select {
	case err := <-doneCh:
		if err != nil {
			t.Fatalf("Error creating consumer: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Timed out?")
	}
	checkFor(t, 5*time.Second, 100*time.Millisecond, func() error {
		ci, err := js.ConsumerInfo("foo", "dlc")
		require_NoError(t, err)
		if ci.NumPending != uint64(n) {
			return fmt.Errorf("Expected NumPending to be %d, got %d", n, ci.NumPending)
		}
		return nil
	})
}

func TestJetStreamClusterPullPerf(t *testing.T) {
	skip(t)

	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	js.AddStream(&nats.StreamConfig{Name: "f22"})
	defer js.DeleteStream("f22")

	n, msg := 1_000_000, []byte(strings.Repeat("A", 1000))
	for i := 0; i < n; i++ {
		js.PublishAsync("f22", msg)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(10 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	si, err := js.StreamInfo("f22")
	require_NoError(t, err)

	fmt.Printf("msgs: %d, total_bytes: %v\n", si.State.Msgs, friendlyBytes(int64(si.State.Bytes)))

	// OrderedConsumer - fastest push based.
	start := time.Now()
	received, done := 0, make(chan bool)
	_, err = js.Subscribe("f22", func(m *nats.Msg) {
		received++
		if received >= n {
			done <- true
		}
	}, nats.OrderedConsumer())
	require_NoError(t, err)

	// Wait to receive all messages.
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatalf("Did not receive all of our messages")
	}

	tt := time.Since(start)
	fmt.Printf("Took %v to receive %d msgs\n", tt, n)
	fmt.Printf("%.0f msgs/s\n", float64(n)/tt.Seconds())
	fmt.Printf("%.0f mb/s\n\n", float64(si.State.Bytes/(1024*1024))/tt.Seconds())

	// Now do pull based, this is custom for now.
	// Current nats.PullSubscribe maxes at about 1/2 the performance even with large batches.
	_, err = js.AddConsumer("f22", &nats.ConsumerConfig{
		Durable:       "dlc",
		AckPolicy:     nats.AckAllPolicy,
		MaxAckPending: 1000,
	})
	require_NoError(t, err)

	r := 0
	_, err = nc.Subscribe("xx", func(m *nats.Msg) {
		r++
		if r >= n {
			done <- true
		}
		if r%750 == 0 {
			m.AckSync()
		}
	})
	require_NoError(t, err)

	// Simulate an non-ending request.
	req := &JSApiConsumerGetNextRequest{Batch: n, Expires: 60 * time.Second}
	jreq, err := json.Marshal(req)
	require_NoError(t, err)

	start = time.Now()
	rsubj := fmt.Sprintf(JSApiRequestNextT, "f22", "dlc")
	err = nc.PublishRequest(rsubj, "xx", jreq)
	require_NoError(t, err)

	// Wait to receive all messages.
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatalf("Did not receive all of our messages")
	}

	tt = time.Since(start)
	fmt.Printf("Took %v to receive %d msgs\n", tt, n)
	fmt.Printf("%.0f msgs/s\n", float64(n)/tt.Seconds())
	fmt.Printf("%.0f mb/s\n\n", float64(si.State.Bytes/(1024*1024))/tt.Seconds())
}

// Test that we get the right signaling when a consumer leader change occurs for any pending requests.
func TestJetStreamClusterPullConsumerLeaderChange(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Replicas: 3,
		Subjects: []string{"foo"},
	})
	require_NoError(t, err)

	_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{
		Durable:       "dlc",
		AckPolicy:     nats.AckExplicitPolicy,
		FilterSubject: "foo",
	})
	require_NoError(t, err)

	rsubj := fmt.Sprintf(JSApiRequestNextT, "TEST", "dlc")
	sub, err := nc.SubscribeSync("reply")
	require_NoError(t, err)
	defer sub.Unsubscribe()

	drainSub := func() {
		t.Helper()
		for _, err := sub.NextMsg(0); err == nil; _, err = sub.NextMsg(0) {
		}
		checkSubsPending(t, sub, 0)
	}

	// Queue up a request that can live for a bit.
	req := &JSApiConsumerGetNextRequest{Expires: 2 * time.Second}
	jreq, err := json.Marshal(req)
	require_NoError(t, err)
	err = nc.PublishRequest(rsubj, "reply", jreq)
	require_NoError(t, err)
	// Make sure request is recorded and replicated.
	time.Sleep(100 * time.Millisecond)
	checkSubsPending(t, sub, 0)

	// Now have consumer leader change and make sure we get signaled that our request is not valid.
	_, err = nc.Request(fmt.Sprintf(JSApiConsumerLeaderStepDownT, "TEST", "dlc"), nil, time.Second)
	require_NoError(t, err)
	c.waitOnConsumerLeader("$G", "TEST", "dlc")
	checkSubsPending(t, sub, 1)
	m, err := sub.NextMsg(0)
	require_NoError(t, err)
	// Make sure this is an alert that tells us our request is no longer valid.
	if m.Header.Get("Status") != "409" {
		t.Fatalf("Expected a 409 status code, got %q", m.Header.Get("Status"))
	}
	checkSubsPending(t, sub, 0)

	// Add a few messages to the stream to fulfill a request.
	for i := 0; i < 10; i++ {
		_, err := js.Publish("foo", []byte("HELLO"))
		require_NoError(t, err)
	}
	req = &JSApiConsumerGetNextRequest{Batch: 10, Expires: 10 * time.Second}
	jreq, err = json.Marshal(req)
	require_NoError(t, err)
	err = nc.PublishRequest(rsubj, "reply", jreq)
	require_NoError(t, err)
	checkSubsPending(t, sub, 10)
	drainSub()

	// Now do a leader change again, make sure we do not get anything about that request.
	_, err = nc.Request(fmt.Sprintf(JSApiConsumerLeaderStepDownT, "TEST", "dlc"), nil, time.Second)
	require_NoError(t, err)
	c.waitOnConsumerLeader("$G", "TEST", "dlc")
	time.Sleep(100 * time.Millisecond)
	checkSubsPending(t, sub, 0)

	// Make sure we do not get anything if we expire, etc.
	req = &JSApiConsumerGetNextRequest{Batch: 10, Expires: 250 * time.Millisecond}
	jreq, err = json.Marshal(req)
	require_NoError(t, err)
	err = nc.PublishRequest(rsubj, "reply", jreq)
	require_NoError(t, err)
	// Let it expire.
	time.Sleep(350 * time.Millisecond)
	checkSubsPending(t, sub, 1)

	// Now do a leader change again, make sure we do not get anything about that request.
	_, err = nc.Request(fmt.Sprintf(JSApiConsumerLeaderStepDownT, "TEST", "dlc"), nil, time.Second)
	require_NoError(t, err)
	c.waitOnConsumerLeader("$G", "TEST", "dlc")
	checkSubsPending(t, sub, 1)
}

func TestJetStreamClusterEphemeralPullConsumerServerShutdown(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Replicas: 2,
		Subjects: []string{"foo"},
	})
	require_NoError(t, err)

	ci, err := js.AddConsumer("TEST", &nats.ConsumerConfig{
		AckPolicy:     nats.AckExplicitPolicy,
		FilterSubject: "foo",
	})
	require_NoError(t, err)

	rsubj := fmt.Sprintf(JSApiRequestNextT, "TEST", ci.Name)
	sub, err := nc.SubscribeSync("reply")
	require_NoError(t, err)
	defer sub.Unsubscribe()

	// Queue up a request that can live for a bit.
	req := &JSApiConsumerGetNextRequest{Expires: 2 * time.Second}
	jreq, err := json.Marshal(req)
	require_NoError(t, err)
	err = nc.PublishRequest(rsubj, "reply", jreq)
	require_NoError(t, err)
	// Make sure request is recorded and replicated.
	time.Sleep(100 * time.Millisecond)
	checkSubsPending(t, sub, 0)

	// Now shutdown the server where this ephemeral lives.
	c.consumerLeader("$G", "TEST", ci.Name).Shutdown()
	checkSubsPending(t, sub, 1)
	m, err := sub.NextMsg(0)
	require_NoError(t, err)
	// Make sure this is an alert that tells us our request is no longer valid.
	if m.Header.Get("Status") != "409" {
		t.Fatalf("Expected a 409 status code, got %q", m.Header.Get("Status"))
	}
}

func TestJetStreamClusterNAKBackoffs(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Replicas: 2,
		Subjects: []string{"foo"},
	})
	require_NoError(t, err)

	_, err = js.Publish("foo", []byte("NAK"))
	require_NoError(t, err)

	sub, err := js.SubscribeSync("foo", nats.Durable("dlc"), nats.AckWait(5*time.Second), nats.ManualAck())
	require_NoError(t, err)
	defer sub.Unsubscribe()

	checkSubsPending(t, sub, 1)
	m, err := sub.NextMsg(0)
	require_NoError(t, err)

	// Default nak will redeliver almost immediately.
	// We can now add a parse duration string after whitespace to the NAK proto.
	start := time.Now()
	dnak := []byte(fmt.Sprintf("%s 200ms", AckNak))
	m.Respond(dnak)
	checkSubsPending(t, sub, 1)
	elapsed := time.Since(start)
	if elapsed < 200*time.Millisecond {
		t.Fatalf("Took too short to redeliver, expected ~200ms but got %v", elapsed)
	}
	if elapsed > time.Second {
		t.Fatalf("Took too long to redeliver, expected ~200ms but got %v", elapsed)
	}

	// Now let's delay and make sure that is honored when a new consumer leader takes over.
	m, err = sub.NextMsg(0)
	require_NoError(t, err)
	dnak = []byte(fmt.Sprintf("%s 1s", AckNak))
	start = time.Now()
	m.Respond(dnak)
	// Wait for NAK state to propagate.
	time.Sleep(100 * time.Millisecond)
	// Ask leader to stepdown.
	_, err = nc.Request(fmt.Sprintf(JSApiConsumerLeaderStepDownT, "TEST", "dlc"), nil, time.Second)
	require_NoError(t, err)
	c.waitOnConsumerLeader("$G", "TEST", "dlc")
	checkSubsPending(t, sub, 1)
	elapsed = time.Since(start)
	if elapsed < time.Second {
		t.Fatalf("Took too short to redeliver, expected ~1s but got %v", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("Took too long to redeliver, expected ~1s but got %v", elapsed)
	}

	// Test json version.
	delay, err := json.Marshal(&ConsumerNakOptions{Delay: 20 * time.Millisecond})
	require_NoError(t, err)
	dnak = []byte(fmt.Sprintf("%s  %s", AckNak, delay))
	m, err = sub.NextMsg(0)
	require_NoError(t, err)
	start = time.Now()
	m.Respond(dnak)
	checkSubsPending(t, sub, 1)
	elapsed = time.Since(start)
	if elapsed < 20*time.Millisecond {
		t.Fatalf("Took too short to redeliver, expected ~20ms but got %v", elapsed)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("Took too long to redeliver, expected ~20ms but got %v", elapsed)
	}
}

func TestJetStreamClusterRedeliverBackoffs(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Replicas: 2,
		Subjects: []string{"foo", "bar"},
	})
	require_NoError(t, err)

	// Produce some messages on bar so that when we create the consumer
	// on "foo", we don't have a 1:1 between consumer/stream sequence.
	for i := 0; i < 10; i++ {
		js.Publish("bar", []byte("msg"))
	}

	// Test when BackOff is configured and AckWait and MaxDeliver are as well.
	// Currently the BackOff will override AckWait, but we want MaxDeliver to be set to be at least len(BackOff)+1.
	ccReq := &CreateConsumerRequest{
		Stream: "TEST",
		Config: ConsumerConfig{
			Durable:        "dlc",
			FilterSubject:  "foo",
			DeliverSubject: "x",
			AckPolicy:      AckExplicit,
			AckWait:        30 * time.Second,
			MaxDeliver:     2,
			BackOff:        []time.Duration{25 * time.Millisecond, 100 * time.Millisecond, 250 * time.Millisecond},
		},
	}
	req, err := json.Marshal(ccReq)
	require_NoError(t, err)
	resp, err := nc.Request(fmt.Sprintf(JSApiDurableCreateT, "TEST", "dlc"), req, time.Second)
	require_NoError(t, err)
	var ccResp JSApiConsumerCreateResponse
	err = json.Unmarshal(resp.Data, &ccResp)
	require_NoError(t, err)
	if ccResp.Error == nil || ccResp.Error.ErrCode != 10116 {
		t.Fatalf("Expected an error when MaxDeliver is <= len(BackOff), got %+v", ccResp.Error)
	}

	// Set MaxDeliver to 6.
	ccReq.Config.MaxDeliver = 6
	req, err = json.Marshal(ccReq)
	require_NoError(t, err)
	resp, err = nc.Request(fmt.Sprintf(JSApiDurableCreateT, "TEST", "dlc"), req, time.Second)
	require_NoError(t, err)
	ccResp.Error = nil
	err = json.Unmarshal(resp.Data, &ccResp)
	require_NoError(t, err)
	if ccResp.Error != nil {
		t.Fatalf("Unexpected error: %+v", ccResp.Error)
	}
	if cfg := ccResp.ConsumerInfo.Config; cfg.AckWait != 25*time.Millisecond || cfg.MaxDeliver != 6 {
		t.Fatalf("Expected AckWait to be first BackOff (25ms) and MaxDeliver set to 6, got %+v", cfg)
	}

	var received []time.Time
	var mu sync.Mutex

	sub, err := nc.Subscribe("x", func(m *nats.Msg) {
		mu.Lock()
		received = append(received, time.Now())
		mu.Unlock()
	})
	require_NoError(t, err)

	// Send a message.
	start := time.Now()
	_, err = js.Publish("foo", []byte("m22"))
	require_NoError(t, err)

	checkFor(t, 5*time.Second, 500*time.Millisecond, func() error {
		mu.Lock()
		nr := len(received)
		mu.Unlock()
		if nr >= 6 {
			return nil
		}
		return fmt.Errorf("Only seen %d of 6", nr)
	})
	sub.Unsubscribe()

	expected := ccReq.Config.BackOff
	// We expect the MaxDeliver to go until 6, so fill in two additional ones.
	expected = append(expected, 250*time.Millisecond, 250*time.Millisecond)
	for i, tr := range received[1:] {
		d := tr.Sub(start)
		// Adjust start for next calcs.
		start = start.Add(d)
		if d < expected[i] || d > expected[i]*2 {
			t.Fatalf("Timing is off for %d, expected ~%v, but got %v", i, expected[i], d)
		}
	}
}

func TestJetStreamClusterConsumerUpgrade(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	testUpdate := func(t *testing.T, s *Server) {
		nc, js := jsClientConnect(t, s)
		defer nc.Close()
		_, err := js.AddStream(&nats.StreamConfig{Name: "X"})
		require_NoError(t, err)
		_, err = js.Publish("X", []byte("OK"))
		require_NoError(t, err)
		// First create a consumer that is push based.
		_, err = js.AddConsumer("X", &nats.ConsumerConfig{Durable: "dlc", DeliverSubject: "Y"})
		require_NoError(t, err)
	}

	t.Run("Single", func(t *testing.T) { testUpdate(t, s) })
	t.Run("Clustered", func(t *testing.T) { testUpdate(t, c.randomServer()) })
}

func TestJetStreamClusterAddConsumerWithInfo(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	testConsInfo := func(t *testing.T, s *Server) {
		nc, js := jsClientConnect(t, s)
		defer nc.Close()

		_, err := js.AddStream(&nats.StreamConfig{
			Name:     "TEST",
			Subjects: []string{"foo"},
		})
		require_NoError(t, err)

		for i := 0; i < 10; i++ {
			_, err = js.Publish("foo", []byte("msg"))
			require_NoError(t, err)
		}

		for i := 0; i < 100; i++ {
			inbox := nats.NewInbox()
			sub := natsSubSync(t, nc, inbox)

			ci, err := js.AddConsumer("TEST", &nats.ConsumerConfig{
				DeliverSubject: inbox,
				DeliverPolicy:  nats.DeliverAllPolicy,
				FilterSubject:  "foo",
				AckPolicy:      nats.AckExplicitPolicy,
			})
			require_NoError(t, err)

			if ci.NumPending != 10 {
				t.Fatalf("Iter=%v - expected 10 messages pending on create, got %v", i+1, ci.NumPending)
			}
			js.DeleteConsumer("TEST", ci.Name)
			sub.Unsubscribe()
		}
	}

	t.Run("Single", func(t *testing.T) { testConsInfo(t, s) })
	t.Run("Clustered", func(t *testing.T) { testConsInfo(t, c.randomServer()) })
}

func TestJetStreamClusterStreamReplicaUpdates(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R7S", 7)
	defer c.shutdown()

	// Client based API
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	// Start out at R1
	cfg := &nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 1,
	}
	_, err := js.AddStream(cfg)
	require_NoError(t, err)

	numMsgs := 1000
	for i := 0; i < numMsgs; i++ {
		js.PublishAsync("foo", []byte("HELLO WORLD"))
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	updateReplicas := func(r int) {
		t.Helper()
		si, err := js.StreamInfo("TEST")
		require_NoError(t, err)
		leader := si.Cluster.Leader

		cfg.Replicas = r
		_, err = js.UpdateStream(cfg)
		require_NoError(t, err)
		c.waitOnStreamLeader("$G", "TEST")

		checkFor(t, 10*time.Second, 100*time.Millisecond, func() error {
			si, err = js.StreamInfo("TEST")
			require_NoError(t, err)
			if len(si.Cluster.Replicas) != r-1 {
				return fmt.Errorf("Expected %d replicas, got %d", r-1, len(si.Cluster.Replicas))
			}
			return nil
		})

		// Make sure we kept same leader.
		if si.Cluster.Leader != leader {
			t.Fatalf("Leader changed, expected %q got %q", leader, si.Cluster.Leader)
		}
		// Make sure all are current.
		for _, r := range si.Cluster.Replicas {
			c.waitOnStreamCurrent(c.serverByName(r.Name), "$G", "TEST")
		}
		// Check msgs.
		if si.State.Msgs != uint64(numMsgs) {
			t.Fatalf("Expected %d msgs, got %d", numMsgs, si.State.Msgs)
		}
		// Make sure we have the right number of HA Assets running on the leader.
		s := c.serverByName(leader)
		jsi, err := s.Jsz(nil)
		require_NoError(t, err)
		nha := 1 // meta always present.
		if len(si.Cluster.Replicas) > 0 {
			nha++
		}
		if nha != jsi.HAAssets {
			t.Fatalf("Expected %d HA asset(s), but got %d", nha, jsi.HAAssets)
		}
	}

	// Update from 1-3
	updateReplicas(3)
	// Update from 3-5
	updateReplicas(5)
	// Update from 5-3
	updateReplicas(3)
	// Update from 3-1
	updateReplicas(1)
}

func TestJetStreamClusterStreamAndConsumerScaleUpAndDown(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	// Client based API
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	// Start out at R3
	cfg := &nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 3,
	}
	_, err := js.AddStream(cfg)
	require_NoError(t, err)

	sub, err := js.SubscribeSync("foo", nats.Durable("cat"))
	require_NoError(t, err)

	numMsgs := 10
	for i := 0; i < numMsgs; i++ {
		_, err := js.Publish("foo", []byte("HELLO WORLD"))
		require_NoError(t, err)
	}
	checkSubsPending(t, sub, numMsgs)

	// Now ask leader to stepdown.
	rmsg, err := nc.Request(fmt.Sprintf(JSApiStreamLeaderStepDownT, "TEST"), nil, time.Second)
	require_NoError(t, err)

	var sdResp JSApiStreamLeaderStepDownResponse
	err = json.Unmarshal(rmsg.Data, &sdResp)
	require_NoError(t, err)

	if sdResp.Error != nil || !sdResp.Success {
		t.Fatalf("Unexpected error: %+v", sdResp.Error)
	}

	c.waitOnStreamLeader("$G", "TEST")

	updateReplicas := func(r int) {
		t.Helper()
		cfg.Replicas = r
		_, err := js.UpdateStream(cfg)
		require_NoError(t, err)
		c.waitOnStreamLeader("$G", "TEST")
		c.waitOnConsumerLeader("$G", "TEST", "cat")
		ci, err := js.ConsumerInfo("TEST", "cat")
		require_NoError(t, err)
		if ci.Cluster.Leader == _EMPTY_ {
			t.Fatalf("Expected a consumer leader but got none in consumer info")
		}
		if len(ci.Cluster.Replicas)+1 != r {
			t.Fatalf("Expected consumer info to have %d peers, got %d", r, len(ci.Cluster.Replicas)+1)
		}
	}

	// Capture leader, we want to make sure when we scale down this does not change.
	sl := c.streamLeader("$G", "TEST")

	// Scale down to 1.
	updateReplicas(1)

	if sl != c.streamLeader("$G", "TEST") {
		t.Fatalf("Expected same leader, but it changed")
	}

	// Make sure we can still send to the stream.
	for i := 0; i < numMsgs; i++ {
		_, err := js.Publish("foo", []byte("HELLO WORLD"))
		require_NoError(t, err)
	}

	si, err := js.StreamInfo("TEST")
	require_NoError(t, err)
	if si.State.Msgs != uint64(2*numMsgs) {
		t.Fatalf("Expected %d msgs, got %d", 3*numMsgs, si.State.Msgs)
	}

	checkSubsPending(t, sub, 2*numMsgs)

	// Now back up.
	updateReplicas(3)

	// Send more.
	for i := 0; i < numMsgs; i++ {
		_, err := js.Publish("foo", []byte("HELLO WORLD"))
		require_NoError(t, err)
	}

	si, err = js.StreamInfo("TEST")
	require_NoError(t, err)
	if si.State.Msgs != uint64(3*numMsgs) {
		t.Fatalf("Expected %d msgs, got %d", 3*numMsgs, si.State.Msgs)
	}

	checkSubsPending(t, sub, 3*numMsgs)

	// Make sure cluster replicas are current.
	checkFor(t, 5*time.Second, 100*time.Millisecond, func() error {
		si, err = js.StreamInfo("TEST")
		require_NoError(t, err)
		for _, r := range si.Cluster.Replicas {
			if !r.Current {
				return fmt.Errorf("Expected replica to be current: %+v", r)
			}
		}
		return nil
	})

	checkState := func(s *Server) {
		t.Helper()
		checkFor(t, 5*time.Second, 100*time.Millisecond, func() error {
			mset, err := s.GlobalAccount().lookupStream("TEST")
			require_NoError(t, err)
			state := mset.state()
			if state.Msgs != uint64(3*numMsgs) || state.FirstSeq != 1 || state.LastSeq != 30 || state.Bytes != 1320 {
				return fmt.Errorf("Wrong state: %+v for server: %v", state, s)
			}
			return nil
		})
	}

	// Now check each indidvidual stream on each server to make sure replication occurred.
	for _, s := range c.servers {
		checkState(s)
	}
}

func TestJetStreamClusterInterestRetentionWithFilteredConsumersExtra(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	subjectNameZero := "foo.bar"
	subjectNameOne := "foo.baz"

	// Client based API
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{Name: "TEST", Subjects: []string{"foo.*"}, Retention: nats.InterestPolicy, Replicas: 3})
	require_NoError(t, err)

	checkState := func(expected uint64) {
		t.Helper()
		checkFor(t, 5*time.Second, 100*time.Millisecond, func() error {
			si, err := js.StreamInfo("TEST")
			require_NoError(t, err)
			if si.State.Msgs != expected {
				return fmt.Errorf("Expected %d msgs, got %d", expected, si.State.Msgs)
			}
			return nil
		})
	}

	subZero, err := js.PullSubscribe(subjectNameZero, "dlc-0")
	require_NoError(t, err)

	subOne, err := js.PullSubscribe(subjectNameOne, "dlc-1")
	require_NoError(t, err)

	msg := []byte("FILTERED")
	// Now send a bunch of messages
	for i := 0; i < 1000; i++ {
		_, err = js.PublishAsync(subjectNameZero, msg)
		require_NoError(t, err)
		_, err = js.PublishAsync(subjectNameOne, msg)
		require_NoError(t, err)
	}

	// should be 2000 in total
	checkState(2000)

	// fetch and acknowledge, count records to ensure no errors acknowledging
	getAndAckBatch := func(sub *nats.Subscription) {
		t.Helper()
		successCounter := 0
		msgs, err := sub.Fetch(1000)
		require_NoError(t, err)

		for _, m := range msgs {
			err = m.AckSync()
			require_NoError(t, err)
			successCounter++
		}
		if successCounter != 1000 {
			t.Fatalf("Unexpected number of acknowledges %d for subscription %v", successCounter, sub)
		}
	}

	// fetch records subscription zero
	getAndAckBatch(subZero)
	// fetch records for subscription one
	getAndAckBatch(subOne)
	// Make sure stream is zero.
	checkState(0)
}

func TestJetStreamClusterStreamConsumersCount(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	sname := "TEST_STREAM_CONS_COUNT"
	_, err := js.AddStream(&nats.StreamConfig{Name: sname, Subjects: []string{"foo"}, Replicas: 3})
	require_NoError(t, err)

	// Create some R1 consumers
	for i := 0; i < 10; i++ {
		inbox := nats.NewInbox()
		natsSubSync(t, nc, inbox)
		_, err = js.AddConsumer(sname, &nats.ConsumerConfig{DeliverSubject: inbox})
		require_NoError(t, err)
	}

	// Now check that the consumer count in stream info/list is 10
	checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
		// Check stream info
		si, err := js.StreamInfo(sname)
		if err != nil {
			return fmt.Errorf("Error getting stream info: %v", err)
		}
		if n := si.State.Consumers; n != 10 {
			return fmt.Errorf("From StreamInfo, expecting 10 consumers, got %v", n)
		}

		// Now from stream list
		for si := range js.StreamsInfo() {
			if n := si.State.Consumers; n != 10 {
				return fmt.Errorf("From StreamsInfo, expecting 10 consumers, got %v", n)
			}
		}
		return nil
	})
}

func TestJetStreamClusterFilteredAndIdleConsumerNRGGrowth(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	sname := "TEST"
	_, err := js.AddStream(&nats.StreamConfig{Name: sname, Subjects: []string{"foo.*"}, Replicas: 3})
	require_NoError(t, err)

	sub, err := js.SubscribeSync("foo.baz", nats.Durable("dlc"))
	require_NoError(t, err)

	for i := 0; i < 10_000; i++ {
		js.PublishAsync("foo.bar", []byte("ok"))
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	checkSubsPending(t, sub, 0)

	// Grab consumer's underlying info and make sure NRG log not running away do to no-op skips on filtered consumer.
	// Need a non-leader for the consumer, they are only ones getting skip ops to keep delivered updated.
	cl := c.consumerLeader("$G", "TEST", "dlc")
	var s *Server
	for _, s = range c.servers {
		if s != cl {
			break
		}
	}

	mset, err := s.GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)
	o := mset.lookupConsumer("dlc")
	if o == nil {
		t.Fatalf("Error looking up consumer %q", "dlc")
	}

	// compactNumMin from monitorConsumer is 8192 atm.
	const compactNumMin = 8192
	if entries, _ := o.raftNode().Size(); entries > compactNumMin {
		t.Fatalf("Expected <= %d entries, got %d", compactNumMin, entries)
	}

	// Now make the consumer leader stepdown and make sure we have the proper snapshot.
	resp, err := nc.Request(fmt.Sprintf(JSApiConsumerLeaderStepDownT, "TEST", "dlc"), nil, time.Second)
	require_NoError(t, err)

	var cdResp JSApiConsumerLeaderStepDownResponse
	if err := json.Unmarshal(resp.Data, &cdResp); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if cdResp.Error != nil {
		t.Fatalf("Unexpected error: %+v", cdResp.Error)
	}

	c.waitOnConsumerLeader("$G", "TEST", "dlc")
}

func TestJetStreamClusterMirrorOrSourceNotActiveReporting(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{Name: "TEST", Subjects: []string{"foo"}, Replicas: 3})
	require_NoError(t, err)

	si, err := js.AddStream(&nats.StreamConfig{
		Name:   "M",
		Mirror: &nats.StreamSource{Name: "TEST"},
	})
	require_NoError(t, err)

	// We would previous calculate a large number if we actually never heard from the peer yet.
	// We want to make sure if we have never heard from the other side report -1 as Active.
	// It is possible if testing infra is slow that this could be legit, but should be pretty small.
	if si.Mirror.Active != -1 && si.Mirror.Active > 10*time.Millisecond {
		t.Fatalf("Expected an Active of -1, but got %v", si.Mirror.Active)
	}
}

func TestJetStreamClusterStreamAdvisories(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	checkAdv := func(t *testing.T, sub *nats.Subscription, expectedPrefixes ...string) {
		t.Helper()
		seen := make([]bool, len(expectedPrefixes))
		for i := 0; i < len(expectedPrefixes); i++ {
			msg := natsNexMsg(t, sub, time.Second)
			var gotOne bool
			for j, pfx := range expectedPrefixes {
				if !seen[j] && strings.HasPrefix(msg.Subject, pfx) {
					seen[j] = true
					gotOne = true
					break
				}
			}
			if !gotOne {
				t.Fatalf("Expected one of prefixes %q, got %q", expectedPrefixes, msg.Subject)
			}
		}
	}

	// Used to keep stream names pseudo unique. t.Name() has slashes in it which caused problems.
	var testN int

	checkAdvisories := func(t *testing.T, s *Server, replicas int) {

		nc, js := jsClientConnect(t, s)
		defer nc.Close()

		testN++
		streamName := "TEST_ADVISORIES_" + fmt.Sprintf("%d", testN)

		sub := natsSubSync(t, nc, "$JS.EVENT.ADVISORY.STREAM.*."+streamName)

		si, err := js.AddStream(&nats.StreamConfig{
			Name:     streamName,
			Storage:  nats.FileStorage,
			Replicas: replicas,
		})
		require_NoError(t, err)
		advisories := []string{JSAdvisoryStreamCreatedPre}
		if replicas > 1 {
			advisories = append(advisories, JSAdvisoryStreamLeaderElectedPre)
		}
		checkAdv(t, sub, advisories...)

		si.Config.MaxMsgs = 1000
		_, err = js.UpdateStream(&si.Config)
		require_NoError(t, err)
		checkAdv(t, sub, JSAdvisoryStreamUpdatedPre)

		snapreq := &JSApiStreamSnapshotRequest{
			DeliverSubject: nats.NewInbox(),
			ChunkSize:      512,
		}
		var snapshot []byte
		done := make(chan bool)
		nc.Subscribe(snapreq.DeliverSubject, func(m *nats.Msg) {
			// EOF
			if len(m.Data) == 0 {
				done <- true
				return
			}
			// Could be writing to a file here too.
			snapshot = append(snapshot, m.Data...)
			// Flow ack
			m.Respond(nil)
		})

		req, _ := json.Marshal(snapreq)
		rmsg, err := nc.Request(fmt.Sprintf(JSApiStreamSnapshotT, streamName), req, time.Second)
		if err != nil {
			t.Fatalf("Unexpected error on snapshot request: %v", err)
		}

		var snapresp JSApiStreamSnapshotResponse
		json.Unmarshal(rmsg.Data, &snapresp)
		if snapresp.Error != nil {
			t.Fatalf("Did not get correct error response: %+v", snapresp.Error)
		}

		// Wait to receive the snapshot.
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("Did not receive our snapshot in time")
		}

		checkAdv(t, sub, JSAdvisoryStreamSnapshotCreatePre)
		checkAdv(t, sub, JSAdvisoryStreamSnapshotCompletePre)

		err = js.DeleteStream(streamName)
		require_NoError(t, err)
		checkAdv(t, sub, JSAdvisoryStreamDeletedPre)

		state := *snapresp.State
		config := *snapresp.Config
		resreq := &JSApiStreamRestoreRequest{
			Config: config,
			State:  state,
		}
		req, _ = json.Marshal(resreq)
		rmsg, err = nc.Request(fmt.Sprintf(JSApiStreamRestoreT, streamName), req, 5*time.Second)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		var resresp JSApiStreamRestoreResponse
		json.Unmarshal(rmsg.Data, &resresp)
		if resresp.Error != nil {
			t.Fatalf("Got an unexpected error response: %+v", resresp.Error)
		}

		// Send our snapshot back in to restore the stream.
		// Can be any size message.
		var chunk [1024]byte
		for r := bytes.NewReader(snapshot); ; {
			n, err := r.Read(chunk[:])
			if err != nil {
				break
			}
			nc.Request(resresp.DeliverSubject, chunk[:n], time.Second)
		}
		rmsg, err = nc.Request(resresp.DeliverSubject, nil, time.Second)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		resresp.Error = nil
		json.Unmarshal(rmsg.Data, &resresp)
		if resresp.Error != nil {
			t.Fatalf("Got an unexpected error response: %+v", resresp.Error)
		}

		checkAdv(t, sub, JSAdvisoryStreamRestoreCreatePre)
		// At this point, the stream_created advisory may be sent before
		// or after the restore_complete advisory because they are sent
		// using different "send queues". That is, the restore uses the
		// server's event queue while the stream_created is sent from
		// the stream's own send queue.
		advisories = append(advisories, JSAdvisoryStreamRestoreCompletePre)
		checkAdv(t, sub, advisories...)
	}

	t.Run("Single", func(t *testing.T) { checkAdvisories(t, s, 1) })
	t.Run("Clustered_R1", func(t *testing.T) { checkAdvisories(t, c.randomServer(), 1) })
	t.Run("Clustered_R3", func(t *testing.T) { checkAdvisories(t, c.randomServer(), 3) })
}

// If the config files have duplicate routes this can have the metagroup estimate a size for the system
// which prevents reaching quorum and electing a meta-leader.
func TestJetStreamClusterDuplicateRoutesDisruptJetStreamMetaGroup(t *testing.T) {
	tmpl := `
	listen: 127.0.0.1:-1
	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

	cluster {
		name: RR
		listen: 127.0.0.1:%d
		routes = [
			nats-route://127.0.0.1:%d
			nats-route://127.0.0.1:%d
			nats-route://127.0.0.1:%d
			# These will be dupes
			nats-route://127.0.0.1:%d
			nats-route://127.0.0.1:%d
			nats-route://127.0.0.1:%d
		]
	}

	# For access to system account.
	accounts { $SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] } }
`

	c := &cluster{servers: make([]*Server, 0, 3), opts: make([]*Options, 0, 3), name: "RR", t: t}

	rports := []int{22208, 22209, 22210}
	for i, p := range rports {
		sname, sd := fmt.Sprintf("S%d", i+1), t.TempDir()
		cf := fmt.Sprintf(tmpl, sname, sd, p, rports[0], rports[1], rports[2], rports[0], rports[1], rports[2])
		s, o := RunServerWithConfig(createConfFile(t, []byte(cf)))
		c.servers, c.opts = append(c.servers, s), append(c.opts, o)
	}
	defer c.shutdown()

	checkClusterFormed(t, c.servers...)
	c.waitOnClusterReady()
}

func TestJetStreamClusterDuplicateMsgIdsOnCatchupAndLeaderTakeover(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Replicas: 3,
	})
	require_NoError(t, err)

	// Shutdown a non-leader.
	nc.Close()
	sr := c.randomNonStreamLeader("$G", "TEST")
	sr.Shutdown()

	nc, js = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	m := nats.NewMsg("TEST")
	m.Data = []byte("OK")

	n := 10
	for i := 0; i < n; i++ {
		m.Header.Set(JSMsgId, strconv.Itoa(i))
		_, err := js.PublishMsg(m)
		require_NoError(t, err)
	}

	m.Header.Set(JSMsgId, "8")
	pa, err := js.PublishMsg(m)
	require_NoError(t, err)
	if !pa.Duplicate {
		t.Fatalf("Expected msg to be a duplicate")
	}

	// Now force a snapshot, want to test catchup above RAFT layer.
	sl := c.streamLeader("$G", "TEST")
	mset, err := sl.GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)
	if node := mset.raftNode(); node == nil {
		t.Fatalf("Could not get stream group name")
	} else if err := node.InstallSnapshot(mset.stateSnapshot()); err != nil {
		t.Fatalf("Error installing snapshot: %v", err)
	}

	// Now restart
	sr = c.restartServer(sr)
	c.waitOnStreamCurrent(sr, "$G", "TEST")
	c.waitOnStreamLeader("$G", "TEST")

	// Now make them the leader.
	for sr != c.streamLeader("$G", "TEST") {
		nc.Request(fmt.Sprintf(JSApiStreamLeaderStepDownT, "TEST"), nil, time.Second)
		c.waitOnStreamLeader("$G", "TEST")
	}

	// Make sure this gets rejected.
	pa, err = js.PublishMsg(m)
	require_NoError(t, err)
	if !pa.Duplicate {
		t.Fatalf("Expected msg to be a duplicate")
	}
}

func TestJetStreamClusterConsumerLeaderChangeDeadlock(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	// Create a stream and durable with ack explicit
	_, err := js.AddStream(&nats.StreamConfig{Name: "test", Subjects: []string{"foo"}, Replicas: 3})
	require_NoError(t, err)
	_, err = js.AddConsumer("test", &nats.ConsumerConfig{
		Durable:        "test",
		DeliverSubject: "bar",
		AckPolicy:      nats.AckExplicitPolicy,
		AckWait:        250 * time.Millisecond,
	})
	require_NoError(t, err)

	// Wait for a leader
	c.waitOnConsumerLeader("$G", "test", "test")
	cl := c.consumerLeader("$G", "test", "test")

	// Publish a message
	_, err = js.Publish("foo", []byte("msg"))
	require_NoError(t, err)

	// Create nats consumer on "bar" and don't ack it
	sub := natsSubSync(t, nc, "bar")
	natsNexMsg(t, sub, time.Second)
	// Wait for redeliveries, to make sure it is in the redelivery map
	natsNexMsg(t, sub, time.Second)
	natsNexMsg(t, sub, time.Second)

	mset, err := cl.GlobalAccount().lookupStream("test")
	require_NoError(t, err)
	require_True(t, mset != nil)

	// There are parts in the code (for instance when signaling to consumers
	// that there are new messages) where we get the mset lock and iterate
	// over the consumers and get consumer lock. We are going to do that
	// in a go routine while we send a consumer step down request from
	// another go routine. We will watch for possible deadlock and if
	// found report it.
	ch := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		for {
			mset.mu.Lock()
			for _, o := range mset.consumers {
				o.mu.Lock()
				time.Sleep(time.Duration(rand.Intn(10)) * time.Millisecond)
				o.mu.Unlock()
			}
			mset.mu.Unlock()
			select {
			case <-ch:
				return
			default:
			}
		}
	}()

	// Now cause a leader changes
	for i := 0; i < 5; i++ {
		m, err := nc.Request("$JS.API.CONSUMER.LEADER.STEPDOWN.test.test", nil, 2*time.Second)
		// Ignore error here and check for deadlock below
		if err != nil {
			break
		}
		// if there is a message, check that it is success
		var resp JSApiConsumerLeaderStepDownResponse
		err = json.Unmarshal(m.Data, &resp)
		require_NoError(t, err)
		require_True(t, resp.Success)
		c.waitOnConsumerLeader("$G", "test", "test")
	}

	close(ch)
	select {
	case <-doneCh:
		// OK!
	case <-time.After(2 * time.Second):
		buf := make([]byte, 1000000)
		n := runtime.Stack(buf, true)
		t.Fatalf("Suspected deadlock, printing current stack. The test suite may timeout and will also dump the stack\n%s\n", buf[:n])
	}
}

// We were compacting to keep the raft log manageable but not snapshotting, which meant that restarted
// servers could complain about no snapshot and could not sync after that condition.
// Changes also address https://github.com/nats-io/nats-server/issues/2936
func TestJetStreamClusterMemoryConsumerCompactVsSnapshot(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	// Create a stream and durable with ack explicit
	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "test",
		Storage:  nats.MemoryStorage,
		Replicas: 3,
	})
	require_NoError(t, err)

	_, err = js.AddConsumer("test", &nats.ConsumerConfig{
		Durable:   "d",
		AckPolicy: nats.AckExplicitPolicy,
	})
	require_NoError(t, err)

	// Bring a non-leader down.
	s := c.randomNonConsumerLeader("$G", "test", "d")
	s.Shutdown()

	// In case that was also mete or stream leader.
	c.waitOnLeader()
	c.waitOnStreamLeader("$G", "test")
	// In case we were connected there.
	nc.Close()
	nc, js = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	// Generate some state.
	for i := 0; i < 2000; i++ {
		_, err := js.PublishAsync("test", nil)
		require_NoError(t, err)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	sub, err := js.PullSubscribe("test", "d")
	require_NoError(t, err)

	for i := 0; i < 2; i++ {
		for _, m := range fetchMsgs(t, sub, 1000, 5*time.Second) {
			m.AckSync()
		}
	}

	// Restart our downed server.
	s = c.restartServer(s)
	c.checkClusterFormed()
	c.waitOnServerCurrent(s)

	checkFor(t, 5*time.Second, 100*time.Millisecond, func() error {
		ci, err := js.ConsumerInfo("test", "d")
		require_NoError(t, err)
		for _, r := range ci.Cluster.Replicas {
			if !r.Current || r.Lag != 0 {
				return fmt.Errorf("Replica not current: %+v", r)
			}
		}
		return nil
	})
}

func TestJetStreamClusterMemoryConsumerInterestRetention(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:      "test",
		Storage:   nats.MemoryStorage,
		Retention: nats.InterestPolicy,
		Replicas:  3,
	})
	require_NoError(t, err)

	sub, err := js.SubscribeSync("test", nats.Durable("dlc"))
	require_NoError(t, err)

	for i := 0; i < 1000; i++ {
		_, err := js.PublishAsync("test", nil)
		require_NoError(t, err)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	toAck := 100
	for i := 0; i < toAck; i++ {
		m, err := sub.NextMsg(time.Second)
		require_NoError(t, err)
		m.AckSync()
	}

	checkFor(t, time.Second, 15*time.Millisecond, func() error {
		si, err := js.StreamInfo("test")
		if err != nil {
			return err
		}
		if n := si.State.Msgs; n != 900 {
			return fmt.Errorf("Waiting for msgs count to be 900, got %v", n)
		}
		return nil
	})

	si, err := js.StreamInfo("test")
	require_NoError(t, err)

	ci, err := sub.ConsumerInfo()
	require_NoError(t, err)

	// Make sure acks are not only replicated but processed in a way to remove messages from the replica streams.
	_, err = nc.Request(fmt.Sprintf(JSApiStreamLeaderStepDownT, "test"), nil, time.Second)
	require_NoError(t, err)
	c.waitOnStreamLeader("$G", "test")

	_, err = nc.Request(fmt.Sprintf(JSApiConsumerLeaderStepDownT, "test", "dlc"), nil, time.Second)
	require_NoError(t, err)
	c.waitOnConsumerLeader("$G", "test", "dlc")

	nsi, err := js.StreamInfo("test")
	require_NoError(t, err)
	if !reflect.DeepEqual(nsi.State, si.State) {
		t.Fatalf("Stream states do not match: %+v vs %+v", si.State, nsi.State)
	}

	nci, err := sub.ConsumerInfo()
	require_NoError(t, err)

	// Last may be skewed a very small amount.
	ci.AckFloor.Last, nci.AckFloor.Last = nil, nil
	if nci.AckFloor != ci.AckFloor {
		t.Fatalf("Consumer AckFloors are not the same: %+v vs %+v", ci.AckFloor, nci.AckFloor)
	}
}

func TestJetStreamClusterDeleteAndRestoreAndRestart(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{Name: "TEST"})
	require_NoError(t, err)

	for i := 0; i < 10; i++ {
		_, err := js.Publish("TEST", []byte("OK"))
		require_NoError(t, err)
	}
	_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{Durable: "dlc", AckPolicy: nats.AckExplicitPolicy})
	require_NoError(t, err)

	require_NoError(t, js.DeleteConsumer("TEST", "dlc"))
	require_NoError(t, js.DeleteStream("TEST"))

	_, err = js.AddStream(&nats.StreamConfig{Name: "TEST"})
	require_NoError(t, err)

	for i := 0; i < 22; i++ {
		_, err := js.Publish("TEST", []byte("OK"))
		require_NoError(t, err)
	}

	sub, err := js.SubscribeSync("TEST", nats.Durable("dlc"), nats.Description("SECOND"))
	require_NoError(t, err)

	for i := 0; i < 5; i++ {
		m, err := sub.NextMsg(time.Second)
		require_NoError(t, err)
		m.AckSync()
	}

	// Now restart.
	sl := c.streamLeader("$G", "TEST")
	sl.Shutdown()
	sl = c.restartServer(sl)
	c.waitOnStreamLeader("$G", "TEST")
	c.waitOnConsumerLeader("$G", "TEST", "dlc")

	nc, js = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	checkFor(t, 2*time.Second, 100*time.Millisecond, func() error {
		si, err := js.StreamInfo("TEST")
		require_NoError(t, err)
		if si.State.Msgs != 22 {
			return fmt.Errorf("State is not correct after restart, expected 22 msgs, got %d", si.State.Msgs)
		}
		return nil
	})

	ci, err := js.ConsumerInfo("TEST", "dlc")
	require_NoError(t, err)

	if ci.AckFloor.Consumer != 5 {
		t.Fatalf("Bad ack floor: %+v", ci.AckFloor)
	}

	// Now delete and make sure consumer does not come back.
	// First add a delete something else.
	_, err = js.AddStream(&nats.StreamConfig{Name: "TEST2"})
	require_NoError(t, err)
	require_NoError(t, js.DeleteStream("TEST2"))
	// Now the consumer.
	require_NoError(t, js.DeleteConsumer("TEST", "dlc"))

	sl.Shutdown()
	c.restartServer(sl)
	c.waitOnStreamLeader("$G", "TEST")

	// In rare circumstances this could be recovered and then quickly deleted.
	checkFor(t, 2*time.Second, 100*time.Millisecond, func() error {
		if _, err := js.ConsumerInfo("TEST", "dlc"); err == nil {
			return fmt.Errorf("Not cleaned up yet")
		}
		return nil
	})
}

func TestJetStreamClusterMirrorSourceLoop(t *testing.T) {
	test := func(t *testing.T, s *Server, replicas int) {
		nc, js := jsClientConnect(t, s)
		defer nc.Close()
		// Create a source/mirror loop
		_, err := js.AddStream(&nats.StreamConfig{
			Name:     "1",
			Subjects: []string{"foo", "bar"},
			Replicas: replicas,
			Sources:  []*nats.StreamSource{{Name: "DECOY"}, {Name: "2"}},
		})
		require_NoError(t, err)
		_, err = js.AddStream(&nats.StreamConfig{
			Name:     "DECOY",
			Subjects: []string{"baz"},
			Replicas: replicas,
			Sources:  []*nats.StreamSource{{Name: "NOTTHERE"}},
		})
		require_NoError(t, err)
		_, err = js.AddStream(&nats.StreamConfig{
			Name:     "2",
			Replicas: replicas,
			Sources:  []*nats.StreamSource{{Name: "3"}},
		})
		require_NoError(t, err)
		_, err = js.AddStream(&nats.StreamConfig{
			Name:     "3",
			Replicas: replicas,
			Sources:  []*nats.StreamSource{{Name: "1"}},
		})
		require_Error(t, err)
		require_Equal(t, err.Error(), "nats: detected cycle")
	}

	t.Run("Single", func(t *testing.T) {
		s := RunBasicJetStreamServer(t)
		defer s.Shutdown()
		test(t, s, 1)
	})
	t.Run("Clustered", func(t *testing.T) {
		c := createJetStreamClusterExplicit(t, "JSC", 5)
		defer c.shutdown()
		test(t, c.randomServer(), 2)
	})
}

func TestJetStreamClusterMirrorDeDupWindow(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	si, err := js.AddStream(&nats.StreamConfig{
		Name:     "S",
		Subjects: []string{"foo"},
		Replicas: 3,
	})
	require_NoError(t, err)
	require_True(t, si.Cluster != nil)
	require_True(t, si.Config.Replicas == 3)
	require_True(t, len(si.Cluster.Replicas) == 2)

	send := func(count int) {
		t.Helper()
		for i := 0; i < count; i++ {
			_, err := js.Publish("foo", []byte("msg"))
			require_NoError(t, err)
		}
	}

	// Send 100 messages
	send(100)

	// Now create a valid one.
	si, err = js.AddStream(&nats.StreamConfig{
		Name:     "M",
		Replicas: 3,
		Mirror:   &nats.StreamSource{Name: "S"},
	})
	require_NoError(t, err)
	require_True(t, si.Cluster != nil)
	require_True(t, si.Config.Replicas == 3)
	require_True(t, len(si.Cluster.Replicas) == 2)

	check := func(expected int) {
		t.Helper()
		// Wait for all messages to be in mirror
		checkFor(t, 15*time.Second, 50*time.Millisecond, func() error {
			si, err := js.StreamInfo("M")
			if err != nil {
				return err
			}
			if n := si.State.Msgs; int(n) != expected {
				return fmt.Errorf("Expected %v msgs, got %v", expected, n)
			}
			return nil
		})
	}
	check(100)

	// Restart cluster
	nc.Close()
	c.stopAll()
	c.restartAll()
	c.waitOnLeader()
	c.waitOnStreamLeader(globalAccountName, "S")
	c.waitOnStreamLeader(globalAccountName, "M")

	nc, js = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	si, err = js.StreamInfo("M")
	require_NoError(t, err)
	require_True(t, si.Cluster != nil)
	require_True(t, si.Config.Replicas == 3)
	require_True(t, len(si.Cluster.Replicas) == 2)

	// Send 100 messages
	send(100)
	check(200)
}

func TestJetStreamClusterNewHealthz(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "R1",
		Subjects: []string{"foo"},
		Replicas: 1,
	})
	require_NoError(t, err)

	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "R3",
		Subjects: []string{"bar"},
		Replicas: 3,
	})
	require_NoError(t, err)

	// Create subscribers (durable and ephemeral for each)
	fsube, err := js.SubscribeSync("foo")
	require_NoError(t, err)
	fsubd, err := js.SubscribeSync("foo", nats.Durable("d"))
	require_NoError(t, err)

	_, err = js.SubscribeSync("bar")
	require_NoError(t, err)
	bsubd, err := js.SubscribeSync("bar", nats.Durable("d"))
	require_NoError(t, err)

	for i := 0; i < 20; i++ {
		_, err = js.Publish("foo", []byte("foo"))
		require_NoError(t, err)
	}
	checkSubsPending(t, fsube, 20)
	checkSubsPending(t, fsubd, 20)

	// Select the server where we know the R1 stream is running.
	sl := c.streamLeader("$G", "R1")
	sl.Shutdown()

	// Do same on R3 so that sl has to recover some things before healthz should be good.
	c.waitOnStreamLeader("$G", "R3")

	for i := 0; i < 10; i++ {
		_, err = js.Publish("bar", []byte("bar"))
		require_NoError(t, err)
	}
	// Ephemeral is skipped, might have been on the downed server.
	checkSubsPending(t, bsubd, 10)

	sl = c.restartServer(sl)
	c.waitOnServerHealthz(sl)
}

func TestJetStreamClusterConsumerOverrides(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 3,
	})
	require_NoError(t, err)

	// Test replica override.
	// Make sure we can not go "wider" than the parent stream.
	ccReq := CreateConsumerRequest{
		Stream: "TEST",
		Config: ConsumerConfig{
			Durable:   "d",
			AckPolicy: AckExplicit,
			Replicas:  5,
		},
	}
	req, err := json.Marshal(ccReq)
	require_NoError(t, err)

	ci, err := nc.Request(fmt.Sprintf(JSApiDurableCreateT, "TEST", "d"), req, time.Second)
	require_NoError(t, err)

	var resp JSApiConsumerCreateResponse
	err = json.Unmarshal(ci.Data, &resp)
	require_NoError(t, err)

	if resp.Error == nil || !IsNatsErr(resp.Error, JSConsumerReplicasExceedsStream) {
		t.Fatalf("Expected an error when replicas > parent stream, got %+v", resp.Error)
	}

	// Durables inherit the replica count from the stream, so make sure we can override that.
	ccReq.Config.Replicas = 1
	req, err = json.Marshal(ccReq)
	require_NoError(t, err)

	ci, err = nc.Request(fmt.Sprintf(JSApiDurableCreateT, "TEST", "d"), req, time.Second)
	require_NoError(t, err)

	resp.Error = nil
	err = json.Unmarshal(ci.Data, &resp)
	require_NoError(t, err)
	require_True(t, resp.Error == nil)

	checkCount := func(durable string, expected int) {
		t.Helper()
		count := 0
		for _, s := range c.servers {
			if mset, err := s.GlobalAccount().lookupStream("TEST"); err == nil {
				if o := mset.lookupConsumer(durable); o != nil {
					count++
				}
			}
		}
		if count != expected {
			t.Fatalf("Expected %d consumers in cluster, got %d", expected, count)
		}
	}
	checkCount("d", 1)

	// Now override storage and force storage to memory based.
	ccReq.Config.MemoryStorage = true
	ccReq.Config.Durable = "m"
	ccReq.Config.Replicas = 3

	req, err = json.Marshal(ccReq)
	require_NoError(t, err)

	ci, err = nc.Request(fmt.Sprintf(JSApiDurableCreateT, "TEST", "m"), req, time.Second)
	require_NoError(t, err)

	resp.Error = nil
	err = json.Unmarshal(ci.Data, &resp)
	require_NoError(t, err)
	require_True(t, resp.Error == nil)

	checkCount("m", 3)

	// Make sure memory setting is for both consumer raft log and consumer store.
	s := c.consumerLeader("$G", "TEST", "m")
	require_True(t, s != nil)
	mset, err := s.GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)
	o := mset.lookupConsumer("m")
	require_True(t, o != nil)

	st := o.store.Type()
	n := o.raftNode()
	require_True(t, n != nil)
	rn := n.(*raft)
	rn.RLock()
	wal := rn.wal
	rn.RUnlock()
	require_True(t, wal.Type() == MemoryStorage)
	require_True(t, st == MemoryStorage)

	// Now make sure we account properly for the consumers.
	// Add in normal here first.
	_, err = js.SubscribeSync("foo", nats.Durable("d22"))
	require_NoError(t, err)

	si, err := js.StreamInfo("TEST")
	require_NoError(t, err)
	require_True(t, si.State.Consumers == 3)

	err = js.DeleteConsumer("TEST", "d")
	require_NoError(t, err)

	// Also make sure the stream leader direct store reports same with mixed and matched.
	s = c.streamLeader("$G", "TEST")
	require_True(t, s != nil)
	mset, err = s.GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)

	state := mset.Store().State()
	require_True(t, state.Consumers == 2)

	// Fast state version as well.
	fstate := mset.stateWithDetail(false)
	require_True(t, fstate.Consumers == 2)

	// Make sure delete accounting works too.
	err = js.DeleteConsumer("TEST", "m")
	require_NoError(t, err)

	state = mset.Store().State()
	require_True(t, state.Consumers == 1)

	// Fast state version as well.
	fstate = mset.stateWithDetail(false)
	require_True(t, fstate.Consumers == 1)
}

func TestJetStreamClusterStreamRepublish(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	// Do by hand for now.
	cfg := &StreamConfig{
		Name:     "RP",
		Storage:  MemoryStorage,
		Subjects: []string{"foo", "bar", "baz"},
		Replicas: 3,
		RePublish: &RePublish{
			Source:      ">",
			Destination: "RP.>",
		},
	}

	addStream(t, nc, cfg)

	sub, err := nc.SubscribeSync("RP.>")
	require_NoError(t, err)

	msg, toSend := []byte("OK TO REPUBLISH?"), 100
	for i := 0; i < toSend; i++ {
		_, err = js.PublishAsync("foo", msg)
		require_NoError(t, err)
		_, err = js.PublishAsync("bar", msg)
		require_NoError(t, err)
		_, err = js.PublishAsync("baz", msg)
		require_NoError(t, err)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	checkSubsPending(t, sub, toSend*3)

	lseq := map[string]int{
		"foo": 0,
		"bar": 0,
		"baz": 0,
	}

	for i := 1; i <= toSend; i++ {
		m, err := sub.NextMsg(time.Second)
		require_NoError(t, err)
		// Grab info from Header
		require_True(t, m.Header.Get(JSStream) == "RP")
		// Make sure sequence is correct.
		seq, err := strconv.Atoi(m.Header.Get(JSSequence))
		require_NoError(t, err)
		require_True(t, seq == i)
		// Make sure timestamp is correct
		ts, err := time.Parse(time.RFC3339Nano, m.Header.Get(JSTimeStamp))
		require_NoError(t, err)
		origMsg, err := js.GetMsg("RP", uint64(seq))
		require_NoError(t, err)
		require_True(t, ts == origMsg.Time)
		// Make sure last sequence matches last seq we received on this subject.
		last, err := strconv.Atoi(m.Header.Get(JSLastSequence))
		require_NoError(t, err)
		require_True(t, last == lseq[m.Subject])
		lseq[m.Subject] = seq
	}
}

func TestJetStreamClusterConsumerDeliverNewNotConsumingBeforeStepDownOrRestart(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 3,
	})
	require_NoError(t, err)

	inbox := nats.NewInbox()
	_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{
		DeliverSubject: inbox,
		Durable:        "dur",
		AckPolicy:      nats.AckExplicitPolicy,
		DeliverPolicy:  nats.DeliverNewPolicy,
		FilterSubject:  "foo",
	})
	require_NoError(t, err)

	c.waitOnConsumerLeader(globalAccountName, "TEST", "dur")

	for i := 0; i < 10; i++ {
		sendStreamMsg(t, nc, "foo", "msg")
	}

	checkCount := func(expected int) {
		t.Helper()
		checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
			ci, err := js.ConsumerInfo("TEST", "dur")
			if err != nil {
				return err
			}
			if n := int(ci.NumPending); n != expected {
				return fmt.Errorf("Expected %v pending, got %v", expected, n)
			}
			return nil
		})
	}
	checkCount(10)

	resp, err := nc.Request(fmt.Sprintf(JSApiConsumerLeaderStepDownT, "TEST", "dur"), nil, time.Second)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	var cdResp JSApiConsumerLeaderStepDownResponse
	if err := json.Unmarshal(resp.Data, &cdResp); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if cdResp.Error != nil {
		t.Fatalf("Unexpected error: %+v", cdResp.Error)
	}

	c.waitOnConsumerLeader(globalAccountName, "TEST", "dur")
	checkCount(10)

	// Check also servers restart
	nc.Close()
	c.stopAll()
	c.restartAll()

	c.waitOnConsumerLeader(globalAccountName, "TEST", "dur")

	nc, js = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	checkCount(10)

	// Make sure messages can be consumed
	sub := natsSubSync(t, nc, inbox)
	for i := 0; i < 10; i++ {
		msg, err := sub.NextMsg(time.Second)
		if err != nil {
			t.Fatalf("i=%v next msg error: %v", i, err)
		}
		msg.AckSync()
	}
	checkCount(0)
}

func TestJetStreamClusterConsumerDeliverNewMaxRedeliveriesAndServerRestart(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo.*"},
		Replicas: 3,
	})
	require_NoError(t, err)

	inbox := nats.NewInbox()
	_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{
		DeliverSubject: inbox,
		Durable:        "dur",
		AckPolicy:      nats.AckExplicitPolicy,
		DeliverPolicy:  nats.DeliverNewPolicy,
		MaxDeliver:     3,
		AckWait:        250 * time.Millisecond,
		FilterSubject:  "foo.bar",
	})
	require_NoError(t, err)

	c.waitOnConsumerLeader(globalAccountName, "TEST", "dur")

	sendStreamMsg(t, nc, "foo.bar", "msg")

	sub := natsSubSync(t, nc, inbox)
	for i := 0; i < 3; i++ {
		natsNexMsg(t, sub, time.Second)
	}
	// Now check that there is no more redeliveries
	if msg, err := sub.NextMsg(300 * time.Millisecond); err != nats.ErrTimeout {
		t.Fatalf("Expected timeout, got msg=%+v err=%v", msg, err)
	}

	// Check server restart
	nc.Close()
	c.stopAll()
	c.restartAll()

	c.waitOnConsumerLeader(globalAccountName, "TEST", "dur")

	nc, _ = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	sub = natsSubSync(t, nc, inbox)
	// We should not have messages being redelivered.
	if msg, err := sub.NextMsg(300 * time.Millisecond); err != nats.ErrTimeout {
		t.Fatalf("Expected timeout, got msg=%+v err=%v", msg, err)
	}
}

func TestJetStreamClusterNoRestartAdvisories(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 3,
	})
	require_NoError(t, err)

	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "TEST2",
		Subjects: []string{"bar"},
		Replicas: 1,
	})
	require_NoError(t, err)

	// Create 10 consumers
	for i := 0; i < 10; i++ {
		dur := fmt.Sprintf("dlc-%d", i)
		_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{Durable: dur, AckPolicy: nats.AckExplicitPolicy})
		require_NoError(t, err)
	}

	msg := bytes.Repeat([]byte("Z"), 1024)
	for i := 0; i < 1000; i++ {
		js.PublishAsync("foo", msg)
		js.PublishAsync("bar", msg)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	// Add state to a consumer.
	sub, err := js.PullSubscribe("foo", "dlc-2")
	require_NoError(t, err)
	for _, m := range fetchMsgs(t, sub, 5, time.Second) {
		m.AckSync()
	}
	nc.Close()

	// Required to show the bug.
	c.leader().JetStreamSnapshotMeta()

	nc, _ = jsClientConnect(t, c.consumerLeader("$G", "TEST", "dlc-2"))
	defer nc.Close()

	sub, err = nc.SubscribeSync("$JS.EVENT.ADVISORY.API")
	require_NoError(t, err)

	// Shutdown and Restart.
	s := c.randomNonConsumerLeader("$G", "TEST", "dlc-2")
	s.Shutdown()
	s = c.restartServer(s)
	c.waitOnServerHealthz(s)

	checkSubsPending(t, sub, 0)

	nc, _ = jsClientConnect(t, c.randomNonStreamLeader("$G", "TEST"))
	defer nc.Close()

	sub, err = nc.SubscribeSync("$JS.EVENT.ADVISORY.STREAM.UPDATED.>")
	require_NoError(t, err)

	s = c.streamLeader("$G", "TEST2")
	s.Shutdown()
	s = c.restartServer(s)
	c.waitOnServerHealthz(s)

	checkSubsPending(t, sub, 0)
}

func TestJetStreamClusterR1StreamPlacementNoReservation(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	sp := make(map[string]int)
	for i := 0; i < 100; i++ {
		sname := fmt.Sprintf("T-%d", i)
		_, err := js.AddStream(&nats.StreamConfig{
			Name: sname,
		})
		require_NoError(t, err)
		sp[c.streamLeader("$G", sname).Name()]++
	}

	for serverName, num := range sp {
		if num > 60 {
			t.Fatalf("Streams not distributed, expected ~30-35 but got %d for server %q", num, serverName)
		}
	}
}

func TestJetStreamClusterConsumerAndStreamNamesWithPathSeparators(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{Name: "usr/bin"})
	require_Error(t, err, NewJSStreamNameContainsPathSeparatorsError(), nats.ErrInvalidStreamName)
	_, err = js.AddStream(&nats.StreamConfig{Name: `Documents\readme.txt`})
	require_Error(t, err, NewJSStreamNameContainsPathSeparatorsError(), nats.ErrInvalidStreamName)

	// Now consumers.
	_, err = js.AddStream(&nats.StreamConfig{Name: "T"})
	require_NoError(t, err)

	_, err = js.AddConsumer("T", &nats.ConsumerConfig{Durable: "a/b", AckPolicy: nats.AckExplicitPolicy})
	require_Error(t, err, NewJSConsumerNameContainsPathSeparatorsError(), nats.ErrInvalidConsumerName)

	_, err = js.AddConsumer("T", &nats.ConsumerConfig{Durable: `a\b`, AckPolicy: nats.AckExplicitPolicy})
	require_Error(t, err, NewJSConsumerNameContainsPathSeparatorsError(), nats.ErrInvalidConsumerName)
}

func TestJetStreamClusterFilteredMirrors(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "MSR", 3)
	defer c.shutdown()

	// Client for API requests.
	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	// Origin
	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo", "bar", "baz"},
	})
	require_NoError(t, err)

	msg := bytes.Repeat([]byte("Z"), 3)
	for i := 0; i < 100; i++ {
		js.PublishAsync("foo", msg)
		js.PublishAsync("bar", msg)
		js.PublishAsync("baz", msg)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	// Create Mirror now.
	_, err = js.AddStream(&nats.StreamConfig{
		Name:   "M",
		Mirror: &nats.StreamSource{Name: "TEST", FilterSubject: "foo"},
	})
	require_NoError(t, err)

	checkFor(t, 2*time.Second, 100*time.Millisecond, func() error {
		si, err := js.StreamInfo("M")
		require_NoError(t, err)
		if si.State.Msgs != 100 {
			return fmt.Errorf("Expected 100 msgs, got state: %+v", si.State)
		}
		return nil
	})

	sub, err := js.PullSubscribe("foo", "d", nats.BindStream("M"))
	require_NoError(t, err)

	// Make sure we only have "foo" and that sequence numbers preserved.
	sseq, dseq := uint64(1), uint64(1)
	for _, m := range fetchMsgs(t, sub, 100, 5*time.Second) {
		require_True(t, m.Subject == "foo")
		meta, err := m.Metadata()
		require_NoError(t, err)
		require_True(t, meta.Sequence.Consumer == dseq)
		dseq++
		require_True(t, meta.Sequence.Stream == sseq)
		sseq += 3
	}
}

// Test for making sure we error on same cluster name.
func TestJetStreamClusterSameClusterLeafNodes(t *testing.T) {
	c := createJetStreamCluster(t, jsClusterAccountsTempl, "SAME", _EMPTY_, 3, 11233, true)
	defer c.shutdown()

	// Do by hand since by default we check for connections.
	tmpl := c.createLeafSolicit(jsClusterTemplWithLeafNode)
	lc := createJetStreamCluster(t, tmpl, "SAME", "S-", 2, 22111, false)
	defer lc.shutdown()

	time.Sleep(200 * time.Millisecond)

	// Make sure no leafnodes are connected.
	for _, s := range lc.servers {
		checkLeafNodeConnectedCount(t, s, 0)
	}
}

// https://github.com/nats-io/nats-server/issues/3178
func TestJetStreamClusterLeafNodeSPOFMigrateLeaders(t *testing.T) {
	tmpl := strings.Replace(jsClusterTempl, "store_dir:", "domain: REMOTE, store_dir:", 1)
	c := createJetStreamClusterWithTemplate(t, tmpl, "HUB", 2)
	defer c.shutdown()

	tmpl = strings.Replace(jsClusterTemplWithLeafNode, "store_dir:", "domain: CORE, store_dir:", 1)
	lnc := c.createLeafNodesWithTemplateAndStartPort(tmpl, "LNC", 2, 22110)
	defer lnc.shutdown()

	lnc.waitOnClusterReady()

	// Place JS assets in LN, and we will do a pull consumer from the HUB.
	nc, js := jsClientConnect(t, lnc.randomServer())
	defer nc.Close()

	si, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 2,
	})
	require_NoError(t, err)
	require_True(t, si.Cluster.Name == "LNC")

	for i := 0; i < 100; i++ {
		js.PublishAsync("foo", []byte("HELLO"))
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	// Create the consumer.
	_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{Durable: "d", AckPolicy: nats.AckExplicitPolicy})
	require_NoError(t, err)

	nc, _ = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	dsubj := "$JS.CORE.API.CONSUMER.MSG.NEXT.TEST.d"
	// Grab directly using domain based subject but from the HUB cluster.
	_, err = nc.Request(dsubj, nil, time.Second)
	require_NoError(t, err)

	// Now we will force the consumer leader's server to drop and stall leafnode connections.
	cl := lnc.consumerLeader("$G", "TEST", "d")
	cl.setJetStreamMigrateOnRemoteLeaf()
	cl.closeAndDisableLeafnodes()

	// Now make sure we can eventually get a message again.
	checkFor(t, 5*time.Second, 500*time.Millisecond, func() error {
		_, err = nc.Request(dsubj, nil, 500*time.Millisecond)
		return err
	})

	nc, _ = jsClientConnect(t, lnc.randomServer())
	defer nc.Close()

	// Now make sure the consumer, or any other asset, can not become a leader on this node while the leafnode
	// is disconnected.
	csd := fmt.Sprintf(JSApiConsumerLeaderStepDownT, "TEST", "d")
	for i := 0; i < 10; i++ {
		nc.Request(csd, nil, time.Second)
		lnc.waitOnConsumerLeader(globalAccountName, "TEST", "d")
		if lnc.consumerLeader(globalAccountName, "TEST", "d") == cl {
			t.Fatalf("Consumer leader should not migrate to server without a leafnode connection")
		}
	}

	// Now make sure once leafnode is back we can have leaders on this server.
	cl.reEnableLeafnodes()
	checkLeafNodeConnectedCount(t, cl, 2)

	// Make sure we can migrate back to this server now that we are connected.
	checkFor(t, 5*time.Second, 100*time.Millisecond, func() error {
		nc.Request(csd, nil, time.Second)
		lnc.waitOnConsumerLeader(globalAccountName, "TEST", "d")
		if lnc.consumerLeader(globalAccountName, "TEST", "d") == cl {
			return nil
		}
		return fmt.Errorf("Not this server yet")
	})
}

func TestJetStreamClusterStreamCatchupWithTruncateAndPriorSnapshot(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3F", 3)
	defer c.shutdown()

	// Client based API
	s := c.randomServer()
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 3,
	})
	require_NoError(t, err)

	// Shutdown a replica
	rs := c.randomNonStreamLeader("$G", "TEST")
	rs.Shutdown()
	if s == rs {
		nc.Close()
		s = c.randomServer()
		nc, js = jsClientConnect(t, s)
		defer nc.Close()
	}

	msg, toSend := []byte("OK"), 100
	for i := 0; i < toSend; i++ {
		_, err := js.PublishAsync("foo", msg)
		require_NoError(t, err)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(2 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	sl := c.streamLeader("$G", "TEST")
	mset, err := sl.GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)

	// Force snapshot
	require_NoError(t, mset.raftNode().InstallSnapshot(mset.stateSnapshot()))

	// Now truncate the store on purpose.
	err = mset.store.Truncate(50)
	require_NoError(t, err)

	// Restart Server.
	rs = c.restartServer(rs)

	// Make sure we can become current.
	// With bug we would fail here.
	c.waitOnStreamCurrent(rs, "$G", "TEST")
}

func TestJetStreamClusterNoOrphanedDueToNoConnection(t *testing.T) {
	orgEventsHBInterval := eventsHBInterval
	eventsHBInterval = 500 * time.Millisecond
	defer func() { eventsHBInterval = orgEventsHBInterval }()

	c := createJetStreamClusterExplicit(t, "R3F", 3)
	defer c.shutdown()

	s := c.randomServer()
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 3,
	})
	require_NoError(t, err)

	checkSysServers := func() {
		t.Helper()
		checkFor(t, 2*time.Second, 15*time.Millisecond, func() error {
			for _, s := range c.servers {
				s.mu.RLock()
				num := len(s.sys.servers)
				s.mu.RUnlock()
				if num != 2 {
					return fmt.Errorf("Expected server %q to have 2 servers, got %v", s, num)
				}
			}
			return nil
		})
	}

	checkSysServers()
	nc.Close()

	s.mu.RLock()
	val := (s.sys.orphMax / eventsHBInterval) + 2
	s.mu.RUnlock()
	time.Sleep(val * eventsHBInterval)
	checkSysServers()
}

func TestJetStreamClusterStreamResetOnExpirationDuringPeerDownAndRestartWithLeaderChange(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3F", 3)
	defer c.shutdown()

	s := c.randomServer()
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 3,
		MaxAge:   time.Second,
	})
	require_NoError(t, err)

	n := 100
	for i := 0; i < n; i++ {
		js.PublishAsync("foo", []byte("NORESETPLS"))
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	// Shutdown a non-leader before expiration.
	nsl := c.randomNonStreamLeader("$G", "TEST")
	nsl.Shutdown()

	// Wait for all messages to expire.
	checkFor(t, 5*time.Second, time.Second, func() error {
		si, err := js.StreamInfo("TEST")
		require_NoError(t, err)
		if si.State.Msgs == 0 {
			return nil
		}
		return fmt.Errorf("Wanted 0 messages, got %d", si.State.Msgs)
	})

	// Now restart the non-leader server, twice. First time clears raft,
	// second will not have any index state or raft to tell it what is first sequence.
	nsl = c.restartServer(nsl)
	c.checkClusterFormed()
	c.waitOnServerCurrent(nsl)

	// Now clear raft WAL.
	mset, err := nsl.GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)
	require_NoError(t, mset.raftNode().InstallSnapshot(mset.stateSnapshot()))

	nsl.Shutdown()
	nsl = c.restartServer(nsl)
	c.checkClusterFormed()
	c.waitOnServerCurrent(nsl)

	// We will now check this server directly.
	mset, err = nsl.GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)

	if state := mset.state(); state.FirstSeq != uint64(n+1) || state.LastSeq != uint64(n) {
		t.Fatalf("Expected first sequence of %d, got %d", n+1, state.FirstSeq)
	}

	si, err := js.StreamInfo("TEST")
	require_NoError(t, err)
	if state := si.State; state.FirstSeq != uint64(n+1) || state.LastSeq != uint64(n) {
		t.Fatalf("Expected first sequence of %d, got %d", n+1, state.FirstSeq)
	}

	// Now move the leader there and double check, but above test is sufficient.
	checkFor(t, 10*time.Second, 250*time.Millisecond, func() error {
		_, err = nc.Request(fmt.Sprintf(JSApiStreamLeaderStepDownT, "TEST"), nil, time.Second)
		require_NoError(t, err)
		c.waitOnStreamLeader("$G", "TEST")
		if c.streamLeader("$G", "TEST") == nsl {
			return nil
		}
		return fmt.Errorf("No correct leader yet")
	})

	if state := mset.state(); state.FirstSeq != uint64(n+1) || state.LastSeq != uint64(n) {
		t.Fatalf("Expected first sequence of %d, got %d", n+1, state.FirstSeq)
	}

	si, err = js.StreamInfo("TEST")
	require_NoError(t, err)
	if state := si.State; state.FirstSeq != uint64(n+1) || state.LastSeq != uint64(n) {
		t.Fatalf("Expected first sequence of %d, got %d", n+1, state.FirstSeq)
	}
}

func TestJetStreamClusterPullConsumerMaxWaiting(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{Name: "TEST", Subjects: []string{"test.*"}})
	require_NoError(t, err)

	_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{
		Durable:    "dur",
		AckPolicy:  nats.AckExplicitPolicy,
		MaxWaiting: 10,
	})
	require_NoError(t, err)

	// Cannot be updated.
	_, err = js.UpdateConsumer("TEST", &nats.ConsumerConfig{
		Durable:    "dur",
		AckPolicy:  nats.AckExplicitPolicy,
		MaxWaiting: 1,
	})
	if !strings.Contains(err.Error(), "can not be updated") {
		t.Fatalf(`expected "cannot be updated" error, got %s`, err)
	}
}

func TestJetStreamClusterEncryptedDoubleSnapshotBug(t *testing.T) {
	c := createJetStreamClusterWithTemplate(t, jsClusterEncryptedTempl, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		MaxAge:   time.Second,
		Replicas: 3,
	})
	require_NoError(t, err)

	numMsgs := 50
	for i := 0; i < numMsgs; i++ {
		js.PublishAsync("foo", []byte("SNAP"))
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	// Perform a snapshot on a follower.
	nl := c.randomNonStreamLeader("$G", "TEST")
	mset, err := nl.GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)
	err = mset.raftNode().InstallSnapshot(mset.stateSnapshot())
	require_NoError(t, err)

	_, err = js.Publish("foo", []byte("SNAP2"))
	require_NoError(t, err)

	for _, seq := range []uint64{1, 11, 22, 51} {
		js.DeleteMsg("TEST", seq)
	}

	err = mset.raftNode().InstallSnapshot(mset.stateSnapshot())
	require_NoError(t, err)

	_, err = js.Publish("foo", []byte("SNAP3"))
	require_NoError(t, err)
}

func TestJetStreamClusterRePublishUpdateSupported(t *testing.T) {
	test := func(t *testing.T, s *Server, stream string, replicas int) {
		nc, js := jsClientConnect(t, s)
		defer nc.Close()

		cfg := &nats.StreamConfig{
			Name:     stream,
			Storage:  nats.MemoryStorage,
			Replicas: replicas,
			Subjects: []string{"foo.>"},
		}
		_, err := js.AddStream(cfg)
		require_NoError(t, err)

		expectUpdate := func() {
			t.Helper()

			req, err := json.Marshal(cfg)
			require_NoError(t, err)
			rmsg, err := nc.Request(fmt.Sprintf(JSApiStreamUpdateT, cfg.Name), req, time.Second)
			require_NoError(t, err)
			var resp JSApiStreamCreateResponse
			err = json.Unmarshal(rmsg.Data, &resp)
			require_NoError(t, err)
			if resp.Type != JSApiStreamUpdateResponseType {
				t.Fatalf("Invalid response type %s expected %s", resp.Type, JSApiStreamUpdateResponseType)
			}
			if IsNatsErr(resp.Error, JSStreamInvalidConfigF) {
				t.Fatalf("Expected no error regarding config error, got %+v", resp.Error)
			}
		}

		expectRepublished := func(expectedRepub bool) {
			t.Helper()

			nc, js := jsClientConnect(t, s)
			defer nc.Close()

			// Create a subscriber for foo.> so that we can see
			// our published message being echoed back to us.
			sf, err := nc.SubscribeSync("foo.>")
			require_NoError(t, err)
			defer sf.Unsubscribe()

			// Create a subscriber for bar.> so that we can see
			// any potentially republished messages.
			sb, err := nc.SubscribeSync("bar.>")
			require_NoError(t, err)
			defer sf.Unsubscribe()

			// Publish a message, it will hit the foo.> stream and
			// may potentially be republished to the bar.> stream.
			_, err = js.Publish("foo."+stream, []byte("HELLO!"))
			require_NoError(t, err)

			// Wait for a little while so that we have enough time
			// to determine whether it's going to arrive on one or
			// both streams.
			checkSubsPending(t, sf, 1)
			if expectedRepub {
				checkSubsPending(t, sb, 1)
			} else {
				checkSubsPending(t, sb, 0)
			}
		}

		// At this point there's no republish config, so we should
		// only receive our published message on foo.>.
		expectRepublished(false)

		// Add a republish config so that everything on foo.> also
		// gets republished to bar.>.
		cfg.RePublish = &nats.RePublish{
			Source:      "foo.>",
			Destination: "bar.>",
		}
		expectUpdate()
		expectRepublished(true)

		// Now take the republish config away again, so we should go
		// back to only getting them on foo.>.
		cfg.RePublish = nil
		expectUpdate()
		expectRepublished(false)
	}

	t.Run("Single", func(t *testing.T) {
		s := RunBasicJetStreamServer(t)
		defer s.Shutdown()

		test(t, s, "single", 1)
	})
	t.Run("Clustered", func(t *testing.T) {
		c := createJetStreamClusterExplicit(t, "JSC", 3)
		defer c.shutdown()

		test(t, c.randomNonLeader(), "clustered", 3)
	})
}

func TestJetStreamClusterDirectGetFromLeafnode(t *testing.T) {
	tmpl := strings.Replace(jsClusterAccountsTempl, "store_dir:", "domain: CORE, store_dir:", 1)
	c := createJetStreamCluster(t, tmpl, "CORE", _EMPTY_, 3, 19022, true)
	defer c.shutdown()

	tmpl = strings.Replace(jsClusterTemplWithSingleLeafNode, "store_dir:", "domain: SPOKE, store_dir:", 1)
	ln := c.createLeafNodeWithTemplate("LN-SPOKE", tmpl)
	defer ln.Shutdown()

	checkLeafNodeConnectedCount(t, ln, 2)

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	kv, err := js.CreateKeyValue(&nats.KeyValueConfig{Bucket: "KV"})
	require_NoError(t, err)

	_, err = kv.PutString("age", "22")
	require_NoError(t, err)

	// Now connect to the ln and make sure we can do a domain direct get.
	nc, _ = jsClientConnect(t, ln)
	defer nc.Close()

	js, err = nc.JetStream(nats.Domain("CORE"))
	require_NoError(t, err)

	kv, err = js.KeyValue("KV")
	require_NoError(t, err)

	entry, err := kv.Get("age")
	require_NoError(t, err)
	require_True(t, string(entry.Value()) == "22")
}

func TestJetStreamClusterUnknownReplicaOnClusterRestart(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{Name: "TEST", Subjects: []string{"foo"}, Replicas: 3})
	require_NoError(t, err)

	c.waitOnStreamLeader(globalAccountName, "TEST")
	lname := c.streamLeader(globalAccountName, "TEST").Name()
	sendStreamMsg(t, nc, "foo", "msg1")

	nc.Close()
	c.stopAll()
	// Restart the leader...
	for _, s := range c.servers {
		if s.Name() == lname {
			c.restartServer(s)
		}
	}
	// And one of the other servers
	for _, s := range c.servers {
		if s.Name() != lname {
			c.restartServer(s)
			break
		}
	}
	c.waitOnStreamLeader(globalAccountName, "TEST")

	nc, js = jsClientConnect(t, c.randomServer())
	defer nc.Close()
	sendStreamMsg(t, nc, "foo", "msg2")

	si, err := js.StreamInfo("TEST")
	require_NoError(t, err)
	if len(si.Cluster.Replicas) != 2 {
		t.Fatalf("Leader is %s - expected 2 peers, got %+v", si.Cluster.Leader, si.Cluster.Replicas[0])
	}
	// However, since the leader does not know the name of the server
	// we should report an "unknown" name.
	var ok bool
	for _, r := range si.Cluster.Replicas {
		if strings.Contains(r.Name, "unknown") {
			// Check that it has no lag reported, and the it is not current.
			if r.Current {
				t.Fatal("Expected non started node to be marked as not current")
			}
			if r.Lag != 0 {
				t.Fatalf("Expected lag to not be set, was %v", r.Lag)
			}
			if r.Active != 0 {
				t.Fatalf("Expected active to not be set, was: %v", r.Active)
			}
			ok = true
			break
		}
	}
	if !ok {
		t.Fatalf("Should have had an unknown server name, did not: %+v - %+v", si.Cluster.Replicas[0], si.Cluster.Replicas[1])
	}
}

func TestJetStreamClusterSnapshotBeforePurgeAndCatchup(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		MaxAge:   5 * time.Second,
		Replicas: 3,
	})
	require_NoError(t, err)

	sl := c.streamLeader("$G", "TEST")
	nl := c.randomNonStreamLeader("$G", "TEST")

	// Make sure we do not get disconnected when shutting the non-leader down.
	nc, js = jsClientConnect(t, sl)
	defer nc.Close()

	send1k := func() {
		t.Helper()
		for i := 0; i < 1000; i++ {
			js.PublishAsync("foo", []byte("SNAP"))
		}
		select {
		case <-js.PublishAsyncComplete():
		case <-time.After(5 * time.Second):
			t.Fatalf("Did not receive completion signal")
		}
	}

	// Send first 1000 to everyone.
	send1k()

	// Now shutdown a non-leader.
	c.waitOnStreamCurrent(nl, "$G", "TEST")
	nl.Shutdown()

	// Send another 1000.
	send1k()

	// Force snapshot on the leader.
	mset, err := sl.GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)
	err = mset.raftNode().InstallSnapshot(mset.stateSnapshot())
	require_NoError(t, err)

	// Purge
	err = js.PurgeStream("TEST")
	require_NoError(t, err)

	// Send another 1000.
	send1k()

	// We want to make sure we do not send unnecessary skip msgs when we know we do not have all of these messages.
	nc, _ = jsClientConnect(t, sl, nats.UserInfo("admin", "s3cr3t!"))
	defer nc.Close()
	sub, err := nc.SubscribeSync("$JSC.R.>")
	require_NoError(t, err)

	// Now restart non-leader.
	nl = c.restartServer(nl)
	c.waitOnStreamCurrent(nl, "$G", "TEST")

	// Grab state directly from non-leader.
	mset, err = nl.GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)

	checkFor(t, 2*time.Second, 100*time.Millisecond, func() error {
		if state := mset.state(); state.FirstSeq != 2001 || state.LastSeq != 3000 {
			return fmt.Errorf("Incorrect state: %+v", state)
		}
		return nil
	})

	// Make sure we only sent 1002 sync catchup msgs.
	// This is for the new messages, the delete range, and the EOF.
	nmsgs, _, _ := sub.Pending()
	if nmsgs != 1002 {
		t.Fatalf("Expected only 1002 sync catchup msgs to be sent signaling eof, but got %d", nmsgs)
	}
}

func TestJetStreamClusterStreamResetWithLargeFirstSeq(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	cfg := &nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		MaxAge:   5 * time.Second,
		Replicas: 1,
	}
	_, err := js.AddStream(cfg)
	require_NoError(t, err)

	// Fake a very large first seq.
	sl := c.streamLeader("$G", "TEST")
	mset, err := sl.GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)

	mset.mu.Lock()
	mset.store.Compact(1_000_000)
	mset.mu.Unlock()
	// Restart
	sl.Shutdown()
	sl = c.restartServer(sl)
	c.waitOnStreamLeader("$G", "TEST")

	nc, js = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	// Make sure we have the correct state after restart.
	si, err := js.StreamInfo("TEST")
	require_NoError(t, err)
	require_True(t, si.State.FirstSeq == 1_000_000)

	// Now add in 10,000 messages.
	num := 10_000
	for i := 0; i < num; i++ {
		js.PublishAsync("foo", []byte("SNAP"))
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	si, err = js.StreamInfo("TEST")
	require_NoError(t, err)
	require_True(t, si.State.FirstSeq == 1_000_000)
	require_True(t, si.State.LastSeq == uint64(1_000_000+num-1))

	// We want to make sure we do not send unnecessary skip msgs when we know we do not have all of these messages.
	ncs, _ := jsClientConnect(t, sl, nats.UserInfo("admin", "s3cr3t!"))
	defer nc.Close()
	sub, err := ncs.SubscribeSync("$JSC.R.>")
	require_NoError(t, err)

	// Now scale up to R3.
	cfg.Replicas = 3
	_, err = js.UpdateStream(cfg)
	require_NoError(t, err)
	nl := c.randomNonStreamLeader("$G", "TEST")
	c.waitOnStreamCurrent(nl, "$G", "TEST")

	// Make sure we only sent the number of catchup msgs we expected.
	checkFor(t, 5*time.Second, 50*time.Millisecond, func() error {
		if nmsgs, _, _ := sub.Pending(); nmsgs != (cfg.Replicas-1)*(num+1) {
			return fmt.Errorf("expected %d catchup msgs, but got %d", (cfg.Replicas-1)*(num+1), nmsgs)
		}
		return nil
	})
}

func TestJetStreamClusterStreamCatchupInteriorNilMsgs(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	cfg := &nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
	}
	_, err := js.AddStream(cfg)
	require_NoError(t, err)

	num := 100
	for l := 0; l < 5; l++ {
		for i := 0; i < num-1; i++ {
			js.PublishAsync("foo", []byte("SNAP"))
		}
		// Blank msg.
		js.PublishAsync("foo", nil)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}

	// Make sure we have the correct state after restart.
	si, err := js.StreamInfo("TEST")
	require_NoError(t, err)
	require_True(t, si.State.Msgs == 500)

	// Now scale up to R3.
	cfg.Replicas = 3
	_, err = js.UpdateStream(cfg)
	require_NoError(t, err)
	nl := c.randomNonStreamLeader("$G", "TEST")
	c.waitOnStreamCurrent(nl, "$G", "TEST")

	mset, err := nl.GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)

	mset.mu.RLock()
	state := mset.store.State()
	mset.mu.RUnlock()
	require_True(t, state.Msgs == 500)
}

type captureCatchupWarnLogger struct {
	DummyLogger
	ch chan string
}

func (l *captureCatchupWarnLogger) Warnf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if strings.Contains(msg, "simulate error") {
		select {
		case l.ch <- msg:
		default:
		}
	}
}

type catchupMockStore struct {
	StreamStore
	ch chan uint64
}

func (s catchupMockStore) LoadMsg(seq uint64, sm *StoreMsg) (*StoreMsg, error) {
	s.ch <- seq
	return s.StreamStore.LoadMsg(seq, sm)
}

func TestJetStreamClusterLeaderAbortsCatchupOnFollowerError(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "JSC", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	cfg := &nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 3,
	}
	_, err := js.AddStream(cfg)
	require_NoError(t, err)

	c.waitOnStreamLeader(globalAccountName, "TEST")

	payload := string(make([]byte, 1024))
	total := 100
	for i := 0; i < total; i++ {
		sendStreamMsg(t, nc, "foo", payload)
	}

	c.waitOnAllCurrent()

	// Get the stream leader
	leader := c.streamLeader(globalAccountName, "TEST")
	mset, err := leader.GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)

	var syncSubj string
	mset.mu.RLock()
	if mset.syncSub != nil {
		syncSubj = string(mset.syncSub.subject)
	}
	mset.mu.RUnlock()

	if syncSubj == _EMPTY_ {
		t.Fatal("Did not find the sync request subject")
	}

	// Setup the logger on the leader to make sure we capture the error and print
	// and also stop the runCatchup.
	l := &captureCatchupWarnLogger{ch: make(chan string, 10)}
	leader.SetLogger(l, false, false)

	// Set a fake message store that will allow us to verify
	// a few things.
	mset.mu.Lock()
	orgMS := mset.store
	ms := catchupMockStore{StreamStore: mset.store, ch: make(chan uint64)}
	mset.store = ms
	mset.mu.Unlock()

	// Need the system account to simulate the sync request that we are going to send.
	sysNC := natsConnect(t, c.randomServer().ClientURL(), nats.UserInfo("admin", "s3cr3t!"))
	defer sysNC.Close()
	// Setup a subscription to receive the messages sent by the leader.
	sub := natsSubSync(t, sysNC, nats.NewInbox())
	req := &streamSyncRequest{
		FirstSeq: 1,
		LastSeq:  uint64(total),
		Peer:     "bozo", // Should be one of the node name, but does not matter here
	}
	b, _ := json.Marshal(req)
	// Send the sync request and use our sub's subject for destination where leader
	// needs to send messages to.
	natsPubReq(t, sysNC, syncSubj, sub.Subject, b)

	// The mock store is blocked loading the first message, so we need to consume
	// the sequence before being able to receive the message in our sub.
	if seq := <-ms.ch; seq != 1 {
		t.Fatalf("Expected sequence to be 1, got %v", seq)
	}

	// Now consume and the leader should report the error and terminate runCatchup
	msg := natsNexMsg(t, sub, time.Second)
	msg.Respond([]byte("simulate error"))

	select {
	case <-l.ch:
		// OK
	case <-time.After(time.Second):
		t.Fatal("Did not get the expected error")
	}

	// The mock store should be blocked in seq==2 now, but after consuming, it should
	// abort the runCatchup.
	if seq := <-ms.ch; seq != 2 {
		t.Fatalf("Expected sequence to be 2, got %v", seq)
	}
	// We may have some more messages loaded as a race between when the sub will
	// indicate that the catchup should stop and the part where we send messages
	// in the batch, but we should likely not have sent all messages.
	loaded := 0
	for done := false; !done; {
		select {
		case <-ms.ch:
			loaded++
		case <-time.After(250 * time.Millisecond):
			done = true
		}
	}
	if loaded > 10 {
		t.Fatalf("Too many messages were sent after detecting remote is done: %v", loaded)
	}

	ch := make(chan string, 1)
	mset.mu.Lock()
	mset.store = orgMS
	leader.sysUnsubscribe(mset.syncSub)
	mset.syncSub = nil
	leader.systemSubscribe(syncSubj, _EMPTY_, false, mset.sysc, func(_ *subscription, _ *client, _ *Account, _, reply string, msg []byte) {
		var sreq streamSyncRequest
		if err := json.Unmarshal(msg, &sreq); err != nil {
			return
		}
		select {
		case ch <- reply:
		default:
		}
	})
	mset.mu.Unlock()
	syncRepl := natsSubSync(t, sysNC, nats.NewInbox()+".>")
	// Make sure our sub is propagated
	time.Sleep(250 * time.Millisecond)

	if v := leader.gcbTotal(); v != 0 {
		t.Fatalf("Expected gcbTotal to be 0, got %v", v)
	}

	buf := make([]byte, 1_000_000)
	n := runtime.Stack(buf, true)
	if bytes.Contains(buf[:n], []byte("runCatchup")) {
		t.Fatalf("Looks like runCatchup is still running:\n%s", buf[:n])
	}

	mset.mu.Lock()
	var state StreamState
	mset.store.FastState(&state)
	snapshot := &streamSnapshot{
		Msgs:     state.Msgs,
		Bytes:    state.Bytes,
		FirstSeq: state.FirstSeq,
		LastSeq:  state.LastSeq + 1,
	}
	b, _ = json.Marshal(snapshot)
	mset.node.SendSnapshot(b)
	mset.mu.Unlock()

	var sreqSubj string
	select {
	case sreqSubj = <-ch:
	case <-time.After(time.Second):
		t.Fatal("Did not receive sync request")
	}

	// Now send a message with a wrong sequence and expect to receive an error.
	em := encodeStreamMsg("foo", _EMPTY_, nil, []byte("fail"), 102, time.Now().UnixNano())
	leader.sendInternalMsgLocked(sreqSubj, syncRepl.Subject, nil, em)
	msg = natsNexMsg(t, syncRepl, time.Second)
	if len(msg.Data) == 0 {
		t.Fatal("Expected err response from the remote")
	}
}

func TestJetStreamClusterStreamDirectGetNotTooSoon(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3F", 3)
	defer c.shutdown()

	// Client based API
	s := c.randomServer()
	nc, _ := jsClientConnect(t, s)
	defer nc.Close()

	// Do by hand for now.
	cfg := &StreamConfig{
		Name:        "TEST",
		Storage:     FileStorage,
		Subjects:    []string{"foo"},
		Replicas:    3,
		MaxMsgsPer:  1,
		AllowDirect: true,
	}
	addStream(t, nc, cfg)
	sendStreamMsg(t, nc, "foo", "bar")

	getSubj := fmt.Sprintf(JSDirectGetLastBySubjectT, "TEST", "foo")

	// Make sure we get all direct subs.
	checkForDirectSubs := func() {
		t.Helper()
		checkFor(t, 10*time.Second, 250*time.Millisecond, func() error {
			for _, s := range c.servers {
				mset, err := s.GlobalAccount().lookupStream("TEST")
				if err != nil {
					return err
				}
				mset.mu.RLock()
				hasBoth := mset.directSub != nil && mset.lastBySub != nil
				mset.mu.RUnlock()
				if !hasBoth {
					return fmt.Errorf("%v does not have both direct subs registered", s)
				}
			}
			return nil
		})
	}

	_, err := nc.Request(getSubj, nil, time.Second)
	require_NoError(t, err)

	checkForDirectSubs()

	// We want to make sure that when starting up we do not listen until we have a leader.
	nc.Close()
	c.stopAll()

	// Start just one..
	s, opts := RunServerWithConfig(c.opts[0].ConfigFile)
	c.servers[0] = s
	c.opts[0] = opts

	nc, _ = jsClientConnect(t, s)
	defer nc.Close()

	_, err = nc.Request(getSubj, nil, time.Second)
	require_Error(t, err, nats.ErrTimeout)

	// Now start all and make sure they all eventually have subs for direct access.
	c.restartAll()
	c.waitOnStreamLeader("$G", "TEST")

	_, err = nc.Request(getSubj, nil, time.Second)
	require_NoError(t, err)

	checkForDirectSubs()
}

func TestJetStreamClusterStaleReadsOnRestart(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3F", 3)
	defer c.shutdown()

	// Client based API
	s := c.randomServer()
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo", "bar", "baz"},
		Replicas: 3,
	})
	require_NoError(t, err)

	_, err = js.Publish("foo", nil)
	require_NoError(t, err)

	sl := c.streamLeader("$G", "TEST")

	r1 := c.randomNonStreamLeader("$G", "TEST")
	r1.Shutdown()

	nc.Close()
	nc, js = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err = js.Publish("bar", nil)
	require_NoError(t, err)

	_, err = js.Publish("baz", nil)
	require_NoError(t, err)

	r2 := c.randomNonStreamLeader("$G", "TEST")
	r2.Shutdown()

	sl.Shutdown()

	c.restartServer(r2)
	c.restartServer(r1)

	c.waitOnStreamLeader("$G", "TEST")

	nc.Close()
	nc, js = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err = js.Publish("foo", nil)
	require_NoError(t, err)

	_, err = js.Publish("bar", nil)
	require_NoError(t, err)

	_, err = js.Publish("baz", nil)
	require_NoError(t, err)

	c.restartServer(sl)
	c.waitOnAllCurrent()
	c.waitOnStreamLeader("$G", "TEST")

	// Grab expected from leader.
	var state StreamState
	sl = c.streamLeader("$G", "TEST")
	mset, err := sl.GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)
	mset.store.FastState(&state)

	checkFor(t, 10*time.Second, 200*time.Millisecond, func() error {
		for _, s := range c.servers {
			if s.Running() {
				mset, err := s.GlobalAccount().lookupStream("TEST")
				if err != nil {
					return err
				}
				var fs StreamState
				mset.store.FastState(&fs)
				if !reflect.DeepEqual(fs, state) {
					return fmt.Errorf("States do not match, expected %+v but got %+v", state, fs)
				}
			}
		}
		return nil
	})
}

func TestJetStreamClusterReplicasChangeStreamInfo(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3F", 3)
	defer c.shutdown()

	s := c.randomServer()
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	numStreams := 1
	msgsPerStream := 10
	for i := 0; i < numStreams; i++ {
		sname := fmt.Sprintf("TEST_%v", i)
		_, err := js.AddStream(&nats.StreamConfig{
			Name:     sname,
			Replicas: 3,
		})
		require_NoError(t, err)
		for j := 0; j < msgsPerStream; j++ {
			sendStreamMsg(t, nc, sname, "msg")
		}
	}

	checkStreamInfo := func(js nats.JetStreamContext) {
		t.Helper()
		checkFor(t, 20*time.Second, 15*time.Millisecond, func() error {
			for i := 0; i < numStreams; i++ {
				si, err := js.StreamInfo(fmt.Sprintf("TEST_%v", i))
				if err != nil {
					return err
				}
				if si.State.Msgs != uint64(msgsPerStream) || si.State.FirstSeq != 1 || si.State.LastSeq != uint64(msgsPerStream) {
					return fmt.Errorf("Invalid stream info for %s: %+v", si.Config.Name, si.State)
				}
			}
			return nil
		})
	}
	checkStreamInfo(js)

	// Update replicas down to 1
	for i := 0; i < numStreams; i++ {
		sname := fmt.Sprintf("TEST_%v", i)
		_, err := js.UpdateStream(&nats.StreamConfig{
			Name:     sname,
			Replicas: 1,
		})
		require_NoError(t, err)
	}
	checkStreamInfo(js)

	// Back up to 3
	for i := 0; i < numStreams; i++ {
		sname := fmt.Sprintf("TEST_%v", i)
		_, err := js.UpdateStream(&nats.StreamConfig{
			Name:     sname,
			Replicas: 3,
		})
		require_NoError(t, err)
		c.waitOnStreamLeader(globalAccountName, sname)
		for _, s := range c.servers {
			c.waitOnStreamCurrent(s, globalAccountName, sname)
		}
	}
	checkStreamInfo(js)

	// Now shutdown the cluster and restart it
	nc.Close()
	c.stopAll()
	c.restartAll()

	for i := 0; i < numStreams; i++ {
		sname := fmt.Sprintf("TEST_%v", i)
		c.waitOnStreamLeader(globalAccountName, sname)
		for _, s := range c.servers {
			c.waitOnStreamCurrent(s, globalAccountName, sname)
		}
	}

	nc, js = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	checkStreamInfo(js)
}

func TestJetStreamClusterMaxOutstandingCatchup(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "MCB", 3)
	defer c.shutdown()

	for _, s := range c.servers {
		s.gcbMu.RLock()
		v := s.gcbOutMax
		s.gcbMu.RUnlock()
		if v != defaultMaxTotalCatchupOutBytes {
			t.Fatalf("Server %v, expected max_outstanding_catchup to be %v, got %v", s, defaultMaxTotalCatchupOutBytes, v)
		}
	}

	c.shutdown()

	tmpl := `
		listen: 127.0.0.1:-1
		server_name: %s
		jetstream: { max_outstanding_catchup: 1KB, domain: ngs, max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}
		leaf: { listen: 127.0.0.1:-1 }
		cluster {
			name: %s
			listen: 127.0.0.1:%d
			routes = [%s]
		}
	`
	c = createJetStreamClusterWithTemplate(t, tmpl, "MCB", 3)
	defer c.shutdown()

	for _, s := range c.servers {
		s.gcbMu.RLock()
		v := s.gcbOutMax
		s.gcbMu.RUnlock()
		if v != 1024 {
			t.Fatalf("Server %v, expected max_outstanding_catchup to be 1KB, got %v", s, v)
		}
	}

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 3,
	})
	require_NoError(t, err)

	// Close client now and will create new one
	nc.Close()

	c.waitOnStreamLeader(globalAccountName, "TEST")

	follower := c.randomNonStreamLeader(globalAccountName, "TEST")
	follower.Shutdown()

	c.waitOnStreamLeader(globalAccountName, "TEST")

	// Create new connection in case we would have been connected to follower.
	nc, _ = jsClientConnect(t, c.randomServer())
	defer nc.Close()

	payload := string(make([]byte, 2048))
	for i := 0; i < 1000; i++ {
		sendStreamMsg(t, nc, "foo", payload)
	}

	// Cause snapshots on leader
	mset, err := c.streamLeader(globalAccountName, "TEST").GlobalAccount().lookupStream("TEST")
	require_NoError(t, err)
	err = mset.raftNode().InstallSnapshot(mset.stateSnapshot())
	require_NoError(t, err)

	// Resart server and it should be able to catchup
	follower = c.restartServer(follower)
	c.waitOnStreamCurrent(follower, globalAccountName, "TEST")

	// Config reload not supported
	s := c.servers[0]
	cfile := s.getOpts().ConfigFile
	content, err := os.ReadFile(cfile)
	require_NoError(t, err)
	conf := string(content)
	conf = strings.ReplaceAll(conf, "max_outstanding_catchup: 1KB,", "max_outstanding_catchup: 1MB,")
	err = os.WriteFile(cfile, []byte(conf), 0644)
	require_NoError(t, err)
	err = s.Reload()
	require_Error(t, err, fmt.Errorf("config reload not supported for JetStreamMaxCatchup: old=1024, new=1048576"))
}

func TestJetStreamClusterCompressedStreamMessages(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3F", 3)
	defer c.shutdown()

	s := c.randomServer()
	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Replicas: 3,
	})
	require_NoError(t, err)

	// 32k (compress threshold ~4k)
	toSend, msg := 10_000, []byte(strings.Repeat("ABCD", 8*1024))
	for i := 0; i < toSend; i++ {
		js.PublishAsync("foo", msg)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(5 * time.Second):
		t.Fatalf("Did not receive completion signal")
	}
}

//
// DO NOT ADD NEW TESTS IN THIS FILE
// Add at the end of jetstream_cluster_<n>_test.go, with <n> being the highest value.
//
