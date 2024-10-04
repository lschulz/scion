// Copyright 2024 OVGU Magdeburg
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package snet

import (
	"context"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
)

// Provides level 2 DRKeys for validating messages from border routers.
// All methodes require external synchronization if used concurrently.
type KeyProvider interface {
	// Gets an AS-Host DRKey valid at the given point of time.
	GetASHostKey(ctx context.Context, validity time.Time, srcIA addr.IA) (drkey.Key, error)
	// Gets a Host-Host DRKey for messages sent to the local host.
	GetHostSelfKey(ctx context.Context, validity time.Time, srcAddr addr.Addr) (drkey.Key, error)
	// Gets a Host-Host DRKey valid at the given point of time.
	GetHostHostKey(ctx context.Context, validity time.Time, srcAddr addr.Addr, dstAddr addr.Addr) (drkey.Key, error)
	// Refresh keys that will expire soon or already have expired assuming
	// a global epoch duration of 'keyDuration'.
	RefreshKeys(ctx context.Context, keyDuration time.Duration) []error
	// Deletes all keys expired since 'now'.
	DeleteExpiredKeys(now time.Time)
}

type DaemonConnector interface {
	// DRKeyGetASHostKey requests a AS-Host Key from the daemon.
	DRKeyGetASHostKey(ctx context.Context, meta drkey.ASHostMeta) (drkey.ASHostKey, error)
	// DRKeyGetHostHostKey requests a Host-Host Key from the daemon.
	DRKeyGetHostHostKey(ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error)
}

type KeyCache struct {
	Sciond    DaemonConnector
	DstIA     addr.IA
	DstHost   netip.Addr
	cache     map[addr.IA][]drkey.ASHostKey
	hostCache map[addr.Addr]map[addr.Addr][]drkey.HostHostKey
}

func (c *KeyCache) GetASHostKey(
	ctx context.Context,
	validity time.Time,
	srcIA addr.IA,
) (drkey.Key, error) {
	if c.cache == nil {
		c.cache = make(map[addr.IA][]drkey.ASHostKey)
	}

	keys, ok := c.cache[srcIA]
	if ok {
		for i := len(keys) - 1; i >= 0; i-- {
			if keys[i].Epoch.Contains(validity) {
				return keys[i].Key, nil
			}
		}
	}

	key, err := c.fetchASHostKey(ctx, validity, srcIA)
	if err != nil {
		return drkey.Key{}, err
	}
	if ok {
		c.cache[srcIA] = append(c.cache[srcIA], key)
	} else {
		c.cache[srcIA] = []drkey.ASHostKey{key}
	}
	return key.Key, nil
}

func (c *KeyCache) GetHostSelfKey(
	ctx context.Context,
	validity time.Time,
	srcAddr addr.Addr,
) (drkey.Key, error) {
	dstAddr := addr.Addr{
		IA:   c.DstIA,
		Host: addr.HostIP(c.DstHost),
	}
	return c.GetHostHostKey(ctx, validity, srcAddr, dstAddr)
}

func (c *KeyCache) GetHostHostKey(
	ctx context.Context,
	validity time.Time,
	srcAddr addr.Addr,
	dstAddr addr.Addr,
) (drkey.Key, error) {
	if c.hostCache == nil {
		c.hostCache = make(map[addr.Addr]map[addr.Addr][]drkey.HostHostKey)
	}

	// Search for key in cache
	var keys []drkey.HostHostKey
	var sok bool
	sources, dok := c.hostCache[dstAddr]
	if dok {
		keys, sok := sources[srcAddr]
		if sok {
			for i := len(keys) - 1; i >= 0; i-- {
				if keys[i].Epoch.Contains(validity) {
					return keys[i].Key, nil
				}
			}
		}
	}

	// Fetch key from daemon
	key, err := c.fetchHostHostKey(ctx, validity, srcAddr, dstAddr)
	if err != nil {
		return drkey.Key{}, err
	}

	// Add key to cache
	if !dok {
		sources = make(map[addr.Addr][]drkey.HostHostKey)
		c.hostCache[dstAddr] = sources
	}
	if !sok {
		keys = make([]drkey.HostHostKey, 0)
		sources[srcAddr] = keys
	}
	keys = append(keys, key)

	return key.Key, nil
}

func (c *KeyCache) RefreshKeys(ctx context.Context, keyDuration time.Duration) []error {

	errors := make([]error, 0)
	t := time.Now().Add(keyDuration / 2)

	if c.cache != nil {
		for srcIA, keys := range c.cache {
			if len(keys) == 0 || keys[len(keys)-1].Epoch.NotAfter.After(t) {
				key, err := c.fetchASHostKey(ctx, t, srcIA)
				if err != nil {
					errors = append(errors, err)
					continue
				}
				if len(keys) > 0 && keys[len(keys)-1].Epoch.Covers(key.Epoch.Validity) {
					continue
				}
				c.cache[srcIA] = append(c.cache[srcIA], key)
			}
		}
	}

	if c.hostCache != nil {
		for dstAddr, sources := range c.hostCache {
			for srcAddr, keys := range sources {
				if len(keys) == 0 || keys[len(keys)-1].Epoch.NotAfter.After(t) {
					key, err := c.fetchHostHostKey(ctx, t, srcAddr, dstAddr)
					if err != nil {
						errors = append(errors, err)
						continue
					}
					if len(keys) > 0 && keys[len(keys)-1].Epoch.Covers(key.Epoch.Validity) {
						continue
					}
					keys = append(keys, key)
				}
			}
		}
	}

	return errors
}

func (c *KeyCache) DeleteExpiredKeys(now time.Time) {
	if c.cache != nil {
		for srcIA, keys := range c.cache {
			for i, key := range keys {
				if key.Epoch.NotAfter.After(now) {
					c.cache[srcIA] = c.cache[srcIA][i:]
					break
				}
			}
		}
	}
	if c.hostCache != nil {
		for dstAddr, sources := range c.hostCache {
			for srcAddr, keys := range sources {
				// look for the youngest key that is no longer valid
				i := 0
				for i, _ = range keys {
					if keys[len(keys)-i].Epoch.NotAfter.Before(now) {
						break
					}
				}
				if (i + 1) < len(keys) {
					// remove expired keys at the end of the slice
					copy(keys[:], keys[i:])
					keys = keys[:i]
				} else {
					// all keys have expired
					delete(sources, srcAddr)
				}
			}
			if len(sources) == 0 {
				// all sources for a destination have expired
				delete(c.hostCache, dstAddr)
			}
		}
	}
}

// Gets an AS-Host key from Daemon.
func (c *KeyCache) fetchASHostKey(
	ctx context.Context,
	validity time.Time,
	srcIA addr.IA,
) (drkey.ASHostKey, error) {
	meta := drkey.ASHostMeta{
		ProtoId:  drkey.IDINT,
		Validity: validity,
		SrcIA:    srcIA,
		DstIA:    c.DstIA,
		DstHost:  c.DstHost.String(),
	}
	key, err := c.Sciond.DRKeyGetASHostKey(ctx, meta)
	if err != nil {
		return drkey.ASHostKey{}, err
	}
	return key, nil
}

// Gets a Host-Host key from Daemon.
func (c *KeyCache) fetchHostHostKey(
	ctx context.Context,
	validity time.Time,
	srcAddr addr.Addr,
	dstAddr addr.Addr,
) (drkey.HostHostKey, error) {
	meta := drkey.HostHostMeta{
		ProtoId:  drkey.IDINT,
		Validity: validity,
		SrcIA:    srcAddr.IA,
		DstIA:    dstAddr.IA,
		SrcHost:  srcAddr.Host.String(),
		DstHost:  dstAddr.Host.String(),
	}
	key, err := c.Sciond.DRKeyGetHostHostKey(ctx, meta)
	if err != nil {
		return drkey.HostHostKey{}, err
	}
	return key, nil
}
