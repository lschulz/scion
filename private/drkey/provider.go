// Copyright 2024 OvGU Magdeburg
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

package drkey

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/arc/v2"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/drkey/specific"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	drkeypb "github.com/scionproto/scion/pkg/proto/drkey"
	"github.com/scionproto/scion/private/drkey/drkeyutil"
	"github.com/scionproto/scion/private/periodic"
	"github.com/scionproto/scion/router/config"
	"github.com/scionproto/scion/router/control"
)

const (
	// Maximum number of keys to fetch in parallel
	maxConcurrentKeyFetchers = 32
)

type cachedKey struct {
	lastAccess time.Time
	key        [2]drkey.Level1Key
}

func (c *cachedKey) getValidKey(validity time.Time) (drkey.Level1Key, bool) {
	for i := 0; i < 2; i++ {
		if c.key[i].Epoch.Contains(validity) {
			c.lastAccess = time.Now()
			return c.key[i], true
		}
	}
	return drkey.Level1Key{}, false
}

func (c *cachedKey) getExpiry() time.Time {
	if c.key[0].Epoch.NotAfter.After(c.key[1].Epoch.NotAfter) {
		return c.key[0].Epoch.NotAfter
	} else {
		return c.key[0].Epoch.NotAfter
	}
}

func (c *cachedKey) updateKey(key drkey.Level1Key) {
	if c.key[0].Epoch.NotAfter.Before(c.key[1].Epoch.NotAfter) {
		c.key[0] = key
	} else {
		c.key[1] = key
	}
}

// var errNotReachable = serrors.New("AS not reachable")
var ErrNotReady = serrors.New("key is being fetched")

// Fetcher obtains Level1 DRKeys from a local CS.
type Fetcher interface {
	Level1(ctx context.Context, meta drkey.Level1Meta) (drkey.Level1Key, error)
}

type Prefetcher interface {
	RefreshKeys(ctx context.Context)
}

type PrefetchTask struct {
	LocalIA     addr.IA
	Prefetcher  Prefetcher
	KeyDuration time.Duration
}

// Name returns the tasks name.
func (p *PrefetchTask) Name() string {
	return fmt.Sprintf("drkey_prefetcher_%s", p.LocalIA)
}

// Run requests the level 1 keys to other CSs via a local CS.
func (p *PrefetchTask) Run(ctx context.Context) {
	p.Prefetcher.RefreshKeys(ctx)
}

type Provider struct {
	// Identity of the local AS.
	localIA addr.IA
	// Lock protecting access to keyCache and fetching.
	cacheLock sync.Mutex
	// Level 1 DRKeys of all known responsive ASes.
	keyCache map[addr.IA]*cachedKey
	// Set of level 1 keys that are currently being fetched
	fetching map[addr.IA]context.CancelFunc
	// Dialer for connecting to CS
	dialer libgrpc.TCPDialer
	// Fait group for key fetching goroutines
	fetcherWg      sync.WaitGroup
	prefetchCache  *arc.ARCCache[addr.IA, struct{}]
	prefetcher     PrefetchTask
	prefetchRunner *periodic.Runner
}

func NewProvider(globalCfg *config.Config, controlCfg *control.Config) (*Provider, error) {
	prefetchCache, err := arc.NewARC[addr.IA, struct{}](globalCfg.DRKey.PrefetchEntries)
	if err != nil {
		return nil, serrors.WrapStr("creating Level1ARC cache", err)
	}
	provider := &Provider{
		localIA:       controlCfg.IA,
		keyCache:      make(map[addr.IA]*cachedKey, globalCfg.DRKey.PrefetchEntries),
		fetching:      make(map[addr.IA]context.CancelFunc, maxConcurrentKeyFetchers),
		prefetchCache: prefetchCache,
	}
	provider.prefetcher = PrefetchTask{
		LocalIA:     controlCfg.IA,
		Prefetcher:  provider,
		KeyDuration: drkeyutil.LoadEpochDuration(),
	}
	return provider, nil
}

func (p *Provider) SetDialer(dialer libgrpc.TCPDialer) {
	p.dialer = dialer
}

func (p *Provider) RunPrefetcher() error {
	p.prefetchRunner = periodic.Start(
		&p.prefetcher,
		p.prefetcher.KeyDuration/2,
		p.prefetcher.KeyDuration/2,
	)
	return nil
}

func (p *Provider) CancelAll() {
	if p.prefetchRunner != nil {
		p.prefetchRunner.Kill()
		p.prefetchRunner = nil
	}
	p.cancelFetchers()
	p.fetcherWg.Wait()
}

func (p *Provider) cancelFetchers() {
	p.cacheLock.Lock()
	defer p.cacheLock.Unlock()
	for _, cancel := range p.fetching {
		cancel()
	}
}

func (p *Provider) GetASHostKey(
	validTime time.Time,
	dstIA addr.IA,
	dstAddr addr.Host,
) (drkey.Key, error) {

	level1Key, err := p.getLevel1Key(validTime, dstIA)
	if err != nil {
		return drkey.Key{}, err
	}

	key, err := specific.Deriver{}.DeriveASHostFast(dstAddr, level1Key.Key)
	if err != nil {
		return drkey.Key{}, err
	}
	return key, nil
}

func (p *Provider) getLevel1Key(
	validity time.Time,
	dstIA addr.IA,
) (drkey.Level1Key, error) {
	p.prefetchCache.Add(dstIA, struct{}{})

	p.cacheLock.Lock()
	defer p.cacheLock.Unlock()

	e, ok := p.keyCache[dstIA]
	if !ok {
		p.fetchLevel1Key(validity, dstIA)
		return drkey.Level1Key{}, ErrNotReady
	}

	key, ok := e.getValidKey(validity)
	if !ok {
		p.fetchLevel1Key(validity, dstIA)
		return drkey.Level1Key{}, ErrNotReady
	}

	return key, nil
}

// Get Level1 key from CS.
// Precondition: cacheLock must be held
func (p *Provider) fetchLevel1Key(
	validity time.Time,
	dstIA addr.IA,
) {
	meta := drkey.Level1Meta{
		Validity: validity,
		SrcIA:    p.localIA,
		DstIA:    dstIA,
		ProtoId:  drkey.Protocol(drkeypb.Protocol_PROTOCOL_IDINT),
	}

	_, fetching := p.fetching[dstIA]
	if fetching || len(p.fetching) >= maxConcurrentKeyFetchers {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.fetching[dstIA] = cancel

	p.fetcherWg.Add(1)
	go func() {
		defer log.HandlePanic()
		defer p.fetcherWg.Done()

		fetcher := GrpcFetcher{
			Dialer: p.dialer,
		}
		err := fetcher.Dial(ctx, p.localIA)
		if err != nil {
			log.Error("fetching level 1 key", "err", err)
			return
		}
		defer fetcher.Close()
		key, err := fetcher.Level1(ctx, meta)

		p.cacheLock.Lock()
		defer p.cacheLock.Unlock()
		delete(p.fetching, dstIA)

		if err == nil {
			e := p.keyCache[dstIA]
			if e == nil {
				e = &cachedKey{}
				p.keyCache[dstIA] = e
			}
			e.updateKey(key)
		}
	}()
}

func (p *Provider) RefreshKeys(ctx context.Context) {
	fetcher := GrpcFetcher{Dialer: p.dialer}
	if err := fetcher.Dial(ctx, p.localIA); err != nil {
		log.Error("prefetching level 1 DRKeys", "err", err)
		return
	}
	defer fetcher.Close()

	validity := time.Now()
	for _, dstIA := range p.prefetchCache.Keys() {
		meta := drkey.Level1Meta{
			Validity: validity,
			SrcIA:    p.localIA,
			DstIA:    dstIA,
			ProtoId:  drkey.Protocol(drkeypb.Protocol_PROTOCOL_IDINT),
		}
		key, err := fetcher.Level1(ctx, meta)
		if err != nil {
			log.Error("prefetching level 1 DRKeys", "err", err)
		} else {
			p.updateKey(key)
		}
	}
}

func (p *Provider) updateKey(key drkey.Level1Key) {
	p.cacheLock.Lock()
	defer p.cacheLock.Unlock()

	e := p.keyCache[key.DstIA]
	if e == nil {
		e = &cachedKey{}
		p.keyCache[key.DstIA] = e
	}
	e.updateKey(key)
}
