package core

import (
	"context"
	"crypto/ecdsa"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/sonm-io/core/accounts"
	"github.com/sonm-io/core/proto"
	"github.com/sonm-io/core/util"
	"github.com/sonm-io/core/util/xgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	dwhUpdateInterval = 5 * time.Second
)

var accountSlotsDefaults = map[uint64]uint64{
	0: 16,
	1: 32,
	2: 64,
	3: 128,
	4: 256,
}

type SonmConfig struct {
	KeyPath     string
	KeyPass     string
	DWHEndpoint string
}

var DefaultSonmConfig = SonmConfig{
	DWHEndpoint: "0xadffcac607a0a1b583c489977eae413a62d4bc73@dwh.livenet.sonm.com:15021",
}

type SonmExtension interface {
	AccountSlots(common.Address) uint64
	ValidateTransaction(tx *types.Transaction, local bool) error
	Stop()
}

type sonmExtension struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.RWMutex

	dwhConn   *grpc.ClientConn
	dwh       sonm.DWHClient
	key       *ecdsa.PrivateKey
	accLevels map[common.Address]uint64

	wg sync.WaitGroup
}

func (m *sonmExtension) Stop() {
	m.cancel()
	m.wg.Wait()
	log.Info("SONM Extensions stopped")
}

func (m *sonmExtension) ValidateTransaction(tx *types.Transaction, local bool) error {
	return nil
}

func (m *sonmExtension) AccountSlots(addr common.Address) uint64 {
	m.mu.RLock()
	defer m.mu.Unlock()

	level, ok := m.accLevels[addr]
	if !ok {
		sonmAddr := sonm.NewEthAddress(addr)
		profile, err := m.dwh.GetProfileInfo(m.ctx, &sonm.EthID{Id: sonmAddr})

		if err != nil {
			log.Warn("Failed to get profile info for account", "account", addr, "err", err)
			return accountSlotsDefaults[0]
		}

		m.accLevels[addr] = profile.IdentityLevel
		level = profile.IdentityLevel
	}

	if slots, ok := accountSlotsDefaults[level]; ok {
		return slots
	}

	return accountSlotsDefaults[0]
}

func (m *sonmExtension) updateLevelInfo() {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Info("Updaring SONM account level infos")

	for acc, level := range m.accLevels {
		profile, err := m.dwh.GetProfileInfo(m.ctx, &sonm.EthID{Id: sonm.NewEthAddress(acc)})

		if err != nil {
			continue
		}

		if level == profile.IdentityLevel {
			continue
		}

		m.accLevels[acc] = profile.IdentityLevel
	}
}

func (m *sonmExtension) loop() {
	defer m.wg.Done()
	update := time.NewTicker(dwhUpdateInterval)

	for {
		select {
		case <-update.C:
			m.updateLevelInfo()
		case <-m.ctx.Done():
			return
		}
	}
}

func NewSonmExtension(cfg SonmConfig) (SonmExtension, error) {
	se := &sonmExtension{}

	key, err := accounts.OpenSingleKeystore(cfg.KeyPath, cfg.KeyPass, accounts.NewStaticPassPhraser(cfg.KeyPass))
	if err != nil {
		return nil, err
	}

	se.ctx, se.cancel = context.WithCancel(context.Background())

	se.key = key

	transportCredentials, err := newTLS(se.ctx, key)
	if err != nil {
		return nil, err
	}

	dwhCC, err := xgrpc.NewClient(se.ctx, cfg.DWHEndpoint, transportCredentials)
	if err != nil {
		return nil, err
	}

	se.dwh = sonm.NewDWHClient(dwhCC)

	se.wg.Add(1)
	go se.loop()

	return se, nil
}

func newTLS(ctx context.Context, privateKey *ecdsa.PrivateKey) (credentials.TransportCredentials, error) {
	_, tlsConfig, err := util.NewHitlessCertRotator(ctx, privateKey)
	return util.NewTLS(tlsConfig), err
}
