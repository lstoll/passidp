package storage

import (
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkrotatev1 "lds.li/tinkrotate/proto/tinkrotate/v1"
)

var (
	keysetKeyCreatedTimestampSeconds = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "keyset_key_created_timestamp_seconds",
			Help: "Unix timestamp (seconds) when a key in a keyset was created",
		},
		[]string{"keyset_name", "key_id"},
	)

	keysetKeyCount = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "keyset_key_count",
			Help: "Number of keys in a keyset",
		},
		[]string{"keyset_name"},
	)

	stateBoltFileSizeBytes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "state_bolt_file_size_bytes",
			Help: "Size in bytes of the BoltDB state file",
		},
	)

	// reportedKeys tracks which keys we've reported metrics for, per keyset.
	// Map structure: keysetName -> map[keyID]bool
	reportedKeys sync.Map
)

func reportKeysetMetrics(keysetName string, handle *keyset.Handle, metadata *tinkrotatev1.KeyRotationMetadata) {
	if handle == nil || metadata == nil {
		return
	}

	keysetInfo := handle.KeysetInfo()
	if keysetInfo == nil {
		return
	}

	keyMetadataMap := metadata.GetKeyMetadata()
	keyCount := 0
	currentKeys := make(map[string]bool)

	for _, keyInfo := range keysetInfo.KeyInfo {
		keyID := fmt.Sprintf("%d", keyInfo.KeyId)
		currentKeys[keyID] = true
		keyCount++

		if keyMeta, ok := keyMetadataMap[keyInfo.KeyId]; ok && keyMeta != nil {
			creationTime := keyMeta.GetCreationTime()
			if creationTime != nil {
				unixSeconds := creationTime.AsTime().Unix()
				keysetKeyCreatedTimestampSeconds.WithLabelValues(keysetName, keyID).Set(float64(unixSeconds))
			}
		}
	}

	var previousKeys map[string]bool
	if prev, ok := reportedKeys.Load(keysetName); ok {
		previousKeys = prev.(map[string]bool)
	} else {
		previousKeys = make(map[string]bool)
	}

	for keyID := range previousKeys {
		if !currentKeys[keyID] {
			keysetKeyCreatedTimestampSeconds.DeleteLabelValues(keysetName, keyID)
		}
	}

	reportedKeys.Store(keysetName, currentKeys)
	keysetKeyCount.WithLabelValues(keysetName).Set(float64(keyCount))
}

func reportStateFileSize(path string) {
	size, err := getFileSize(path)
	if err != nil {
		return
	}
	stateBoltFileSizeBytes.Set(float64(size))
}
