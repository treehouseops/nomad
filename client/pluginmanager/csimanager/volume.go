package csimanager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nomad/helper/mount"
	"github.com/hashicorp/nomad/nomad/structs"
	"github.com/hashicorp/nomad/plugins/csi"
)

var _ VolumeMounter = &volumeManager{}

const (
	DefaultMountActionTimeout = 2 * time.Minute
	StagingDirName            = "staging"
	AllocSpecificDirName      = "per-alloc"
)

// volumeManager handles the state of attached volumes for a given CSI Plugin.
//
// volumeManagers outlive the lifetime of a given allocation as volumes may be
// shared by multiple allocations on the same node.
//
// volumes are stored by an eriched volume usage struct as the CSI Spec requires
// slightly different usage based on the given usage model.
type volumeManager struct {
	logger hclog.Logger
	plugin csi.CSIPlugin

	volumes   map[string]interface{}
	volumesMu sync.Mutex

	// mountRoot is the root of where plugin directories and mounts may be created
	// e.g /opt/nomad.d/statedir/csi/my-csi-plugin/
	mountRoot string

	requiresStaging bool

	// allocationsByVolume stores a map of volume-id:(alloc-id:allocation) for use
	// by the volume manager. This allows us to detemine when a volume is no longer
	// in use by the Nomad Client to perform an unstage volume request, and is also
	// used to produce node-wide volume usage stats.
	allocationsByVolume   map[string]map[string]*structs.Allocation
	allocationsByVolumeMu sync.Mutex
}

func newVolumeManager(logger hclog.Logger, plugin csi.CSIPlugin, rootDir string) *volumeManager {
	return &volumeManager{
		logger:    logger.Named("volume_manager"),
		plugin:    plugin,
		mountRoot: rootDir,

		volumes:             make(map[string]interface{}),
		allocationsByVolume: make(map[string]map[string]*structs.Allocation),
	}
}

// ClaimForAllocation performs the steps required for using a given volume
// configuration for the provided allocation.
//
// Currently it:
// - Checks to see ifh
// - Checks to see if mountRoot/staging/{volume-id}/{usage-options-hash}/ exists and is
//   likely to be a mountpoint. If this does not ex
//
// TODO: Validate remote volume attachment
func (v *volumeManager) MountVolume(ctx context.Context, vol *structs.CSIVolume, alloc *structs.Allocation) (*MountInfo, error) {
	var publishContext map[string]string
	stagingPath := ""
	targetPath := filepath.Join(v.mountRoot, AllocSpecificDirName, alloc.ID, "TODO-pass-and-hash-usage-opts")

	if v.requiresStaging {
		stagingPath = filepath.Join(v.mountRoot, StagingDirName, vol.ID, "TODO-pass-and-hash-usage-opts")

		// Make the staging path, owned by the Nomad User
		if err := os.MkdirAll(stagingPath, 0700); !os.IsExist(err) {
			return nil, fmt.Errorf("failed to create staging directory for volume (%s): %v", vol.ID, err)
		}

		// Validate that it is not already a mount point
		m := mount.New()
		isMount, err := m.IsNotAMountPoint(stagingPath)
		if err != nil {
			return nil, fmt.Errorf("mount point detection failed for volume (%s): %v", vol.ID, err)
		}

		if !isMount {
			// TODO: STAGE VOLUME
		}
	}

	return nil, nil
}

func (v *volumeManager) UnmountVolume(ctx context.Context, vol *structs.CSIVolume, alloc *structs.Allocation) error {
	return nil
}
