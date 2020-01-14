package structs

import (
	"fmt"
	"strings"
	"time"
)

// CSISocketName is the filename that Nomad expects plugins to create inside the
// PluginMountDir.
const CSISocketName = "csi.sock"

// CSIIntermediaryDirname is the name of the directory inside the PluginMountDir
// where Nomad will expect plugins to create intermediary mounts for volumes.
const CSIIntermediaryDirname = "volumes"

// VolumeTypeCSI is the type in the volume stanza of a TaskGroup
const VolumeTypeCSI = "csi"

// CSIPluginType is an enum string that encapsulates the valid options for a
// CSIPlugin stanza's Type. These modes will allow the plugin to be used in
// different ways by the client.
type CSIPluginType string

const (
	// CSIPluginTypeNode indicates that Nomad should only use the plugin for
	// performing Node RPCs against the provided plugin.
	CSIPluginTypeNode CSIPluginType = "node"

	// CSIPluginTypeController indicates that Nomad should only use the plugin for
	// performing Controller RPCs against the provided plugin.
	CSIPluginTypeController CSIPluginType = "controller"

	// CSIPluginTypeMonolith indicates that Nomad can use the provided plugin for
	// both controller and node rpcs.
	CSIPluginTypeMonolith CSIPluginType = "monolith"
)

// CSIPluginTypeIsValid validates the given CSIPluginType string and returns
// true only when a correct plugin type is specified.
func CSIPluginTypeIsValid(pt CSIPluginType) bool {
	switch pt {
	case CSIPluginTypeNode, CSIPluginTypeController, CSIPluginTypeMonolith:
		return true
	default:
		return false
	}
}

// TaskCSIPluginConfig contains the data that is required to setup a task as a
// CSI plugin. This will be used by the csi_plugin_supervisor_hook to configure
// mounts for the plugin and initiate the connection to the plugin catalog.
type TaskCSIPluginConfig struct {
	// ID is the identifier of the plugin.
	// Ideally this should be the FQDN of the plugin.
	ID string

	// Type instructs Nomad on how to handle processing a plugin
	Type CSIPluginType

	// MountDir is the destination that nomad should mount in its CSI
	// directory for the plugin. It will then expect a file called CSISocketName
	// to be created by the plugin, and will provide references into
	// "MountDir/CSIIntermediaryDirname/{VolumeName}/{AllocID} for mounts.
	MountDir string
}

func (t *TaskCSIPluginConfig) Copy() *TaskCSIPluginConfig {
	if t == nil {
		return nil
	}

	nt := new(TaskCSIPluginConfig)
	*nt = *t

	return nt
}

// CSIVolumeAttachmentMode chooses the type of storage api that will be used to
// interact with the device.
type CSIVolumeAttachmentMode string

const (
	CSIVolumeAttachmentModeUnknown     CSIVolumeAttachmentMode = ""
	CSIVolumeAttachmentModeBlockDevice CSIVolumeAttachmentMode = "block-device"
	CSIVolumeAttachmentModeFilesystem  CSIVolumeAttachmentMode = "file-system"
)

func ValidCSIVolumeAttachmentMode(attachmentMode CSIVolumeAttachmentMode) bool {
	switch attachmentMode {
	case CSIVolumeAttachmentModeBlockDevice, CSIVolumeAttachmentModeFilesystem:
		return true
	default:
		return false
	}
}

// CSIVolumeAccessMode indicates how a volume should be used in a storage topology
// e.g whether the provider should make the volume available concurrently.
type CSIVolumeAccessMode string

const (
	CSIVolumeAccessModeUnknown CSIVolumeAccessMode = ""

	CSIVolumeAccessModeSingleNodeReader CSIVolumeAccessMode = "single-node-reader-only"
	CSIVolumeAccessModeSingleNodeWriter CSIVolumeAccessMode = "single-node-writer"

	CSIVolumeAccessModeMultiNodeReader       CSIVolumeAccessMode = "multi-node-reader-only"
	CSIVolumeAccessModeMultiNodeSingleWriter CSIVolumeAccessMode = "multi-node-single-writer"
	CSIVolumeAccessModeMultiNodeMultiWriter  CSIVolumeAccessMode = "multi-node-multi-writer"
)

// ValidCSIVolumeAccessMode checks to see that the provided access mode is a valid,
// non-empty access mode.
func ValidCSIVolumeAccessMode(accessMode CSIVolumeAccessMode) bool {
	switch accessMode {
	case CSIVolumeAccessModeSingleNodeReader, CSIVolumeAccessModeSingleNodeWriter,
		CSIVolumeAccessModeMultiNodeReader, CSIVolumeAccessModeMultiNodeSingleWriter,
		CSIVolumeAccessModeMultiNodeMultiWriter:
		return true
	default:
		return false
	}
}

// ValidCSIVolumeAccessMode checks for a writable access mode
func ValidCSIVolumeWriteAccessMode(accessMode CSIVolumeAccessMode) bool {
	switch accessMode {
	case CSIVolumeAccessModeSingleNodeWriter,
		CSIVolumeAccessModeMultiNodeSingleWriter,
		CSIVolumeAccessModeMultiNodeMultiWriter:
		return true
	default:
		return false
	}
}

// CSIVolume is the full representation of a CSI Volume
type CSIVolume struct {
	ID             string
	Driver         string
	Namespace      string
	Topologies     []*CSITopology
	AccessMode     CSIVolumeAccessMode
	AttachmentMode CSIVolumeAttachmentMode

	// Allocations, tracking claim status
	ReadAllocs  map[string]*Allocation
	WriteAllocs map[string]*Allocation
	PastAllocs  map[string]*Allocation

	// Healthy is true if all the denormalized plugin health fields are true, and the
	// volume has not been marked for garbage collection
	Healthy            bool
	VolumeGC           time.Time
	PluginID           string
	ControllerHealthy  int
	ControllerExpected int
	Controller         []*Job
	NodeHealthy        int
	NodeExpected       int
	ResourceExhausted  time.Time

	CreateIndex uint64
	ModifyIndex uint64
}

// CSIVolListStub is partial representation of a CSI Volume for inclusion in lists
type CSIVolListStub struct {
	ID                 string
	Driver             string
	Namespace          string
	Topologies         []*CSITopology
	AccessMode         CSIVolumeAccessMode
	AttachmentMode     CSIVolumeAttachmentMode
	CurrentReaders     int
	CurrentWriters     int
	Healthy            bool
	VolumeGC           time.Time
	ControllerName     string
	ControllerHealthy  int
	ControllerExpected int
	NodeHealthy        int
	NodeExpected       int
	CreateIndex        uint64
	ModifyIndex        uint64
}

func CreateCSIVolume(controllerName string) *CSIVolume {
	return &CSIVolume{
		PluginID:    controllerName,
		ReadAllocs:  map[string]*Allocation{},
		WriteAllocs: map[string]*Allocation{},
		PastAllocs:  map[string]*Allocation{},
		Topologies:  []*CSITopology{},
	}
}

func (v *CSIVolume) Stub() *CSIVolListStub {
	stub := CSIVolListStub{
		ID:                v.ID,
		Driver:            v.Driver,
		Namespace:         v.Namespace,
		Topologies:        v.Topologies,
		AccessMode:        v.AccessMode,
		AttachmentMode:    v.AttachmentMode,
		CurrentReaders:    len(v.ReadAllocs),
		CurrentWriters:    len(v.WriteAllocs),
		Healthy:           v.Healthy,
		VolumeGC:          v.VolumeGC,
		ControllerName:    v.PluginID,
		ControllerHealthy: v.ControllerHealthy,
		NodeHealthy:       v.NodeHealthy,
		NodeExpected:      v.NodeExpected,
		CreateIndex:       v.CreateIndex,
		ModifyIndex:       v.ModifyIndex,
	}

	return &stub
}

func (v *CSIVolume) CanReadOnly() bool {
	if !v.Healthy {
		return false
	}

	return v.ResourceExhausted == time.Time{}
}

func (v *CSIVolume) CanWrite() bool {
	if !v.Healthy {
		return false
	}

	switch v.AccessMode {
	case CSIVolumeAccessModeSingleNodeWriter, CSIVolumeAccessModeMultiNodeSingleWriter:
		return len(v.WriteAllocs) == 0
	case CSIVolumeAccessModeMultiNodeMultiWriter:
		return v.ResourceExhausted == time.Time{}
	default:
		return false
	}
}

func (v *CSIVolume) Claim(claim CSIVolumeClaimMode, alloc *Allocation) bool {
	switch claim {
	case CSIVolumeClaimRead:
		return v.ClaimRead(alloc)
	case CSIVolumeClaimWrite:
		return v.ClaimWrite(alloc)
	case CSIVolumeClaimRelease:
		return v.ClaimRelease(alloc)
	}
	return false
}

func (v *CSIVolume) ClaimRead(alloc *Allocation) bool {
	if !v.CanReadOnly() {
		return false
	}
	v.ReadAllocs[alloc.ID] = alloc
	delete(v.WriteAllocs, alloc.ID)
	delete(v.PastAllocs, alloc.ID)
	return true
}

func (v *CSIVolume) ClaimWrite(alloc *Allocation) bool {
	if !v.CanWrite() {
		return false
	}
	v.WriteAllocs[alloc.ID] = alloc
	delete(v.ReadAllocs, alloc.ID)
	delete(v.PastAllocs, alloc.ID)
	return true
}

func (v *CSIVolume) ClaimRelease(alloc *Allocation) bool {
	delete(v.ReadAllocs, alloc.ID)
	delete(v.WriteAllocs, alloc.ID)
	v.PastAllocs[alloc.ID] = alloc
	return true
}

// GCAlloc is called on Allocation gc, by following the alloc's pointer back to the volume
func (v *CSIVolume) GCAlloc(alloc *Allocation) {
	delete(v.ReadAllocs, alloc.ID)
	delete(v.WriteAllocs, alloc.ID)
	delete(v.PastAllocs, alloc.ID)
}

// Equality by value
func (v *CSIVolume) Equal(o *CSIVolume) bool {
	if v == nil || o == nil {
		return v == o
	}

	// Omit the plugin health fields, their values are controlled by plugin jobs
	if v.ID == o.ID &&
		v.Driver == o.Driver &&
		v.Namespace == o.Namespace &&
		v.AccessMode == o.AccessMode &&
		v.AttachmentMode == o.AttachmentMode &&
		v.PluginID == o.PluginID {
		// Setwise equality of topologies
		var ok bool
		for _, t := range v.Topologies {
			ok = false
			for _, u := range o.Topologies {
				if t.Equal(u) {
					ok = true
					break
				}
			}
			if !ok {
				return false
			}
		}
		return true
	}
	return false
}

// Validate validates the volume struct, returning all validation errors at once
func (v *CSIVolume) Validate() error {
	errs := []string{}

	if v.ID == "" {
		errs = append(errs, "missing volume id")
	}
	if v.Driver == "" {
		errs = append(errs, "missing driver")
	}
	if v.Namespace == "" {
		errs = append(errs, "missing namespace")
	}
	if v.AccessMode == "" {
		errs = append(errs, "missing access mode")
	}
	if v.AttachmentMode == "" {
		errs = append(errs, "missing attachment mode")
	}

	var ok bool
	for _, t := range v.Topologies {
		if t != nil && len(t.Segments) > 0 {
			ok = true
			break
		}
	}
	if !ok {
		errs = append(errs, "missing topology")
	}

	if len(errs) > 0 {
		return fmt.Errorf("validation: %s", strings.Join(errs, ", "))
	}
	return nil
}

// Request and response wrappers
type CSIVolumeRegisterRequest struct {
	Volumes []*CSIVolume
	WriteRequest
}

type CSIVolumeRegisterResponse struct {
	QueryMeta
}

type CSIVolumeDeregisterRequest struct {
	VolumeIDs []string
	WriteRequest
}

type CSIVolumeDeregisterResponse struct {
	QueryMeta
}

type CSIVolumeClaimMode int

const (
	CSIVolumeClaimRead CSIVolumeClaimMode = iota
	CSIVolumeClaimWrite
	CSIVolumeClaimRelease
)

type CSIVolumeClaimRequest struct {
	VolumeID   string
	Allocation *Allocation
	Claim      CSIVolumeClaimMode
	WriteRequest
}

type CSIVolumeListRequest struct {
	Driver string
	QueryOptions
}

type CSIVolumeListResponse struct {
	Volumes []*CSIVolListStub
	QueryMeta
}

type CSIVolumeGetRequest struct {
	ID string
	QueryOptions
}

type CSIVolumeGetResponse struct {
	Volume *CSIVolume
	QueryMeta
}

// CSIPlugin bundles job and info context for the plugin for clients
type CSIPlugin struct {
	ID        string
	Type      CSIPluginType
	Namespace string // FIXME all jobs in the same namespace?
	Jobs      map[string]map[string]*Job

	ControllerHealthy int
	Controllers       map[string]*CSIInfo
	NodeHealthy       int
	Nodes             map[string]*CSIInfo

	CreateIndex uint64
	ModifyIndex uint64
}

func NewCSIPlugin(id, driver string, index uint64) *CSIPlugin {
	return &CSIPlugin{
		ID:          id,
		Driver:      driver,
		Jobs:        map[string]map[string]*Job{},
		Controllers: map[string]*CSIInfo{},
		Nodes:       map[string]*CSIInfo{},
		CreateIndex: index,
		ModifyIndex: index,
	}
}

func (p *CSIPlugin) AddPlugin(nodeID string, info *CSIInfo, index uint64) {
	if info.ControllerInfo != nil {
		prev, ok := p.Controllers[nodeID]
		if ok && prev.Healthy {
			p.ControllerHealthy -= 1
		}
		p.Controllers[nodeID] = info
		if info.Healthy {
			p.ControllerHealthy += 1
		}
	}

	if info.NodeInfo != nil {
		prev, ok := p.Nodes[nodeID]
		if ok && prev.Healthy {
			p.NodeHealthy -= 1
		}
		p.Nodes[nodeID] = info
		if info.Healthy {
			p.NodeHealthy += 1
		}
	}

	p.ModifyIndex = index
}

func (p *CSIPlugin) DeletePlugins(nodeID string, index uint64) {
	prev, ok := p.Controllers[nodeID]
	if ok && prev.Healthy {
		p.ControllerHealthy -= 1
	}
	delete(p.Controllers, nodeID)

	prev, ok = p.Nodes[nodeID]
	if ok && prev.Healthy {
		p.NodeHealthy -= 1
	}
	delete(p.Nodes, nodeID)

	p.ModifyIndex = index
}

type CSIPluginListStub struct {
	ID                 string
	Type               CSIPluginType
	JobIDs             map[string]map[string]struct{}
	ControllerHealthy  int
	ControllerExpected int
	NodeHealthy        int
	NodeExpected       int
	CreateIndex        uint64
	ModifyIndex        uint64
}

func (p *CSIPlugin) Stub() *CSIPluginListStub {
	ids := map[string]map[string]struct{}{}
	for ns, js := range p.Jobs {
		ids[ns] = map[string]struct{}{}
		for id := range js {
			ids[ns][id] = struct{}{}
		}
	}

	return &CSIPluginListStub{
		ID:                 p.ID,
		Type:               p.Type,
		JobIDs:             ids,
		ControllerHealthy:  p.ControllerHealthy,
		ControllerExpected: len(p.Controllers),
		NodeHealthy:        p.NodeHealthy,
		NodeExpected:       len(p.Nodes),
		CreateIndex:        p.CreateIndex,
		ModifyIndex:        p.ModifyIndex,
	}
}

func (p *CSIPlugin) IsEmpty() bool {
	if !(len(p.Controllers) == 0 && len(p.Nodes) == 0) {
		return false
	}

	empty := true
	for _, m := range p.Jobs {
		if len(m) > 0 {
			empty = false
		}
	}
	return empty
}

type CSIPluginListRequest struct {
	Driver string
	QueryOptions
}

type CSIPluginListResponse struct {
	Plugins []*CSIPluginListStub
	QueryMeta
}

type CSIPluginGetRequest struct {
	ID string
	QueryOptions
}

type CSIPluginGetResponse struct {
	Plugin *CSIPlugin
	QueryMeta
}
