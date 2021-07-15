package rtp

// PartitionHeadChecker is the interface that checks whether the packet is keyframe or not
// This is essentially func([]byte) bool, but for compatibility reasons is
// kept as an interface.  The analogous PartitionTailChecker is just a function.
type PartitionHeadChecker interface {
	IsPartitionHead([]byte) bool
}
