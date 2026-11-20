package provider

// ManagedStamp is private provider evidence of a committed batch, independent of
// public alert labels, suppression, subscriber delivery, and subsequent GC.
type ManagedStamp struct {
	Generation      int64
	Attempt, Digest string
}
