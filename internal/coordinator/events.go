package coordinator

// Activity-log event kinds. Centralised so the full catalogue is visible in one
// place and typos can't silently create a new "kind". The dotted namespace
// (<entity>.<action>) is what the web UI and webhook consumers filter on.
const (
	evAdminLogin       = "admin.login"
	evNodeEnroll       = "node.enroll"
	evNodePending      = "node.pending"
	evNodeApprove      = "node.approve"
	evNodeRekey        = "node.rekey"
	evNodeRoutes       = "node.routes"
	evNodeTags         = "node.tags"
	evNodeDelete       = "node.delete"
	evStaticPeerCreate = "static_peer.create"
	evStaticPeerDelete = "static_peer.delete"
	evStaticPeerTags   = "static_peer.tags"
	evPublishCreate    = "publish.create"
	evPublishDelete    = "publish.delete"
	evPolicyCreate     = "policy.create"
	evPolicyDelete     = "policy.delete"
	evLockInit         = "lock.init"
	evLockActive       = "lock.active"
)
