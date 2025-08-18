
package netonline

// Evaluate recomputes the passive "online" state immediately using the
// same heuristic as the event engine (routes + iface + usable IP + DNS, etc.).
func Evaluate() (bool, string, error) {
	return recomputeOnline()
}
