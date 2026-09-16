// Package repocheck holds repository-level invariants that are enforced as
// tests rather than as review habits.
//
// Nothing here is imported by the server. These are checks whose failure has no
// runtime symptom — the binary runs perfectly and somebody else discovers the
// problem — which is exactly the class of rule that quietly stops being true
// unless CI is the thing that remembers it.
package repocheck
