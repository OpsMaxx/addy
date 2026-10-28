// Package addy embeds the documentation the relay serves at /docs, from where
// it lives in the repository, so the pages and the files cannot drift apart.
//
// Go embeds only from a package's own directory and below, and the documents
// live at the root and in docs/, so the embed has to be here.
package addy

import "embed"

// Docs holds the user-facing documents. The research and review notes in
// docs/ are deliberately left out: they record how decisions were reached,
// and a reader looking for how to run a relay should not land in one.
//
//go:embed README.md THREAT_MODEL.md docs/ADMIN.md docs/OPERATOR-SIGNIN.md docs/PROTOCOL.md docs/DESIGN.md
var Docs embed.FS
