module velociraptor-ia/ia_forensic

// CVE detectes par govulncheck (GO-2026-4601, GO-2026-4602, GO-2026-4337, etc.)
// Correction disponible dans Go >= 1.25.8. Mettez a jour votre toolchain Go.
// Pour mettre a jour : https://golang.org/dl/
go 1.21

require github.com/mattn/go-sqlite3 v1.14.34
