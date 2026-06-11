package generator

import "embed"

//go:embed web/index.html web/app.js web/style.css
var WebFS embed.FS
