// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package gowsdl

var headerTmpl = `
// Code generated by gowsdl DO NOT EDIT.

package {{.Package}}

import (
	"context"
	"encoding/xml"
	"time"
	"github.com/eyetowers/gowsdl/soap"

	{{range $k, $v := .Imports}}
		{{replaceReservedWords $k}} "{{normalizePackage $v}}"
	{{end}}
)

// against "unused imports"
var _ time.Time
var _ xml.Name
var _ context.Context
var _ soap.SOAPEnvelope
`
