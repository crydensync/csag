package httpapi

import (
	"net/http"

	"github.com/crydensync/api/templates"
)

// EmailTemplatesHandlers backs the admin template-status endpoint. Its
// sole purpose is to report whether the console's templates are configured
// (a directory on disk, read at startup) and, if they are, to render a
// sample of each. The console's template editor is not built from this
// endpoint, templates are files on disk, not rows in the database, and
// the console has no endpoint to write them through.
type EmailTemplatesHandlers struct {
	// TemplateDir is the EMAIL_TEMPLATE_DIR value from config, or empty
	// when EMAIL_TEMPLATE_DIR was not set. The handler uses it only to
	// decide between "configured" (a dir on disk, render a sample) and
	// "not configured" (nil means the built-in lines, which this endpoint
	// cannot render since it has no access to them).
	TemplateDir string

	// Templates is the loaded set, nil when EMAIL_TEMPLATE_DIR was not set
	// or when the directory contained no valid templates. Both are normal
	// states, answered with their own sentences rather than as errors.
	Templates *templates.Set
}

// templateStatusDTO is what the screen needs to render the status row
// per template: configured or not, and if configured, a rendered sample.
type templateStatusDTO struct {
	// Kind is "verification" or "magic_link", the name the console shows.
	Kind     string `json:"kind"`
	Filename string `json:"filename"`
	// Configured is false when EMAIL_TEMPLATE_DIR was not set or when
	// the directory held no template for this kind.
	Configured bool   `json:"configured"`
	Sample     string `json:"sample,omitempty"`
	// SampleError is set only when the template was found but could not be
	// rendered, a parse error, or a template that uses an unknown field.
	// A rendering error on a template that was deployed is a real problem,
	// not a silent degradation, so it is surfaced rather than omitted.
	SampleError string `json:"sample_error,omitempty"`
}

// emailTemplatesDTO is the whole answer. The two kinds map directly to
// the two files templates.go defines, and to the two senders the console
// stand-ins implement.
type emailTemplatesDTO struct {
	// Configured is true when EMAIL_TEMPLATE_DIR was set and the directory
	// contained at least one readable template. False means the built-in
	// lines are in use, and the screen explains what EMAIL_TEMPLATE_DIR
	// unlocks rather than showing empty cells.
	Configured bool `json:"configured"`

	// EmailTemplateDir is the absolute path of the configured directory,
	// or empty when not configured. The console shows it in the status so
	// an operator can audit where their copy lives.
	EmailTemplateDir string `json:"email_template_dir,omitempty"`

	Kinds []templateStatusDTO `json:"kinds"`
}

// EmailTemplates returns which templates this deployment has and a rendered
// sample of each. GET /v1/admin/settings/email-templates.
//
// It does not expose a write path: templates are files on disk, and this
// endpoint's only job is reporting whether they are configured and what
// they would say. An operator who wants to change them does so on the host
// filesystem, same as they would change any configuration file. The
// "reset to default" and "save template" buttons in a prototype template
// editor have no server path, since there is nothing here to save into or
// reset from.
//
// Not behind adminOnly: reading a template file and rendering it is a safe,
// read-only operation, and the email template content is already in the
// operator's own control by definition (they are the ones who put the
// files on disk). Admin-only would mean SQLite still blocking an operator
// from seeing the status of a feature they cannot use anyway. But it IS
// behind RequireAuth, since a template that was written and deployed is
// operator-level content, not a public reference document.
func (h *EmailTemplatesHandlers) EmailTemplates(w http.ResponseWriter, r *http.Request) {
	var dto emailTemplatesDTO

	if h.TemplateDir != "" {
		dto.Configured = true
		dto.EmailTemplateDir = h.TemplateDir
	}

	dto.Kinds = []templateStatusDTO{
		{Kind: "verification", Filename: templates.VerificationFile},
		{Kind: "magic_link", Filename: templates.MagicLinkFile},
	}
	// Populate Configured before rendering, the loop below needs it.
	for i := range dto.Kinds {
		s := &dto.Kinds[i]
		switch s.Kind {
		case "verification":
			if h.Templates != nil {
				_, ok, _ := h.Templates.Verification(templates.Data{})
				s.Configured = ok
			}
		case "magic_link":
			if h.Templates != nil {
				_, ok, _ := h.Templates.MagicLink(templates.Data{})
				s.Configured = ok
			}
		}
	}

	for i := range dto.Kinds {
		status := &dto.Kinds[i]
		if !status.Configured {
			continue
		}
		sampleData := templates.Data{
			To:    "status@example.com",
			Token: "SAMPLE_TOKEN",
			URL:   "https://example.com/magic-link?token=SAMPLE_TOKEN",
		}
		var body string
		var ok bool
		var err error
		if status.Kind == "verification" {
			body, ok, err = h.Templates.Verification(sampleData)
		} else {
			body, ok, err = h.Templates.MagicLink(sampleData)
		}
		if err != nil {
			status.SampleError = err.Error()
			continue
		}
		if !ok {
			status.Configured = false
			continue
		}
		status.Sample = body
	}

	writeData(w, http.StatusOK, dto)
}
