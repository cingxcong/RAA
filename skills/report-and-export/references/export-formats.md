# Export formats

## Markdown

Use for human review, issue trackers and engagement notes. The document starts
with the artifact identity and SHA-256, then summary metrics, frameworks,
findings, signature status, coverage limitations and evidence IDs.

## JSON

Use for automation. The payload is the full `AnalysisReport` model, including
typed findings and evidence identifiers. Do not post-process `inferred`
confidence into `observed`.

## Naming

`report_generate` accepts an optional filename. Path separators are removed,
reserved Windows names are prefixed and the file is always written below the
project's export directory. A filename is not a security boundary; the export
directory is.
