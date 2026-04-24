## MODIFIED Requirements

### Requirement: Cloud upload is opt-in and gated as final defense
The system MUST keep cloud sample upload disabled by default. For online modes (`cloud_only`, `fast`, `smart`, `deep`), cloud upload SHALL execute as a final-defense evidence path when all gate conditions are satisfied: `-cloud-upload=true`, target is uploadable (readable file, not directory, size within limit), and pre-upload stages do not provide an explicit terminal conclusion. The `local_only` mode MUST NOT upload samples even when `-cloud-upload=true`.

#### Scenario: Upload remains disabled by default
- **WHEN** a user runs risk analysis without explicitly setting `-cloud-upload=true`
- **THEN** the analyzer MUST NOT submit files to cloud providers

#### Scenario: Unresolved online-mode record triggers upload fallback
- **WHEN** mode is `cloud_only`, `fast`, `smart`, or `deep`, `-cloud-upload=true`, and pre-upload stages do not produce explicit terminal conclusion for a record
- **THEN** the analyzer submits the uploadable file to configured upload-capable providers

#### Scenario: Local-only mode never uploads
- **WHEN** mode is `local_only` and `-cloud-upload=true`
- **THEN** the analyzer skips upload with reason indicating local-only mode

### Requirement: High-confidence conclusions block upload
The system SHALL skip cloud upload only when an explicit terminal conclusion is already available from pre-upload stages: whitelist terminal decision (`allow` or `deny`), high-confidence local malicious conclusion, or high-confidence cloud hash conclusion. Score-only terminal heuristics (for example, pre-score extremely low/high) MUST NOT block upload by themselves.

#### Scenario: Whitelist deny blocks upload
- **WHEN** whitelist decision is `deny`
- **THEN** the analyzer finalizes the verdict without submitting any file upload

#### Scenario: High-confidence cloud hash hit blocks upload
- **WHEN** cloud hash analysis reaches high-confidence malicious threshold before upload stage
- **THEN** the analyzer skips file upload and returns final result with existing evidence

#### Scenario: Score-only low-risk pre-score does not block upload
- **WHEN** `-cloud-upload=true`, pre-upload score is very low, and no explicit terminal conclusion is present
- **THEN** the analyzer still enters upload stage for uploadable targets
