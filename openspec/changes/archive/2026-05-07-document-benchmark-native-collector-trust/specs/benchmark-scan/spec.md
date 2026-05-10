## MODIFIED Requirements

### Requirement: Benchmark runtime SHALL use native collectors and YAML rule metadata
The benchmark runtime SHALL use Go-native collectors and YAML-defined rule metadata for `windows`, `linux`, `euleros`, and `kylin` templates across all supported baseline levels while preserving each template's benchmark semantics. The runtime MUST NOT invoke external commands, shell pipelines, or vendor benchmark scripts to obtain benchmark facts for any template-level check.

#### Scenario: Windows benchmark runs without command or script collection
- **WHEN** the user executes `c-eyes benchmark --template windows --baseline-level 4`
- **THEN** benchmark completes using Go-native Windows collectors and YAML rule metadata
- **AND** benchmark does not invoke external `.exe`, `.cmd`, `.bat`, `.ps1`, `.vbs`, `.pl`, or similar command/script collectors to obtain Windows baseline facts

#### Scenario: Linux-family benchmark uses native fact collection for any level
- **WHEN** the user executes `c-eyes benchmark --template linux --baseline-level 3`
- **THEN** benchmark collects Linux baseline facts from in-process native readers, OS files, or platform APIs
- **AND** benchmark does not invoke shell commands or packaged benchmark scripts to obtain those facts

#### Scenario: EulerOS and Kylin templates stay on the same native-only contract
- **WHEN** the user executes `c-eyes benchmark --template euleros` or `c-eyes benchmark --template kylin`
- **THEN** the selected template uses the same native-only fact-collection contract as `linux`
- **AND** no template-specific benchmark fact is sourced from command execution or vendor script replay

## ADDED Requirements

### Requirement: Benchmark native policy results SHALL prefer trustworthy native sources
Benchmark policy evaluation MUST return determinate results when the operating system exposes a trustworthy native source for the requested field. The implementation MUST NOT degrade such checks to `unknown` because of avoidable access-mask mistakes, incorrect native API selection, or other implementation-level collector defects.

#### Scenario: Native Windows password policy fields return determinate values
- **WHEN** benchmark evaluates Windows security policy fields such as `PasswordComplexity`, `AllowAdministratorLockout`, or `ClearTextPassword`
- **THEN** the values are collected from trustworthy native Windows security interfaces
- **AND** the resulting row values reflect the effective local security policy instead of `unknown`

#### Scenario: Missing trustworthy native source remains unknown without command fallback
- **WHEN** a benchmark field has no sufficiently trustworthy native source on the current platform
- **THEN** benchmark marks that row as undetermined/`unknown`
- **AND** benchmark does not fall back to external command execution, shell parsing, or vendor script replay to synthesize a value

#### Scenario: Native collector semantics remain comparable to platform truth
- **WHEN** maintainers validate native benchmark output against platform policy exports or equivalent operating-system truth sources
- **THEN** the native collector values match the effective policy semantics for the same fields
- **AND** benchmark rule evaluation produces the same pass/fail outcome those effective values imply
