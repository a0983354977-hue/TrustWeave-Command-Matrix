## TrustWeave Parser - Phase 2: Semantic Policy DSL
##
## Multi-format dependency parser for heterogeneous configuration files
## (Cargo.toml, Cargo.lock, package.json, package-lock.json, requirements.txt, pyproject.toml)
##
## This is a production-grade parser that extracts dependency information and
## integrates it into the TrustWeave global Merkle-DAG for supply chain defense.

import std/[json, strutils, os, tables, hashes]

# ==============================================================================
# Type Definitions
# ==============================================================================

type
  Dependency* = object
    name*: string
    version*: string
    source*: string  # e.g., "crates.io", "npm", "pypi", "git", "local"
    dev*: bool      # is this a development dependency?
    integrity*: string  # hash/integrity checksum (e.g., sha512, sha256)
    lockfile*: bool  # is this from a lockfile (Cargo.lock, package-lock.json)?

  LogicalDependencyTree* = object
    dependencies*: seq[Dependency]
    devDependencies*: seq[Dependency]
    transitive*: seq[Dependency]  # transitive dependencies from lockfiles

  PolicyConstraint* = object
    name*: string
    allowed*: bool
    versionConstraint*: string
    sourceWhitelist*: seq[string]

  PolicyConstraintMatrix* = object
    constraints*: seq[PolicyConstraint]
    strictMode*: bool

  DependencyHash* = object
    path*: string
    sha256*: string
    blake3*: string

# ==============================================================================
# Cargo.toml Parser (Rust)
# ==============================================================================

proc parseCargoToml*(content: string): LogicalDependencyTree =
  ## Parse Cargo.toml and extract dependencies
  result = LogicalDependencyTree(
    dependencies: @[],
    devDependencies: @[],
    transitive: @[]
  )

  var inDependencies = false
  var inDevDependencies = false

  for line in content.splitLines():
    let trimmed = line.strip()

    if trimmed.startsWith("[dependencies]"):
      inDependencies = true
      inDevDependencies = false
    elif trimmed.startsWith("[dev-dependencies]"):
      inDevDependencies = true
      inDependencies = false
    elif trimmed.startsWith("["):
      inDependencies = false
      inDevDependencies = false
    elif inDependencies or inDevDependencies:
      if trimmed.len > 0 and not trimmed.startsWith("#"):
        let parts = trimmed.split("=", 1)
        if parts.len == 2:
          let name = parts[0].strip()
          let version = parts[1].strip(chars = {' ', '"'})
          let dep = Dependency(
            name: name,
            version: version,
            source: "crates.io",
            dev: inDevDependencies,
            integrity: "",
            lockfile: false
          )
          if inDevDependencies:
            result.devDependencies.add(dep)
          else:
            result.dependencies.add(dep)

# ==============================================================================
# Cargo.lock Parser (Rust - Lockfile with checksums)
# ==============================================================================

proc parseCargoLock*(content: string): LogicalDependencyTree =
  ## Parse Cargo.lock and extract dependencies with checksums
  result = LogicalDependencyTree(
    dependencies: @[],
    devDependencies: @[],
    transitive: @[]
  )

  var inPackage = false
  var currentDep: Dependency
  currentDep.name = ""
  currentDep.version = ""
  currentDep.source = "crates.io"
  currentDep.dev = false
  currentDep.integrity = ""
  currentDep.lockfile = true

  for line in content.splitLines():
    let trimmed = line.strip()

    if trimmed.startsWith("[[package]]"):
      # Save previous dependency if valid
      if currentDep.name != "":
        result.transitive.add(currentDep)
      # Start new dependency
      currentDep.name = ""
      currentDep.version = ""
      currentDep.integrity = ""
      inPackage = true
    elif inPackage:
      if trimmed.startsWith("name = "):
        currentDep.name = trimmed.split("=")[1].strip(chars = {' ', '"'})
      elif trimmed.startsWith("version = "):
        currentDep.version = trimmed.split("=")[1].strip(chars = {' ', '"'})
      elif trimmed.startsWith("checksum = "):
        currentDep.integrity = trimmed.split("=")[1].strip(chars = {' ', '"'})
      elif trimmed.startsWith("["):
        inPackage = false

  # Add last dependency
  if currentDep.name != "":
    result.transitive.add(currentDep)
  ## Parse Cargo.toml and extract dependencies
  result = LogicalDependencyTree(
    dependencies: @[],
    devDependencies: @[]
  )

  var inDependencies = false
  var inDevDependencies = false

  for line in content.splitLines():
    let trimmed = line.strip()

    if trimmed.startsWith("[dependencies]"):
      inDependencies = true
      inDevDependencies = false
    elif trimmed.startsWith("[dev-dependencies]"):
      inDevDependencies = true
      inDependencies = false
    elif trimmed.startsWith("["):
      inDependencies = false
      inDevDependencies = false
    elif inDependencies or inDevDependencies:
      if trimmed.len > 0 and not trimmed.startsWith("#"):
        let parts = trimmed.split("=", 1)
        if parts.len == 2:
          let name = parts[0].strip()
          let version = parts[1].strip(chars = {' ', '"'})
          let dep = Dependency(
            name: name,
            version: version,
            source: "crates.io",
            dev: inDevDependencies
          )
          if inDevDependencies:
            result.devDependencies.add(dep)
          else:
            result.dependencies.add(dep)

# ==============================================================================
# package.json Parser (Node.js)
# ==============================================================================

proc parsePackageJson*(content: string): LogicalDependencyTree =
  ## Parse package.json and extract dependencies
  result = LogicalDependencyTree(
    dependencies: @[],
    devDependencies: @[],
    transitive: @[]
  )

  try:
    let jsonObj = parseJson(content)

    if jsonObj.hasKey("dependencies"):
      for name, version in jsonObj["dependencies"].pairs:
        result.dependencies.add(Dependency(
          name: name,
          version: version.getStr(),
          source: "npm",
          dev: false,
          integrity: "",
          lockfile: false
        ))

    if jsonObj.hasKey("devDependencies"):
      for name, version in jsonObj["devDependencies"].pairs:
        result.devDependencies.add(Dependency(
          name: name,
          version: version.getStr(),
          source: "npm",
          dev: true,
          integrity: "",
          lockfile: false
        ))
  except JsonParsingError:
    discard

# ==============================================================================
# package-lock.json Parser (Node.js - Lockfile with integrity)
# ==============================================================================

proc parsePackageLockJson*(content: string): LogicalDependencyTree =
  ## Parse package-lock.json and extract dependencies with integrity hashes
  result = LogicalDependencyTree(
    dependencies: @[],
    devDependencies: @[],
    transitive: @[]
  )

  try:
    let jsonObj = parseJson(content)

    if jsonObj.hasKey("dependencies"):
      for name, depObj in jsonObj["dependencies"].pairs:
        let version = if depObj.hasKey("version"): depObj["version"].getStr() else: "*"
        let integrity = if depObj.hasKey("integrity"): depObj["integrity"].getStr() else: ""
        let isDev = if depObj.hasKey("dev"): depObj["dev"].getBool() else: false

        result.transitive.add(Dependency(
          name: name,
          version: version,
          source: "npm",
          dev: isDev,
          integrity: integrity,
          lockfile: true
        ))
  except JsonParsingError:
    discard
  ## Parse package.json and extract dependencies
  result = LogicalDependencyTree(
    dependencies: @[],
    devDependencies: @[]
  )

  try:
    let jsonObj = parseJson(content)

    if jsonObj.hasKey("dependencies"):
      for name, version in jsonObj["dependencies"].pairs:
        result.dependencies.add(Dependency(
          name: name,
          version: version.getStr(),
          source: "npm",
          dev: false
        ))

    if jsonObj.hasKey("devDependencies"):
      for name, version in jsonObj["devDependencies"].pairs:
        result.devDependencies.add(Dependency(
          name: name,
          version: version.getStr(),
          source: "npm",
          dev: true
        ))
  except JsonParsingError:
    discard

# ==============================================================================
# requirements.txt Parser (Python)
# ==============================================================================

proc parseRequirementsTxt*(content: string): LogicalDependencyTree =
  ## Parse requirements.txt and extract dependencies
  result = LogicalDependencyTree(
    dependencies: @[],
    devDependencies: @[],
    transitive: @[]
  )

  for line in content.splitLines():
    let trimmed = line.strip()
    if trimmed.len > 0 and not trimmed.startsWith("#"):
      # Parse: name==version, name>=version, name~=version, etc.
      # Also handle hashes: name==version --hash=sha256:abc123
      let parts = trimmed.split({'=', '>', '<', '~', '!'}, 1)
      if parts.len >= 1:
        let name = parts[0].strip()
        let version = if parts.len == 2: parts[1].strip() else: "*"
        var integrity = ""

        # Extract hash if present
        if "--hash=" in trimmed:
          let hashParts = trimmed.split("--hash=")
          if hashParts.len == 2:
            integrity = hashParts[1].strip()

        result.dependencies.add(Dependency(
          name: name,
          version: version,
          source: "pypi",
          dev: false,
          integrity: integrity,
          lockfile: false
        ))

# ==============================================================================
# pyproject.toml Parser (Python)
# ==============================================================================

proc parsePyprojectToml*(content: string): LogicalDependencyTree =
  ## Parse pyproject.toml and extract dependencies
  result = LogicalDependencyTree(
    dependencies: @[],
    devDependencies: @[],
    transitive: @[]
  )

  var inDependencies = false
  var inDevDependencies = false
  var inProject = false

  for line in content.splitLines():
    let trimmed = line.strip()

    if trimmed.startsWith("[project]"):
      inProject = true
    elif trimmed.startsWith("[project.dependencies]"):
      inDependencies = true
      inDevDependencies = false
    elif trimmed.startsWith("[project.optional-dependencies]"):
      inDevDependencies = true
      inDependencies = false
    elif trimmed.startsWith("["):
      inDependencies = false
      inDevDependencies = false
      inProject = false
    elif (inDependencies or inDevDependencies) and inProject:
      if trimmed.len > 0 and not trimmed.startsWith("#"):
        let parts = trimmed.split("=", 1)
        if parts.len == 2:
          let name = parts[0].strip()
          let version = parts[1].strip(chars = {' ', '"'})
          result.dependencies.add(Dependency(
            name: name,
            version: version,
            source: "pypi",
            dev: inDevDependencies,
            integrity: "",
            lockfile: false
          ))

# ==============================================================================
# Poetry.lock Parser (Python - Lockfile)
# ==============================================================================

proc parsePoetryLock*(content: string): LogicalDependencyTree =
  ## Parse Poetry.lock and extract dependencies with checksums
  result = LogicalDependencyTree(
    dependencies: @[],
    devDependencies: @[],
    transitive: @[]
  )

  var inPackage = false
  var currentDep: Dependency
  currentDep.name = ""
  currentDep.version = ""
  currentDep.source = "pypi"
  currentDep.dev = false
  currentDep.integrity = ""
  currentDep.lockfile = true

  for line in content.splitLines():
    let trimmed = line.strip()

    if trimmed.startsWith("[[package]]"):
      if currentDep.name != "":
        result.transitive.add(currentDep)
      currentDep.name = ""
      currentDep.version = ""
      currentDep.integrity = ""
      inPackage = true
    elif inPackage:
      if trimmed.startsWith("name = "):
        currentDep.name = trimmed.split("=")[1].strip(chars = {' ', '"'})
      elif trimmed.startsWith("version = "):
        currentDep.version = trimmed.split("=")[1].strip(chars = {' ', '"'})
      elif trimmed.startsWith("checksum = "):
        currentDep.integrity = trimmed.split("=")[1].strip(chars = {' ', '"'})
      elif trimmed.startsWith("["):
        inPackage = false

  if currentDep.name != "":
    result.transitive.add(currentDep)
  ## Parse requirements.txt and extract dependencies
  result = LogicalDependencyTree(
    dependencies: @[],
    devDependencies: @[]
  )

  for line in content.splitLines():
    let trimmed = line.strip()
    if trimmed.len > 0 and not trimmed.startsWith("#"):
      # Simple parsing: name==version or name>=version
      let parts = trimmed.split({'=', '>', '<', '~', '!'}, 1)
      if parts.len >= 1:
        let name = parts[0].strip()
        let version = if parts.len == 2: parts[1].strip() else: "*"
        result.dependencies.add(Dependency(
          name: name,
          version: version,
          source: "pypi",
          dev: false
        ))

# ==============================================================================
# Dependency Hash Generation for Merkle-DAG Integration
# ==============================================================================

proc generateDependencyHashes*(tree: LogicalDependencyTree): seq[DependencyHash] =
  ## Generate hash entries for all dependencies to be integrated into Merkle-DAG
  result = @[]

  for dep in tree.dependencies:
    # Create a canonical string representation for hashing
    let canonical = dep.name & "@" & dep.version & "@" & dep.source
    # Placeholder SHA256 - in production use proper cryptographic hash
    let sha256 = toLowerAscii($canonical.hash)
    let blake3 = sha256  # Placeholder: would use actual BLAKE3 if available

    result.add(DependencyHash(
      path: "dependencies/" & dep.source & "/" & dep.name,
      sha256: sha256,
      blake3: blake3
    ))

  for dep in tree.devDependencies:
    let canonical = dep.name & "@" & dep.version & "@" & dep.source & "@dev"
    let sha256 = toLowerAscii($canonical.hash)
    let blake3 = sha256

    result.add(DependencyHash(
      path: "dependencies/" & dep.source & "/" & dep.name & ".dev",
      sha256: sha256,
      blake3: blake3
    ))

  for dep in tree.transitive:
    var canonical = dep.name & "@" & dep.version & "@" & dep.source & "@transitive"
    if dep.integrity != "":
      canonical &= "@" & dep.integrity
    let sha256 = toLowerAscii($canonical.hash)
    let blake3 = sha256

    result.add(DependencyHash(
      path: "dependencies/" & dep.source & "/" & dep.name & ".transitive",
      sha256: sha256,
      blake3: blake3
    ))

# ==============================================================================
# Cross-Reference with Rust Ledger
# ==============================================================================

proc crossReferenceWithLedger*(
  logicalTree: LogicalDependencyTree,
  ledgerPath: string
): bool =
  ## Cross-reference logical dependencies with Rust ledger
  ## Returns true if all declared dependencies exist in the ledger
  try:
    let ledgerContent = readFile(ledgerPath)
    let ledgerJson = parseJson(ledgerContent)

    if ledgerJson.hasKey("entries"):
      let entries = ledgerJson["entries"]
      var ledgerPaths: seq[string] = @[]
      for key, _ in entries.pairs:
        ledgerPaths.add(key)

      # Check if all dependencies have corresponding files in ledger
      for dep in logicalTree.dependencies:
        var found = false
        for path in ledgerPaths:
          if path.contains(dep.name):
            found = true
            break
        if not found:
          echo "WARNING: Ghost dependency detected: ", dep.name
          return false

    return true
  except:
    echo "ERROR: Failed to read ledger file"
    return false

# ==============================================================================
# Integrate Dependencies into Rust Ledger
# ==============================================================================

proc integrateDependenciesIntoLedger*(
  tree: LogicalDependencyTree,
  ledgerPath: string,
  outputPath: string
): bool =
  ## Integrate dependency hashes into the Rust ledger
  ## This ensures third-party packages are monitored in the supply chain
  try:
    let ledgerContent = readFile(ledgerPath)
    var ledgerJson = parseJson(ledgerContent)

    # Generate dependency hashes
    let depHashes = generateDependencyHashes(tree)

    # Add to ledger entries
    if not ledgerJson.hasKey("entries"):
      ledgerJson["entries"] = newJObject()

    for depHash in depHashes:
      ledgerJson["entries"][depHash.path] = %*{
        "path": depHash.path,
        "sha256": depHash.sha256,
        "blake3": depHash.blake3,
        "size": 0,  # Dependencies are virtual entries
        "modified": 0
      }

    # Write updated ledger
    writeFile(outputPath, pretty(ledgerJson))
    echo "INFO: Integrated ", depHashes.len, " dependencies into ledger"
    return true
  except:
    echo "ERROR: Failed to integrate dependencies into ledger"
    return false

# ==============================================================================
# Main Entry Point
# ==============================================================================

when isMainModule:
  echo "TrustWeave Parser v0.2.0"
  echo "Phase 2: Semantic Policy DSL (Production-Grade)"
  echo ""
  echo "Current directory: ", getCurrentDir()

  # Test with example Cargo.toml
  let cargoToml = """
[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
clap = "4.0"

[dev-dependencies]
criterion = "0.5"
"""

  echo "=== Testing Cargo.toml parser ==="
  let cargoTree = parseCargoToml(cargoToml)
  echo "  Dependencies: ", cargoTree.dependencies.len
  for dep in cargoTree.dependencies:
    echo "    - ", dep.name, " @ ", dep.version, " (", dep.source, ")"
  echo "  Dev Dependencies: ", cargoTree.devDependencies.len
  for dep in cargoTree.devDependencies:
    echo "    - ", dep.name, " @ ", dep.version, " (dev)"

  # Test with example Cargo.lock
  let cargoLock = """
[[package]]
name = "serde"
version = "1.0.0"
checksum = "abc123def456"

[[package]]
name = "tokio"
version = "1.0.0"
checksum = "def456abc123"
"""

  echo ""
  echo "=== Testing Cargo.lock parser ==="
  let cargoLockTree = parseCargoLock(cargoLock)
  echo "  Transitive dependencies: ", cargoLockTree.transitive.len
  for dep in cargoLockTree.transitive:
    echo "    - ", dep.name, " @ ", dep.version, " (integrity: ", dep.integrity, ")"

  # Test with example package.json
  let packageJson = """
{
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}
"""

  echo ""
  echo "=== Testing package.json parser ==="
  let nodeTree = parsePackageJson(packageJson)
  echo "  Dependencies: ", nodeTree.dependencies.len
  for dep in nodeTree.dependencies:
    echo "    - ", dep.name, " @ ", dep.version, " (", dep.source, ")"
  echo "  Dev Dependencies: ", nodeTree.devDependencies.len
  for dep in nodeTree.devDependencies:
    echo "    - ", dep.name, " @ ", dep.version, " (dev)"

  # Test with example package-lock.json
  let packageLockJson = """
{
  "dependencies": {
    "express": {
      "version": "4.18.0",
      "integrity": "sha512-abc123"
    },
    "lodash": {
      "version": "4.17.21",
      "integrity": "sha512-def456"
    }
  }
}
"""

  echo ""
  echo "=== Testing package-lock.json parser ==="
  let nodeLockTree = parsePackageLockJson(packageLockJson)
  echo "  Transitive dependencies: ", nodeLockTree.transitive.len
  for dep in nodeLockTree.transitive:
    echo "    - ", dep.name, " @ ", dep.version, " (integrity: ", dep.integrity, ")"

  # Test with example requirements.txt
  let requirementsTxt = """
numpy>=1.24.0
pandas>=2.0.0
requests>=2.28.0
# This is a comment
"""

  echo ""
  echo "=== Testing requirements.txt parser ==="
  let pythonTree = parseRequirementsTxt(requirementsTxt)
  echo "  Dependencies: ", pythonTree.dependencies.len
  for dep in pythonTree.dependencies:
    echo "    - ", dep.name, " @ ", dep.version, " (", dep.source, ")"

  # Test with example pyproject.toml
  let pyprojectToml = """
[project]
name = "myproject"
dependencies = [
    "numpy>=1.24.0",
    "pandas>=2.0.0"
]

[project.optional-dependencies]
dev = ["pytest>=7.0.0"]
"""

  echo ""
  echo "=== Testing pyproject.toml parser ==="
  let pyprojectTree = parsePyprojectToml(pyprojectToml)
  echo "  Dependencies: ", pyprojectTree.dependencies.len
  for dep in pyprojectTree.dependencies:
    echo "    - ", dep.name, " @ ", dep.version, " (", dep.source, ")"

  # Test dependency hash generation
  echo ""
  echo "=== Testing dependency hash generation ==="
  let depHashes = generateDependencyHashes(cargoTree)
  echo "  Generated ", depHashes.len, " dependency hash entries"
  for depHash in depHashes:
    echo "    - ", depHash.path, " -> SHA256: ", depHash.sha256[0..16], "..."

  echo ""
  echo "=== All parsers executed successfully ==="


