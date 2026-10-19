## Compile-time security policy DSL and policy-matrix emitter.

import std/[json, macros, os, strutils]

type
  PolicyRule* = object
    pattern*: string
    allowed*: bool
    source*: string
    versionConstraint*: string

  PolicyConstraint* = object
    name*: string
    value*: string

  SecurityPolicy* = object
    name*: string
    rules*: seq[PolicyRule]
    constraints*: seq[PolicyConstraint]
    strictMode*: bool

proc normalizedCommand(name: string): string {.compileTime.} =
  result = name.toLowerAscii.replace("_", "").replace("-", "")

proc stringArgument(node: NimNode, command: string): string {.compileTime.} =
  if node.kind notin {nnkStrLit, nnkRStrLit, nnkTripleStrLit}:
    error(command & " arguments must be string literals", node)
  node.strVal

proc parsePolicyStatement(statement: NimNode, policy: var SecurityPolicy) {.compileTime.} =
  if statement.kind notin {nnkCall, nnkCommand} or statement.len < 2:
    error("expected a policy declaration such as allowDependency \"serde\", \"crates.io\"", statement)

  let command = normalizedCommand(statement[0].strVal)
  case command
  of "name":
    if statement.len != 2:
      error("name expects exactly one string", statement)
    policy.name = stringArgument(statement[1], command)
  of "strict":
    if statement.len != 2 or statement[1].kind notin {nnkIdent, nnkSym}:
      error("strict expects true or false", statement)
    let value = statement[1].strVal.toLowerAscii
    if value notin ["true", "false"]:
      error("strict expects true or false", statement)
    policy.strictMode = value == "true"
  of "allowsource", "denysource":
    if statement.len != 2:
      error(command & " expects one path prefix", statement)
    policy.rules.add(PolicyRule(
      pattern: stringArgument(statement[1], command),
      allowed: command == "allowsource",
      source: "path",
      versionConstraint: ""
    ))
  of "allowdependency", "denydependency":
    if statement.len notin {2, 3}:
      error(command & " expects a dependency name and optional source", statement)
    policy.rules.add(PolicyRule(
      pattern: stringArgument(statement[1], command),
      allowed: command == "allowdependency",
      source: if statement.len == 3: stringArgument(statement[2], command) else: "*",
      versionConstraint: ""
    ))
  of "constraint":
    if statement.len != 3:
      error("constraint expects a name and string value", statement)
    policy.constraints.add(PolicyConstraint(
      name: stringArgument(statement[1], command),
      value: stringArgument(statement[2], command)
    ))
  else:
    error("unknown policy declaration: " & command, statement)

proc parsePolicy(body: NimNode): SecurityPolicy {.compileTime.} =
  result = SecurityPolicy(name: "default", rules: @[], constraints: @[], strictMode: true)
  let statements =
    if body.kind in {nnkStmtList, nnkStmtListExpr}: body
    else: newTree(nnkStmtList, body)
  for statement in statements:
    if statement.kind in {nnkEmpty, nnkCommentStmt}:
      continue
    parsePolicyStatement(statement, result)

proc policyJson(policy: SecurityPolicy): JsonNode =
  result = %*{
    "name": policy.name,
    "strictMode": policy.strictMode,
    "rules": policy.rules,
    "constraints": policy.constraints
  }

macro policy*(body: untyped): untyped =
  ## Parse literal policy declarations and emit both a Nim value and JSON matrix.
  let parsed = parsePolicy(body)
  let jsonText = policyJson(parsed).pretty() & "\n"
  try:
    writeFile("tw-policy.json", jsonText)
  except IOError as exc:
    error("could not write compile-time policy matrix: " & exc.msg, body)
  result = newLit(parsed)

proc matchesPattern(pattern, value: string): bool =
  if pattern == "*":
    return true
  let wildcard = pattern.find('*')
  if wildcard < 0:
    return pattern == value
  if pattern.count('*') != 1:
    return false
  let prefix = pattern[0 ..< wildcard]
  let suffix = pattern[wildcard + 1 .. ^1]
  value.startsWith(prefix) and value.endsWith(suffix) and
    value.len >= prefix.len + suffix.len

proc validateDependency*(policy: SecurityPolicy, depName: string, depSource: string): bool =
  ## Deny rules take precedence; otherwise the first matching rule applies.
  for rule in policy.rules:
    if not rule.allowed and matchesPattern(rule.pattern, depName) and
        (rule.source == "*" or rule.source == depSource):
      return false
  for rule in policy.rules:
    if rule.allowed and matchesPattern(rule.pattern, depName) and
        (rule.source == "*" or rule.source == depSource):
      return true
  not policy.strictMode

proc validateSource*(policy: SecurityPolicy, sourcePath: string): bool =
  ## Validate a normalized source path against allow/deny prefix rules.
  for rule in policy.rules:
    if rule.source == "path" and not rule.allowed and
        sourcePath.startsWith(rule.pattern):
      return false
  for rule in policy.rules:
    if rule.source == "path" and rule.allowed and
        sourcePath.startsWith(rule.pattern):
      return true
  not policy.strictMode

proc generatePolicyMatrix*(policy: SecurityPolicy): JsonNode =
  ## Generate the policy matrix for serialization.
  policyJson(policy)

when isMainModule:
  let myPolicy = policy:
    name "release"
    strict true
    allowSource "src/"
    denySource "src/private/"
    allowDependency "serde", "crates.io"
    allowDependency "tokio", "crates.io"
    allowDependency "express", "npm"
    denyDependency "unsafe-*"
    constraint "requireLicense", "true"
    constraint "requireSource", "true"

  doAssert myPolicy.name == "release"
  doAssert myPolicy.rules.len == 6
  doAssert validateDependency(myPolicy, "serde", "crates.io")
  doAssert validateDependency(myPolicy, "unsafe-crate", "crates.io") == false
  doAssert validateDependency(myPolicy, "unknown", "crates.io") == false
  doAssert validateSource(myPolicy, "src/main.nim")
  doAssert validateSource(myPolicy, "src/private/key.nim") == false
  doAssert validateSource(myPolicy, "tests/test_policy.nim") == false
  echo generatePolicyMatrix(myPolicy).pretty()
  echo "Policy matrix emitted at compile time: ", getCurrentDir() / "tw-policy.json"
