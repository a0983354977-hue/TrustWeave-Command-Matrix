namespace TrustWeave

abbrev Node := Nat

structure PolicyMatrix where
  allowedPackages : List Node
  deniedPackages : List Node
  strictMode : Bool

def PolicyMatrix.authorizes (policy : PolicyMatrix) (node : Node) : Bool :=
  if policy.deniedPackages.contains node then
    false
  else if policy.allowedPackages.contains node then
    true
  else
    !policy.strictMode

inductive Reachable (dependency : Node → Node → Prop) (root : Node) : Node → Prop where
  | root : Reachable dependency root root
  | step {parent child : Node} :
      Reachable dependency root parent →
      dependency parent child →
      Reachable dependency root child

structure BuildEvidence
    (dependency : Node → Node → Prop)
    (root : Node)
    (policy : PolicyMatrix) where
  ledgerRootMatches : Prop
  policyMatrixMatches : Prop
  rootAllowed : policy.authorizes root = true
  everyDependencyAllowed :
    ∀ parent child, dependency parent child → policy.authorizes child = true

/--
Under the explicit assumptions that the committed graph and policy correspond
to the supplied relations, the root is allowed, and every dependency edge's
target is allowed, all nodes in the transitive dependency closure are allowed.
The cryptographic correctness of those correspondence assumptions is supplied
by the verifier, not proved by this logical model.
-/
theorem committed_build_has_only_authorized_dependencies
    (dependency : Node → Node → Prop)
    (root : Node)
    (policy : PolicyMatrix)
    (evidence : BuildEvidence dependency root policy)
    (commitments_match :
      evidence.ledgerRootMatches ∧ evidence.policyMatrixMatches) :
    (∀ node, Reachable dependency root node → policy.authorizes node = true) ∧
      evidence.ledgerRootMatches ∧ evidence.policyMatrixMatches := by
  have all_allowed :
      ∀ node, Reachable dependency root node → policy.authorizes node = true := by
    intro target path
    induction path with
    | root =>
        exact evidence.rootAllowed
    | @step parent child _ edge _ =>
        exact evidence.everyDependencyAllowed parent child edge
  exact ⟨all_allowed, commitments_match.1, commitments_match.2⟩

end TrustWeave
