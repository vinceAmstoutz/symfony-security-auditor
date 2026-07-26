---
paths:
  - "src/**"
  - "tests/**"
---

# Testing Rules

## Philosophy

Tests verify **behavior through public interfaces**, never implementation
details. Code can change entirely; tests shouldn't.

**Good test** describes WHAT the system does — e.g. _"VulnerabilityFactory drops
malformed entries"_. Survives refactors because it doesn't know HOW.

**Bad test** is coupled to implementation: mocks internal collaborators, asserts
on private helpers, verifies through external means (e.g. reading a database row
instead of calling the public getter). Warning sign: renaming a private method
breaks the suite while behavior is unchanged.

## What 100% MSI Does Not Catch

100% mutation score and 100% line coverage are a **floor, not a ceiling**. They
prove every line that exists is exercised by an assertion that would fail if the
line were mutated. They say nothing about three whole classes of defect — which
is why an external review pass keeps surfacing real medium/high/critical
findings on a green, 100%-MSI tree:

1. **Missing code.** A missing null-guard, an unhandled response shape, an
   absent branch — Infection can only mutate lines that exist, so an absence is
   invisible. Most severe findings in a mature codebase are absences.
2. **Wrong specifications.** If a test asserts the wrong expected behavior, the
   mutant still dies and the bug still ships — MSI is self-consistent even when
   the spec is wrong.
3. **Composition / wiring defects.** Each unit is correct in isolation; the bug
   lives in how the compiled container wires them, or in a config combination,
   or against a real provider's quirks. Unit-level mutants never see it.

Two guards in this suite target these gaps directly — keep them working, do not
weaken them into shallower checks:

- **Container-backed E2E** (`ContainerBackedAuditEndToEndTest`) boots the real
  bundle through a kernel and drives `audit:run` from the compiled container,
  stubbing only the `symfony/ai` platform (at `PlatformInterface`, **not** at
  `LLMClientInterface`), so `SymfonyAiLLMClient` and its retry / tool-loop /
  structured-collection collaborators — and the `config/services.php` DI
  defaults — run end to end. It golden-masters the full JSON and SARIF reports
  against committed snapshots in `__snapshots__/`, so any unintended behavior or
  schema drift fails loudly. When a change legitimately alters report output,
  regenerate the snapshot in the same commit and review the diff. The hand-wired
  `FullAuditEndToEndTest` stays useful for isolated pipeline shapes, but is
  **not** a substitute: it validates a graph users never run.
- **Adversarial-input boundary tests** feed hostile payloads (malformed,
  truncated, duplicate, wrong-typed) to the parsing/response-shape boundaries —
  `LLMResponse::parseJson()`, `VulnerabilityFactory`,
  `TransientFailureClassifier` — because that is where a missing guard becomes a
  crash or a false SAFE.

## Reproduce-or-Reject: triaging external review findings

AI review scans over-report: they inflate severity and raise plausible-but-wrong
findings. Do **not** patch a finding on the strength of its description. The
acceptance test for any reported medium+ finding is a single question:

> Can it be expressed as a failing PHPUnit test — red for the right reason on
> the current code?

- **Yes → it is real.** That failing test _is_ the regression test; commit it
  with the fix (red → green). Which suite layer had to grow to express it tells
  you where the hole was — usually "no E2E ran this config combination."
- **No → reject it.** A finding no one can turn red is noise; record why and
  move on. Never add production code, a guard, or a defensive branch for a
  scenario you cannot make a test reach — that is untested code by definition
  and it dilutes the signal of the next scan.

This keeps the finding backlog honest and steadily converts each genuine
discovery into a permanent guard, rather than repeatedly re-running the same
broad scan to rediscover the same gaps.

## Anti-Pattern: Horizontal Slices

**Never** write all tests first and then all production code. "Horizontal
slicing" produces brittle, imagined-behavior tests that pass when the real
behavior breaks and fail when it doesn't.

```text
WRONG (horizontal):
  RED:   test1, test2, test3, test4
  GREEN: impl1, impl2, impl3, impl4

RIGHT (vertical — tracer bullet):
  RED → GREEN: test1 → impl1
  RED → GREEN: test2 → impl2
  RED → GREEN: test3 → impl3
```

One test, one minimum implementation, then the next test responds to what the
previous cycle revealed. Each step is grounded in code that exists, not code
you're imagining.

## TDD — Red / Green / Refactor

All production code is written using TDD by the book.

1. **Red** — write the smallest failing test that expresses the next behavior.
   Run it; confirm it fails for the right reason.
2. **Green** — write the minimum production code to make the test pass. No
   speculative extras.
3. **Refactor** — clean up structure (names, duplication, SRP) with the suite
   staying green. **Never refactor while red — get to green first.**

Every code change ships with tests. No production code without a test that
justifies it. Mutation score is the quality bar — Infection MSI must stay at
100%; 100% line coverage sits on top as a mechanical floor, enforced by the
custom `MinimumLineCoverageExtension` (`tools/PHPUnit/`). Write tests for
behavior, not to chase the line number (see CI Pipeline in `CLAUDE.md`).

### Planning Before Code

Before any new feature or fix:

- [ ] Confirm with the user which public interface (port, method, value object)
      is changing.
- [ ] List the behaviors to test, ordered by importance — not implementation
      steps.
- [ ] Identify opportunities for [deep modules](#deep-modules) (small interface,
      deep implementation).
- [ ] Design interfaces for testability (see
      [below](#interface-design-for-testability)).
- [ ] Get user approval on the plan.

You can't test everything. Focus effort on critical paths (`AuditOrchestrator`,
`VulnerabilityFactory`, `LLMResponse::parseJson`, the agent loop), not every
conceivable edge case.

### Per-Cycle Checklist

```text
[ ] Test describes behavior, not implementation
[ ] Test uses public interface only
[ ] Test would survive an internal refactor
[ ] Production code is minimal for this test
[ ] No speculative features added
```

## Stubs vs Mocks

See memory: `[[feedback_mock_vs_stub]]`.

### When to Mock at All

Mock at **system boundaries** only:

- `LLMClientInterface` — the sole seam to `symfony/ai` (see [[llm-seam]]).
- Filesystem / process / time / randomness adapters.
- HTTP clients to external services.
- `AttackerCacheInterface`, `AdvisoryDatabaseInterface`, tool ports.

**Do not mock** your own Application or Domain classes. They are part of the
unit under test. Mocking internal collaborators couples the test to the call
graph and defeats TDD.

## Interface Design for Testability

Good interfaces make tests natural; bad interfaces make them painful. **When
testing is painful, the design — not the test — is the problem.**

1. **Accept dependencies, don't construct them.** Every collaborator that
   crosses a layer is an interface injected via the constructor (see
   [[php-classes]]). A class never `new`s a Symfony service or an LLM client.

   ```php
   // Testable
   final readonly class ReviewerAgent
   {
       public function __construct(
           private LLMClientInterface $llmClient,
           private ReviewerPromptBuilderInterface $promptBuilder,
           private LoggerInterface $logger,
           private int $batchSize = self::DEFAULT_BATCH_SIZE,
       ) {}
   }
   ```

2. **Return results, avoid hidden side effects.** Pure functions and immutable
   factories beat mutating methods.
   `Vulnerability::withReviewerValidation(bool)` returns a new instance — easy
   to assert on, impossible to misuse.

3. **Small surface area.** Fewer public methods = fewer tests needed. Fewer
   parameters = simpler arrange phase. If a constructor has six required
   collaborators, the class is doing too much.

## Deep Modules

From _A Philosophy of Software Design_:

```text
Deep module    = small interface + lots of implementation   ← prefer
Shallow module = large interface + little implementation    ← avoid
```

When introducing a class, ask:

- Can I reduce the number of public methods?
- Can I simplify the parameters (introduce a value object)?
- Can I hide more complexity behind a single call?

`AuditOrchestrator::run()` is the canonical deep-module shape: one public
method, large coordinated behavior hidden behind it. Replicate that pattern over
thin wrappers that expose internal steps.

## Refactor Candidates

After all tests are green, look for:

- **Duplication** → extract a private helper or shared collaborator.
- **Long methods** → split into private helpers; keep tests on the public
  interface.
- **Shallow modules** → combine, or push behavior deeper.
- **Feature envy** → move logic to where the data lives (often into the value
  object).
- **Primitive obsession** → introduce a value object (e.g.
  `VulnerabilitySeverity` over `string`).
- **Existing code** that the new code newly reveals as problematic.

## Suite Layout & Conventions

- Suites: `Unit` (isolated, stub collaborators), `Integration` (real classes
  wired together, no LLM), `EndToEnd` (full pipeline with stub LLM client).
- Tests mirror `src/` structure under `tests/Phpunit/`.
- PHPUnit method names use snake_case (enforced by PHP CS Fixer rule
  `php_unit_method_casing`).
- One logical assertion per test. Names describe WHAT, not HOW — prefer
  `reviewer_marks_vulnerability_as_validated` over
  `reviewer_calls_llm_client_then_parses_json`.

### Collapse Repeated Tests with `#[DataProvider]`

When several tests share identical structure and differ only by input/output
values, collapse them with a `#[DataProvider]` instead of duplicating setup.
Reduces noise, keeps every case visible in the test report (each provider entry
is reported as its own test), and isolates the varying part from the fixed
scaffolding.

```php
use PHPUnit\Framework\Attributes\DataProvider;

#[DataProvider('chunkPriorityCases')]
public function test_it_orders_files_by_priority_in_chunks(string $higherPriorityPath, string $lowerPriorityPath): void
{
    // single assertion body — shared scaffolding lives here
}

/** @return iterable<string, array{string, string}> */
public static function chunkPriorityCases(): iterable
{
    yield 'controllers before services' => ['src/Controller/X.php', 'src/Service/Y.php'];
    yield 'voters before entities'      => ['src/Security/V.php',   'src/Entity/E.php'];
}
```

Apply when: same arrange/act/assert shape, only literal values vary. **Do not**
apply when cases need different mock setup, different assertion shape, or
distinct edge-case behavior — those stay as separate test methods.

## Bad-Test Red Flags

- Mocking internal Application or Domain collaborators.
- Asserting on call counts or argument order when the contract is the _result_,
  not the call.
- Bypassing the public interface to verify state (reflecting into private
  properties, reading directly from `AuditContext` arrays the API exposes only
  in aggregate).
- Test name describes HOW (`uses_array_chunk`) instead of WHAT
  (`reviews_in_batches_of_five`).
- Test breaks after a pure rename or extract-method refactor.
- **`$this->expectNotToPerformAssertions()`** — forbidden. A test with no
  assertions is a test that can never fail on a logic mutation. If the only
  observable contract is "does not throw", express it structurally: use
  `expects(self::never())` on a mock collaborator, or fire a follow-up call that
  asserts a return value. If you truly cannot assert anything, delete the test —
  dead coverage is worse than no coverage.

## Quality Gates

- PHPUnit config enforces `failOnDeprecation`, `failOnNotice`, `failOnWarning` —
  do not suppress these.
- **100% mutation score** required (Infection). Avoid trivially-killed mutants:
  assert on **return values**, not just _"no exception thrown"_.
- Never silence Infection / PHPStan / CS Fixer / Rector via annotations or
  config opt-outs — see `CLAUDE.md` → _Never Silence Quality Gates_.
- Symplify PHPUnit rules enforce test hygiene at PHPStan level: data providers
  must be `public static` (`PublicStaticDataProviderRule`), assertions go
  through `$this->`/`self::` (`NoAssertFuncCallInTestsRule`, no global
  `assert()`), a test may not consist only of mock setup with no behavioral
  assertion (`NoMockOnlyTestRule`), and repeated consecutive identical mock
  expectations (`NoDoubleConsecutiveTestMockRule`) signal a missing
  `#[DataProvider]`.
- The custom `ForbiddenTestAttributeRule` (`tools/PHPStan/`) bans test
  attributes that opt out of a gate instead of fixing the code:
  `#[AllowMockObjectsWithoutExpectations]` (use `createStub` — see
  `[[feedback_mock_vs_stub]]`), `#[DoesNotPerformAssertions]` (assert a real
  outcome), and `#[WithoutErrorHandler]` (keeps `failOnWarning`/`failOnNotice`
  live). `#[IgnoreDeprecations]` is allowed **only** scoped to this library
  (`#[IgnoreDeprecations('vinceamstoutz/symfony-security-auditor')]`) alongside
  an `expectUserDeprecationMessage*()` assertion — see
  `[[project_deprecation_testing_pattern]]`.
