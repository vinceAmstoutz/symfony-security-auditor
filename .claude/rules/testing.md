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
justifies it. Coverage is a side-effect, not the target — Infection MSI must
stay at 100% (see CI Pipeline in `CLAUDE.md`).

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
