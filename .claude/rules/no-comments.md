# No-Comments Rule

A comment is a symptom of code that doesn't speak for itself. Before writing
one, fix the code instead.

## Default: no comment

Do not write `//` comment blocks in production or test code. Self-documenting
names beat prose every time.

## When tempted to comment, do this instead

| Temptation                              | Fix                                                  |
| --------------------------------------- | ---------------------------------------------------- |
| Explain what a block does               | Extract a method with a descriptive name             |
| Explain why a value was chosen          | Introduce a named constant                           |
| Explain an algorithm step               | Extract + name each step as a private method         |
| Pin a mutation-test rationale in a test | Write the assertion so its failure message is clear  |
| Explain an `if` condition               | Extract a predicate method (`isSingleBalancedBlock`) |

## Allowed (rare, one line only)

A single `//` line is acceptable only for an **external constraint** that truly
cannot be expressed in code and would take a reader hours to rediscover:

- A provider quirk not documented in their public API (e.g. a model that rejects
  a standard option).
- A PCRE engine edge-case that forces an unusual operator.
- A regulatory or third-party requirement that drives a non-obvious choice.

Even then: one line, no multi-sentence prose.

## Never

- Multi-line `//` blocks explaining design rationale.
- "Mutation-pinning" comments in tests (`// Pins the X mutant — removing this
  assertion allows Y`). If the test name and assertion are clear, the pin is
  implicit.
- Commented-out code.
- Redundant docblocks on `final readonly` classes that just repeat the
  constructor parameters.