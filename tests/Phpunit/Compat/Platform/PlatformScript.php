<?php

/*
 * This file is part of the vinceamstoutz/symfony-security-auditor package.
 *
 * (c) Vincent Amstoutz <vincent.amstoutz.dev@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Platform;

/**
 * What the scripted provider answers beyond the `FINDING {json}` markers it
 * reads in the audited files: reviewer verdicts keyed by a title fragment,
 * the tool calls the first attacker turn makes, and a provider failure after
 * a number of calls.
 */
final readonly class PlatformScript
{
    /**
     * @param array<string, list<array<string, mixed>>> $reviewerSequences
     * @param array<string, array<string, mixed>>       $reviewerVerdicts
     * @param list<array{string, array<string, mixed>}> $attackerToolCalls
     * @param array{int, string}|null                   $failure
     */
    private function __construct(
        public array $reviewerSequences = [],
        public array $reviewerVerdicts = [],
        public array $attackerToolCalls = [],
        public ?array $failure = null,
    ) {}

    public static function default(): self
    {
        return new self();
    }

    /**
     * The verdicts a finding whose review window holds `$titleFragment` gets on
     * its first, second, … review; the last one repeats.
     *
     * @param list<array<string, mixed>> $verdicts
     */
    public function withReviewerSequence(string $titleFragment, array $verdicts): self
    {
        return new self([...$this->reviewerSequences, $titleFragment => $verdicts], $this->reviewerVerdicts, $this->attackerToolCalls, $this->failure);
    }

    /**
     * @param array<string, mixed> $verdict the verdict fields sent as they are, `id` aside
     */
    public function withReviewerVerdict(string $titleFragment, array $verdict): self
    {
        return new self($this->reviewerSequences, [...$this->reviewerVerdicts, $titleFragment => $verdict], $this->attackerToolCalls, $this->failure);
    }

    /**
     * @param array<string, mixed> $arguments
     */
    public function withAttackerToolCall(string $tool, array $arguments): self
    {
        return new self($this->reviewerSequences, $this->reviewerVerdicts, [...$this->attackerToolCalls, [$tool, $arguments]], $this->failure);
    }

    public function failingAfter(int $calls, string $message): self
    {
        return new self($this->reviewerSequences, $this->reviewerVerdicts, $this->attackerToolCalls, [$calls, $message]);
    }
}
