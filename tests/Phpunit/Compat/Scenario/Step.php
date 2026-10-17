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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario;

/**
 * One console command of a scenario. Values of `$input` and the working
 * directory may hold `{workspace}` and `{project}`, replaced by the absolute
 * paths of the scenario workspace and of the audited project.
 */
final readonly class Step
{
    /**
     * @param array<string, bool|int|string|list<string>|null> $input
     * @param list<string>                                     $answers what a user types at the command's prompts, in order
     */
    public function __construct(
        public string $command,
        public array $input = [],
        public string $workingDirectory = '{project}',
        public array $answers = [],
    ) {}

    /**
     * @param array<string, bool|int|string|list<string>|null> $input
     */
    public static function audit(array $input = []): self
    {
        return new self('audit:run', ['project-path' => '{project}', ...$input]);
    }

    public function in(string $workingDirectory): self
    {
        return new self($this->command, $this->input, $workingDirectory, $this->answers);
    }

    /**
     * @param list<string> $answers
     */
    public function answering(array $answers): self
    {
        return new self($this->command, $this->input, $this->workingDirectory, $answers);
    }

    public function mentions(string $text): bool
    {
        foreach ($this->input as $value) {
            if (\is_string($value) && str_contains($value, $text) || \is_array($value) && [] !== array_filter($value, static fn (string $item): bool => str_contains($item, $text))) {
                return true;
            }
        }

        return false;
    }

    public function label(): string
    {
        $parts = [$this->command];
        foreach ($this->input as $name => $value) {
            $parts[] = $this->describe($name, $value);
        }

        return implode(' ', $parts);
    }

    /**
     * @param bool|int|string|list<string>|null $value
     */
    private function describe(string $name, bool|int|string|array|null $value): string
    {
        $rendered = \is_array($value) ? implode('|', $value) : var_export($value, true);

        return str_starts_with($name, '-') ? \sprintf('%s=%s', $name, $rendered) : \sprintf('<%s>=%s', $name, $rendered);
    }
}
