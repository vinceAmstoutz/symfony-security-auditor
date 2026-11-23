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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

/**
 * What became of the audited project's config file when the audit runs from
 * another folder: layered over the other files, or skipped as a whole with
 * the reason.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class AuditedProjectConfig
{
    /**
     * @param array<array-key, mixed> $config      what the file sets, empty when it was skipped
     * @param ?float                  $httpTimeout the timeout the file raises the user's to, null when it sets none
     */
    private function __construct(
        public string $file,
        public array $config,
        public ?float $httpTimeout,
        public ?string $skipReason,
    ) {}

    /**
     * @param array<array-key, mixed> $config
     */
    public static function layered(string $file, array $config, ?float $httpTimeout): self
    {
        return new self($file, $config, $httpTimeout, null);
    }

    public static function skipped(string $file, string $reason): self
    {
        return new self($file, [], null, $reason);
    }

    public function wasSkipped(): bool
    {
        return null !== $this->skipReason;
    }

    /**
     * Returns the baseline the file names, a relative one anchored to the
     * project, or null.
     */
    public function baseline(): ?string
    {
        $baseline = $this->audit()['baseline'] ?? null;

        return \is_string($baseline) ? $baseline : null;
    }

    /**
     * Returns what the file sets as the container reads it back, the `%` signs
     * of the anchored baseline's folder escaped.
     *
     * @return array<array-key, mixed>
     */
    public function configForContainer(): array
    {
        $baseline = $this->baseline();
        if (null === $baseline) {
            return $this->config;
        }

        $audit = $this->audit();
        $audit['baseline'] = ContainerParameterSyntax::escape($baseline);
        $config = $this->config;
        $config['audit'] = $audit;

        return $config;
    }

    /**
     * @return array<array-key, mixed>
     */
    private function audit(): array
    {
        $audit = $this->config['audit'] ?? null;

        return \is_array($audit) ? $audit : [];
    }
}
