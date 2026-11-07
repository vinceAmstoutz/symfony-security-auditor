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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/**
 * What an audit knows of the audited project as a whole: the packages its
 * lockfile installs and the architecture its files are laid out in.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ProjectProfile
{
    private const string SYMFONY_MINIMUM = 'symfony>=';

    private const string SYMFONY_KERNEL = 'symfony/http-kernel';

    private const string NO_LOCKFILE = 'no lockfile';

    /**
     * @param array<string, string>|null $installedPackages  package name => locked version, `null` when no lockfile was read
     * @param list<ArchitectureStyle>    $architectureStyles
     */
    private function __construct(
        private ?array $installedPackages,
        private array $architectureStyles,
    ) {}

    public static function unknown(): self
    {
        return new self(null, []);
    }

    /**
     * @param array<string, string>|null $installedPackages  package name => locked version, `null` when no lockfile was read
     * @param list<ArchitectureStyle>    $architectureStyles
     */
    public static function of(?array $installedPackages, array $architectureStyles): self
    {
        return new self($installedPackages, $architectureStyles);
    }

    /**
     * @return list<ArchitectureStyle>
     */
    public function architectureStyles(): array
    {
        return $this->architectureStyles;
    }

    public function signature(): string
    {
        if (null === $this->installedPackages && [] === $this->architectureStyles) {
            return '';
        }

        $packageNames = array_keys($this->installedPackages ?? []);
        sort($packageNames);

        $symfonyRelease = null === $this->installedPackages
            ? self::NO_LOCKFILE
            : implode('.', \array_slice(explode('.', $this->releaseOf($this->installedPackages[self::SYMFONY_KERNEL] ?? '0')), 0, 2));

        $styles = array_map(static fn (ArchitectureStyle $architectureStyle): string => $architectureStyle->value, $this->architectureStyles);

        return hash('sha256', implode("\n", [$symfonyRelease, ...$styles, '', ...$packageNames]));
    }

    public function satisfies(string $requirement): bool
    {
        if (null === $this->installedPackages) {
            return true;
        }

        foreach (explode(' ', $requirement) as $term) {
            if (!$this->holds($term, $this->installedPackages)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array<string, string> $installedPackages
     */
    private function holds(string $term, array $installedPackages): bool
    {
        foreach (explode('|', $term) as $alternative) {
            if ($this->isMet($alternative, $installedPackages)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, string> $installedPackages
     */
    private function isMet(string $alternative, array $installedPackages): bool
    {
        if (str_starts_with($alternative, self::SYMFONY_MINIMUM)) {
            return version_compare($this->releaseOf($installedPackages[self::SYMFONY_KERNEL] ?? '0'), substr($alternative, \strlen(self::SYMFONY_MINIMUM)), '>=');
        }

        return \array_key_exists($alternative, $installedPackages);
    }

    private function releaseOf(string $lockedVersion): string
    {
        preg_match('/^v?(\d+(?:\.\d+)*)/', $lockedVersion, $matches);

        return $matches[1] ?? '0';
    }
}
