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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory;

use Override;
use Psr\Log\LoggerInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\AdvisorySourceUnavailableException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\Exception\MalformedAdvisoryPayloadException;

/**
 * Advisory database backed by `composer audit --format=json --locked`. The
 * audit is executed once at construction time and the resulting per-package
 * entries are cached for the lifetime of the instance. Composer's advisories
 * stream is the same dataset that powers `composer audit` on the CLI.
 *
 * The advisories the audited project filters out in its own composer config
 * (`config.audit.ignore`, and `ignore-severity` where composer has it) are read
 * from the `ignored-advisories` key composer reports them under: the repository
 * under audit must not be able to hide a vulnerable dependency from its
 * auditor.
 *
 * Failure modes (composer missing, lock file absent, malformed JSON) degrade
 * gracefully to an empty database — `lookup()` always returns a list, never
 * propagates an exception, so the orchestrator and the tool layer stay
 * resilient. {@see self::hasFailedToLoad()} tells that empty database from
 * the snapshot of a project with no advisory.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ComposerAuditAdvisoryDatabase implements AdvisoryDatabaseInterface
{
    /**
     * @var array<string, list<array{cve: ?string, title: string, summary: string, affected_versions: string, link: ?string}>>
     */
    private array $entriesByPackage;

    private bool $loadFailed;

    public function __construct(
        ComposerAuditRunnerInterface $composerAuditRunner,
        AuditedProjectPathHolder $auditedProjectPathHolder,
        LoggerInterface $logger,
    ) {
        $entriesByPackage = $this->load($composerAuditRunner, $auditedProjectPathHolder->path(), $logger);
        $this->entriesByPackage = $entriesByPackage ?? [];

        $this->loadFailed = null === $entriesByPackage;
    }

    public function hasFailedToLoad(): bool
    {
        return $this->loadFailed;
    }

    #[Override]
    public function lookup(string $packageName, string $installedVersion): array
    {
        return $this->entriesByPackage[PackageNameNormalizer::normalize($packageName)] ?? [];
    }

    /**
     * @return array<string, list<array{cve: ?string, title: string, summary: string, affected_versions: string, link: ?string}>>|null null when the audit could not be loaded
     */
    private function load(
        ComposerAuditRunnerInterface $composerAuditRunner,
        string $projectPath,
        LoggerInterface $logger,
    ): ?array {
        try {
            $json = $composerAuditRunner->run($projectPath);

            return $this->parse($json);
        } catch (AdvisorySourceUnavailableException $exception) {
            $logger->warning('composer audit unavailable; advisory lookups disabled', [
                'project' => $projectPath,
                'error' => $exception->getMessage(),
            ]);

            return null;
        } catch (MalformedAdvisoryPayloadException $exception) {
            $logger->warning('composer audit payload was unparseable; advisory lookups disabled', [
                'project' => $projectPath,
                'error' => $exception->getMessage(),
            ]);

            return null;
        } catch (Throwable $exception) {
            $logger->warning('Unexpected composer audit failure; advisory lookups disabled', [
                'project' => $projectPath,
                'error' => $exception->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * @return array<string, list<array{cve: ?string, title: string, summary: string, affected_versions: string, link: ?string}>>
     *
     * @throws MalformedAdvisoryPayloadException
     */
    private function parse(string $json): array
    {
        $advisoryPayload = AdvisoryPayload::fromJson($json);

        return $this->withAdvisories(
            $this->withAdvisories([], $advisoryPayload->advisories),
            $advisoryPayload->ignoredAdvisories,
        );
    }

    /**
     * @param array<string, list<array{cve: ?string, title: string, summary: string, affected_versions: string, link: ?string}>> $entries
     * @param array<array-key, mixed>                                                                                            $advisoriesByPackage
     *
     * @return array<string, list<array{cve: ?string, title: string, summary: string, affected_versions: string, link: ?string}>>
     */
    private function withAdvisories(array $entries, array $advisoriesByPackage): array
    {
        /** @var array<string, mixed> $advisoriesByPackage */
        foreach ($advisoriesByPackage as $packageName => $advisories) {
            if (!\is_array($advisories)) {
                continue;
            }

            $normalizedName = PackageNameNormalizer::normalize($packageName);
            $entries[$normalizedName] = [...($entries[$normalizedName] ?? []), ...$this->mapAdvisories($advisories)];
        }

        return $entries;
    }

    /**
     * @param array<int|string, mixed> $advisories
     *
     * @return list<array{cve: ?string, title: string, summary: string, affected_versions: string, link: ?string}>
     */
    private function mapAdvisories(array $advisories): array
    {
        $mapped = [];
        foreach ($advisories as $advisory) {
            $entry = $this->mapAdvisory($advisory);
            if (null !== $entry) {
                $mapped[] = $entry;
            }
        }

        return $mapped;
    }

    /**
     * @return array{cve: ?string, title: string, summary: string, affected_versions: string, link: ?string}|null
     */
    private function mapAdvisory(mixed $advisory): ?array
    {
        if (!\is_array($advisory)) {
            return null;
        }

        $title = \is_string($advisory['title'] ?? null) ? $advisory['title'] : '';
        if ('' === $title) {
            return null;
        }

        $affected = $advisory['affectedVersions'] ?? '';

        return [
            'cve' => $this->nonEmptyStringOrNull($advisory['cve'] ?? null),
            'title' => $title,
            'summary' => \is_string($advisory['summary'] ?? null) ? $advisory['summary'] : $title,
            'affected_versions' => \is_string($affected) ? $affected : '',
            'link' => $this->nonEmptyStringOrNull($advisory['link'] ?? null),
        ];
    }

    private function nonEmptyStringOrNull(mixed $value): ?string
    {
        return \is_string($value) && '' !== $value ? $value : null;
    }
}
