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

use JsonException;
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
 * Failure modes (composer missing, lock file absent, malformed JSON) degrade
 * gracefully to an empty database — `lookup()` always returns a list, never
 * propagates an exception, so the orchestrator and the tool layer stay
 * resilient.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ComposerAuditAdvisoryDatabase implements AdvisoryDatabaseInterface
{
    /**
     * @var array<string, list<array{cve: ?string, title: string, summary: string, affected_versions: string, link: ?string}>>
     */
    private array $entriesByPackage;

    public function __construct(
        ComposerAuditRunnerInterface $composerAuditRunner,
        AuditedProjectPathHolder $auditedProjectPathHolder,
        LoggerInterface $logger,
    ) {
        $this->entriesByPackage = $this->load($composerAuditRunner, $auditedProjectPathHolder->path(), $logger);
    }

    #[Override]
    public function lookup(string $packageName, string $installedVersion): array
    {
        return $this->entriesByPackage[PackageNameNormalizer::normalize($packageName)] ?? [];
    }

    /**
     * @return array<string, list<array{cve: ?string, title: string, summary: string, affected_versions: string, link: ?string}>>
     */
    private function load(
        ComposerAuditRunnerInterface $composerAuditRunner,
        string $projectPath,
        LoggerInterface $logger,
    ): array {
        try {
            $json = $composerAuditRunner->run($projectPath);

            return $this->parse($json);
        } catch (AdvisorySourceUnavailableException $exception) {
            $logger->warning('composer audit unavailable; advisory lookups disabled', [
                'project' => $projectPath,
                'error' => $exception->getMessage(),
            ]);

            return [];
        } catch (MalformedAdvisoryPayloadException $exception) {
            $logger->warning('composer audit payload was unparseable; advisory lookups disabled', [
                'project' => $projectPath,
                'error' => $exception->getMessage(),
            ]);

            return [];
        } catch (Throwable $exception) {
            $logger->warning('Unexpected composer audit failure; advisory lookups disabled', [
                'project' => $projectPath,
                'error' => $exception->getMessage(),
            ]);

            return [];
        }
    }

    /**
     * @return array<string, list<array{cve: ?string, title: string, summary: string, affected_versions: string, link: ?string}>>
     *
     * @throws MalformedAdvisoryPayloadException
     */
    private function parse(string $json): array
    {
        try {
            $decoded = json_decode($json, true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException $jsonException) {
            throw MalformedAdvisoryPayloadException::forInvalidJson($jsonException);
        }

        if (!\is_array($decoded)) {
            throw MalformedAdvisoryPayloadException::forNonArrayPayload($decoded);
        }

        if (!\array_key_exists('advisories', $decoded) || !\is_array($decoded['advisories'])) {
            throw MalformedAdvisoryPayloadException::forMissingAdvisoriesKey();
        }

        $entries = [];
        /** @var array<string, mixed> $advisoriesByPackage */
        $advisoriesByPackage = $decoded['advisories'];

        foreach ($advisoriesByPackage as $packageName => $advisories) {
            if (!\is_array($advisories)) {
                continue;
            }

            $entries[PackageNameNormalizer::normalize($packageName)] = $this->mapAdvisories($advisories);
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
