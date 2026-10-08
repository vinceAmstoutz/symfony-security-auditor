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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Review;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewerVerdictCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingReviewerCache;

final class ReviewerVerdictCacheTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_failed_cache_store_logs_a_warning_with_the_vulnerability_id_and_error(): void
    {
        $vulnerability = $this->vulnerability();

        $reviewerCache = self::createStub(ReviewerCacheInterface::class);
        $reviewerCache->method('store')->willThrowException(new RuntimeException('disk full'));

        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $message, array $context = []) use (&$warnings): void {
                $warnings[] = [$message, $context];
            },
        );

        (new ReviewerVerdictCache($reviewerCache, $logger))->store($vulnerability, 'code-context', ['accepted' => true]);

        self::assertSame(
            [['Failed to store reviewer verdict in cache', ['vulnerability_id' => $vulnerability->id(), 'error' => 'disk full']]],
            $warnings,
        );
    }

    /**
     * @param array<string, mixed>|null $verdict
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    #[DataProvider('verdictsThatJudgeNothing')]
    public function test_a_verdict_that_judges_nothing_is_never_persisted(?array $verdict): void
    {
        $recordingReviewerCache = new RecordingReviewerCache();

        (new ReviewerVerdictCache($recordingReviewerCache, new NullLogger()))->store($this->vulnerability(), 'code-context', $verdict);

        self::assertSame([], $recordingReviewerCache->stored);
    }

    /**
     * @return iterable<string, array{array<string, mixed>|null}>
     */
    public static function verdictsThatJudgeNothing(): iterable
    {
        yield 'no verdict at all' => [null];
        yield 'an empty verdict' => [[]];
        yield 'notes only' => [['reviewer_notes' => 'not exploitable']];
        yield 'an accepted flag set to null' => [['accepted' => null]];
        yield 'an accepted flag the auditor cannot read' => [['accepted' => 'rejected', 'reviewer_notes' => 'not exploitable']];
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_an_explicit_rejection_is_persisted(): void
    {
        $recordingReviewerCache = new RecordingReviewerCache();

        (new ReviewerVerdictCache($recordingReviewerCache, new NullLogger()))->store($this->vulnerability(), 'code-context', ['accepted' => false, 'reviewer_notes' => 'input is validated upstream']);

        self::assertSame([['accepted' => false, 'reviewer_notes' => 'input is validated upstream']], $recordingReviewerCache->stored);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_cached_verdict_whose_accepted_flag_cannot_be_read_is_a_miss_so_the_reviewer_is_asked_again(): void
    {
        $reviewerCache = self::createStub(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(['accepted' => 'rejected']);

        self::assertNull((new ReviewerVerdictCache($reviewerCache, new NullLogger()))->get($this->vulnerability(), 'code-context', false));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_a_cached_verdict_with_a_readable_accepted_flag_is_served(): void
    {
        $reviewerCache = self::createStub(ReviewerCacheInterface::class);
        $reviewerCache->method('get')->willReturn(['accepted' => 'no', 'reviewer_notes' => 'validated upstream']);

        self::assertSame(
            ['accepted' => 'no', 'reviewer_notes' => 'validated upstream'],
            (new ReviewerVerdictCache($reviewerCache, new NullLogger()))->get($this->vulnerability(), 'code-context', false),
        );
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function vulnerability(): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, 'T', 0.9),
            new CodeLocation('src/A.php', 18, 20),
            new VulnerabilityNarrative('d', 'a', 'p', 'r'),
            'c',
        );
    }
}
