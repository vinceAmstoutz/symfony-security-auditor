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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Cache;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AcceptedFindingFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CodeLocation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ReviewerFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityClassification;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityNarrative;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\Exception\InvalidCacheConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\FilesystemReviewerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Reviewer\ReviewerFeedbackHolder;

final class FilesystemReviewerCacheTest extends TestCase
{
    private string $cacheDir;

    private FilesystemReviewerCache $filesystemReviewerCache;

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_returns_null_when_no_entry_exists(): void
    {
        self::assertNull($this->filesystemReviewerCache->get($this->makeVulnerability('src/A.php'), 'code'));
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_skips_read_when_no_entry_exists(): void
    {
        $filesystem = $this->createMock(Filesystem::class);
        $filesystem->method('exists')->willReturn(false);
        $filesystem->expects(self::never())->method('readFile');

        $filesystemReviewerCache = new FilesystemReviewerCache($this->cacheDir, $filesystem, new NullLogger());

        self::assertNull($filesystemReviewerCache->get($this->makeVulnerability('src/A.php'), 'code'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_round_trip_store_and_get_returns_same_review(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $review = ['accepted' => true, 'adjusted_severity' => 'critical', 'reviewer_notes' => 'real'];

        $this->filesystemReviewerCache->store($vulnerability, 'code-context', $review);

        self::assertSame($review, $this->filesystemReviewerCache->get($vulnerability, 'code-context'));
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_round_trip_hits_under_the_same_baseline_feedback(): void
    {
        $filesystemReviewerCache = $this->cacheWithFeedback('accepted risk');
        $vulnerability = $this->makeVulnerability('src/A.php');

        $filesystemReviewerCache->store($vulnerability, 'code', ['accepted' => true]);

        self::assertSame(['accepted' => true], $filesystemReviewerCache->get($vulnerability, 'code'));
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_returns_null_when_the_baseline_feedback_changed(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');

        $this->cacheWithFeedback('accepted risk')->store($vulnerability, 'code', ['accepted' => true]);

        self::assertNull($this->cacheWithFeedback('guarded by voter')->get($vulnerability, 'code'));
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_returns_null_when_feedback_appears_after_a_feedback_free_store(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');

        $this->filesystemReviewerCache->store($vulnerability, 'code', ['accepted' => true]);

        self::assertNull($this->cacheWithFeedback('accepted risk')->get($vulnerability, 'code'));
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    private function cacheWithFeedback(string $reason): FilesystemReviewerCache
    {
        $reviewerFeedbackHolder = new ReviewerFeedbackHolder();
        $reviewerFeedbackHolder->set(new ReviewerFeedback([
            new AcceptedFindingFeedback('sql_injection', 'src/Foo.php', 'Accepted', $reason),
        ]));

        return new FilesystemReviewerCache($this->cacheDir, new Filesystem(), new NullLogger(), reviewerFeedbackProvider: $reviewerFeedbackHolder);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_returns_null_when_finding_content_differs(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php', title: 'original');
        $changed = $this->makeVulnerability('src/A.php', title: 'changed');

        $this->filesystemReviewerCache->store($vulnerability, 'code', ['accepted' => true]);

        self::assertNull($this->filesystemReviewerCache->get($changed, 'code'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_returns_null_when_code_context_differs(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');

        $this->filesystemReviewerCache->store($vulnerability, 'context one', ['accepted' => true]);

        self::assertNull($this->filesystemReviewerCache->get($vulnerability, 'context two'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_hits_for_a_distinct_finding_object_with_identical_content(): void
    {
        // Two separately-created findings with identical content reuse the same
        // verdict — the key is derived from content, not object identity. (The
        // key-format test pins that the non-deterministic `id` is excluded.)
        $vulnerability = $this->makeVulnerability('src/A.php', title: 'same');
        $twin = $this->makeVulnerability('src/A.php', title: 'same');
        $review = ['accepted' => false, 'reviewer_notes' => 'mitigated'];

        $this->filesystemReviewerCache->store($vulnerability, 'code', $review);

        self::assertSame($review, $this->filesystemReviewerCache->get($twin, 'code'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_hits_across_runs_despite_a_different_detected_at_timestamp(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php', title: 'same');
        $review = ['accepted' => true];
        $this->filesystemReviewerCache->store($vulnerability, 'code', $review);

        usleep(1_100_000);

        $secondRun = $this->makeVulnerability('src/A.php', title: 'same');

        self::assertNotEquals($vulnerability->toArray()['detected_at'], $secondRun->toArray()['detected_at']);
        self::assertSame($review, $this->filesystemReviewerCache->get($secondRun, 'code'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_returns_null_when_cache_file_is_invalid_json(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $this->filesystemReviewerCache->store($vulnerability, 'code', ['accepted' => true]);

        $globResult = glob($this->cacheDir.'/*/*.json');
        $files = false !== $globResult ? $globResult : [];
        self::assertNotEmpty($files);
        file_put_contents($files[0], 'not json{{{');

        self::assertNull($this->filesystemReviewerCache->get($vulnerability, 'code'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_returns_null_when_cache_file_contains_non_array_json(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $this->filesystemReviewerCache->store($vulnerability, 'code', ['accepted' => true]);

        $globResult = glob($this->cacheDir.'/*/*.json');
        $files = false !== $globResult ? $globResult : [];
        file_put_contents($files[0], '"a string"');

        self::assertNull($this->filesystemReviewerCache->get($vulnerability, 'code'));
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_returns_null_instead_of_throwing_when_finding_content_is_not_valid_utf8(): void
    {
        $vulnerability = $this->makeVulnerabilityWithCode('src/A.php', "\xB1\xB2 legacy latin1 snippet");

        self::assertNull($this->filesystemReviewerCache->get($vulnerability, 'code'));
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_logs_warning_when_finding_content_is_not_valid_utf8(): void
    {
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );
        $logger->method('debug');

        $filesystemReviewerCache = new FilesystemReviewerCache($this->cacheDir, new Filesystem(), $logger);
        $vulnerability = $this->makeVulnerabilityWithCode('src/A.php', "\xB1\xB2 legacy latin1 snippet");

        self::assertNull($filesystemReviewerCache->get($vulnerability, 'code'));
        self::assertCount(1, $warnings);
        self::assertSame('Reviewer cache entry was unreadable, ignoring', $warnings[0][0]);
        self::assertNull($warnings[0][1]['path']);
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_store_logs_warning_instead_of_throwing_when_finding_content_is_not_valid_utf8(): void
    {
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );
        $logger->method('debug');

        $filesystemReviewerCache = new FilesystemReviewerCache($this->cacheDir, new Filesystem(), $logger);
        $vulnerability = $this->makeVulnerabilityWithCode('src/A.php', "\xB1\xB2 legacy latin1 snippet");

        $filesystemReviewerCache->store($vulnerability, 'code', ['accepted' => true]);

        self::assertCount(1, $warnings);
        self::assertSame('Failed to write reviewer cache entry', $warnings[0][0]);
        self::assertNull($warnings[0][1]['path']);
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    public function test_constructor_rejects_empty_cache_dir(): void
    {
        $this->expectException(InvalidCacheConfigurationException::class);
        $this->expectExceptionMessage('Reviewer cache dir cannot be empty');
        new FilesystemReviewerCache('   ', new Filesystem(), new NullLogger());
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_returns_null_when_filesystem_read_throws_io_exception(): void
    {
        $filesystem = self::createStub(Filesystem::class);
        $filesystem->method('exists')->willReturn(true);
        $filesystem->method('readFile')->willThrowException(new IOException('permission denied'));

        $filesystemReviewerCache = new FilesystemReviewerCache($this->cacheDir, $filesystem, new NullLogger());

        self::assertNull($filesystemReviewerCache->get($this->makeVulnerability('src/A.php'), 'code'));
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_logs_warning_with_path_and_error_when_read_throws_io_exception(): void
    {
        $filesystem = self::createStub(Filesystem::class);
        $filesystem->method('exists')->willReturn(true);
        $filesystem->method('readFile')->willThrowException(new IOException('permission denied'));

        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );
        $logger->method('debug');

        $filesystemReviewerCache = new FilesystemReviewerCache($this->cacheDir, $filesystem, $logger);
        $filesystemReviewerCache->get($this->makeVulnerability('src/A.php'), 'code');

        self::assertCount(1, $warnings);
        self::assertSame('Reviewer cache entry was unreadable, ignoring', $warnings[0][0]);
        self::assertArrayHasKey('path', $warnings[0][1]);
        self::assertSame('permission denied', $warnings[0][1]['error']);
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_logs_warning_when_cache_entry_is_unreadable_json(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $this->filesystemReviewerCache->store($vulnerability, 'code', ['accepted' => true]);

        $globResult = glob($this->cacheDir.'/*/*.json');
        $files = false !== $globResult ? $globResult : [];
        file_put_contents($files[0], '{{{');

        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );
        $logger->method('debug');

        $filesystemReviewerCache = new FilesystemReviewerCache($this->cacheDir, new Filesystem(), $logger);

        self::assertNull($filesystemReviewerCache->get($vulnerability, 'code'));
        self::assertCount(1, $warnings);
        self::assertSame('Reviewer cache entry was unreadable, ignoring', $warnings[0][0]);
        self::assertArrayHasKey('path', $warnings[0][1]);
        self::assertArrayHasKey('error', $warnings[0][1]);
        self::assertNotSame('', $warnings[0][1]['error']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_store_creates_nested_shard_directory_from_key_prefix(): void
    {
        $this->filesystemReviewerCache->store($this->makeVulnerability('src/A.php'), 'code', ['accepted' => true]);

        $globResult = glob($this->cacheDir.'/*/*.json');
        $files = false !== $globResult ? $globResult : [];
        self::assertCount(1, $files);
        $relative = substr($files[0], \strlen($this->cacheDir) + 1);
        self::assertMatchesRegularExpression('#^[a-f0-9]{2}/[a-f0-9]{64}\.json$#', $relative);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_store_refuses_to_write_through_a_symlinked_cache_file(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $codeContext = '<?php echo 1;';
        $finding = $vulnerability->toArray();
        unset($finding['id'], $finding['detected_at']);
        $expectedKey = hash('sha256', json_encode($finding, \JSON_THROW_ON_ERROR)."\0".$codeContext);
        $expectedPath = \sprintf('%s/%s/%s.json', $this->cacheDir, substr($expectedKey, 0, 2), $expectedKey);

        $outsideTarget = sys_get_temp_dir().'/reviewer_cache_symlink_target_'.uniqid('', true);
        file_put_contents($outsideTarget, 'ORIGINAL');
        mkdir(\dirname($expectedPath), recursive: true);
        symlink($outsideTarget, $expectedPath);

        try {
            $this->filesystemReviewerCache->store($vulnerability, $codeContext, ['accepted' => true]);

            self::assertSame('ORIGINAL', file_get_contents($outsideTarget));
        } finally {
            unlink($outsideTarget);
        }
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_store_refuses_to_write_through_a_symlinked_shard_directory(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $codeContext = '<?php echo 1;';
        $finding = $vulnerability->toArray();
        unset($finding['id'], $finding['detected_at']);
        $expectedKey = hash('sha256', json_encode($finding, \JSON_THROW_ON_ERROR)."\0".$codeContext);
        $shardDir = \sprintf('%s/%s', $this->cacheDir, substr($expectedKey, 0, 2));

        $outsideDir = sys_get_temp_dir().'/reviewer_cache_symlink_dir_'.uniqid('', true);
        mkdir($outsideDir);
        mkdir($this->cacheDir, recursive: true);
        symlink($outsideDir, $shardDir);

        try {
            $this->filesystemReviewerCache->store($vulnerability, $codeContext, ['accepted' => true]);

            $globResult = glob($outsideDir.'/*.json');
            self::assertSame([], false !== $globResult ? $globResult : []);
        } finally {
            $filesystem = new Filesystem();
            $filesystem->remove($outsideDir);
        }
    }

    /**
     * A cache path is derived entirely from the finding's own content
     * (attacker-influenced file paths/descriptions), so a malicious
     * contributor can pre-plant a symlink at the exact path this cache will
     * ever read from — with no `store()` ever called — turning a routine
     * cached-run into an arbitrary-file read whose content is trusted as a
     * real, previously-computed verdict.
     *
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_refuses_to_read_through_a_symlinked_cache_file(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $codeContext = '<?php echo 1;';
        $finding = $vulnerability->toArray();
        unset($finding['id'], $finding['detected_at']);
        $expectedKey = hash('sha256', json_encode($finding, \JSON_THROW_ON_ERROR)."\0".$codeContext);
        $expectedPath = \sprintf('%s/%s/%s.json', $this->cacheDir, substr($expectedKey, 0, 2), $expectedKey);

        $plantedTarget = sys_get_temp_dir().'/reviewer_cache_symlink_read_target_'.uniqid('', true);
        file_put_contents($plantedTarget, json_encode(['accepted' => false]));
        mkdir(\dirname($expectedPath), recursive: true);
        symlink($plantedTarget, $expectedPath);

        try {
            self::assertNull($this->filesystemReviewerCache->get($vulnerability, $codeContext));
        } finally {
            unlink($plantedTarget);
        }
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_logs_a_warning_with_the_path_when_refusing_a_symlinked_cache_file(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $codeContext = '<?php echo 1;';
        $finding = $vulnerability->toArray();
        unset($finding['id'], $finding['detected_at']);
        $expectedKey = hash('sha256', json_encode($finding, \JSON_THROW_ON_ERROR)."\0".$codeContext);
        $expectedPath = \sprintf('%s/%s/%s.json', $this->cacheDir, substr($expectedKey, 0, 2), $expectedKey);

        $plantedTarget = sys_get_temp_dir().'/reviewer_cache_symlink_log_target_'.uniqid('', true);
        file_put_contents($plantedTarget, json_encode(['accepted' => false]));
        mkdir(\dirname($expectedPath), recursive: true);
        symlink($plantedTarget, $expectedPath);

        /** @var list<array{string, array<string, string>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        try {
            (new FilesystemReviewerCache($this->cacheDir, new Filesystem(), $logger))->get($vulnerability, $codeContext);
        } finally {
            unlink($plantedTarget);
        }

        self::assertSame([['Reviewer cache entry path was a symlink, ignoring', ['path' => $expectedPath]]], $warnings);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_refuses_to_read_through_a_symlinked_shard_directory(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $codeContext = '<?php echo 1;';
        $finding = $vulnerability->toArray();
        unset($finding['id'], $finding['detected_at']);
        $expectedKey = hash('sha256', json_encode($finding, \JSON_THROW_ON_ERROR)."\0".$codeContext);
        $shardDir = \sprintf('%s/%s', $this->cacheDir, substr($expectedKey, 0, 2));

        $outsideDir = sys_get_temp_dir().'/reviewer_cache_symlink_read_dir_'.uniqid('', true);
        mkdir($outsideDir);
        file_put_contents(\sprintf('%s/%s.json', $outsideDir, $expectedKey), json_encode(['accepted' => false]));
        mkdir($this->cacheDir, recursive: true);
        symlink($outsideDir, $shardDir);

        try {
            self::assertNull($this->filesystemReviewerCache->get($vulnerability, $codeContext));
        } finally {
            $filesystem = new Filesystem();
            $filesystem->remove($outsideDir);
        }
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_store_calls_mkdir_to_create_shard_directory(): void
    {
        $filesystem = $this->createMock(Filesystem::class);
        $filesystem->expects(self::once())->method('mkdir');
        $filesystem->method('dumpFile');

        $filesystemReviewerCache = new FilesystemReviewerCache($this->cacheDir, $filesystem, new NullLogger());
        $filesystemReviewerCache->store($this->makeVulnerability('src/A.php'), 'code', ['accepted' => true]);
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_key_is_sha256_of_salt_null_byte_finding_without_id_and_code_context(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $codeContext = '<?php echo 1;';

        $finding = $vulnerability->toArray();
        unset($finding['id'], $finding['detected_at']);
        $signature = "claude-haiku-4-5\0".json_encode($finding, \JSON_THROW_ON_ERROR)."\0".$codeContext;
        $expectedKey = hash('sha256', $signature);
        $expectedPath = \sprintf('%s/%s/%s.json', $this->cacheDir, substr($expectedKey, 0, 2), $expectedKey);

        $filesystemReviewerCache = new FilesystemReviewerCache($this->cacheDir, new Filesystem(), new NullLogger(), 'claude-haiku-4-5');
        $filesystemReviewerCache->store($vulnerability, $codeContext, ['accepted' => true]);

        self::assertFileExists($expectedPath);
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_distinct_key_salts_produce_distinct_cache_entries(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $review = ['accepted' => true];

        $haiku = new FilesystemReviewerCache($this->cacheDir, new Filesystem(), new NullLogger(), 'claude-haiku-4-5');
        $opus = new FilesystemReviewerCache($this->cacheDir, new Filesystem(), new NullLogger(), 'claude-opus-4-7');

        $haiku->store($vulnerability, 'code', $review);

        self::assertSame($review, $haiku->get($vulnerability, 'code'));
        self::assertNull($opus->get($vulnerability, 'code'), 'switching the salt must invalidate the cache');
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_empty_salt_keeps_unprefixed_key(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $codeContext = 'ctx';

        $finding = $vulnerability->toArray();
        unset($finding['id'], $finding['detected_at']);
        $expectedKey = hash('sha256', json_encode($finding, \JSON_THROW_ON_ERROR)."\0".$codeContext);
        $expectedPath = \sprintf('%s/%s/%s.json', $this->cacheDir, substr($expectedKey, 0, 2), $expectedKey);

        $this->filesystemReviewerCache->store($vulnerability, $codeContext, ['accepted' => true]);

        self::assertFileExists($expectedPath);
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_dump_path_has_trailing_slash_stripped_from_cache_dir(): void
    {
        $capturedPath = '';
        $filesystem = self::createStub(Filesystem::class);
        $filesystem->method('dumpFile')->willReturnCallback(
            static function (string $path) use (&$capturedPath): void {
                $capturedPath = $path;
            },
        );

        $filesystemReviewerCache = new FilesystemReviewerCache($this->cacheDir.'/', $filesystem, new NullLogger());
        $filesystemReviewerCache->store($this->makeVulnerability('src/A.php'), 'code', ['accepted' => true]);

        self::assertStringNotContainsString('//', $capturedPath);
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_get_logs_debug_cache_hit_with_path(): void
    {
        $vulnerability = $this->makeVulnerability('src/A.php');
        $this->filesystemReviewerCache->store($vulnerability, 'code', ['accepted' => true]);

        $debugLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$debugLogs): void {
                $debugLogs[] = [$msg, $ctx];
            },
        );

        $filesystemReviewerCache = new FilesystemReviewerCache($this->cacheDir, new Filesystem(), $logger);
        $filesystemReviewerCache->get($vulnerability, 'code');

        $hitLogs = array_values(array_filter($debugLogs, static fn (array $e): bool => 'Reviewer cache hit' === $e[0]));
        self::assertCount(1, $hitLogs);
        self::assertArrayHasKey('path', $hitLogs[0][1]);
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_store_logs_debug_stored_with_path(): void
    {
        $debugLogs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$debugLogs): void {
                $debugLogs[] = [$msg, $ctx];
            },
        );

        $filesystemReviewerCache = new FilesystemReviewerCache($this->cacheDir, new Filesystem(), $logger);
        $filesystemReviewerCache->store($this->makeVulnerability('src/A.php'), 'code', ['accepted' => true]);

        $storedLogs = array_values(array_filter($debugLogs, static fn (array $e): bool => 'Reviewer cache stored' === $e[0]));
        self::assertCount(1, $storedLogs);
        self::assertArrayHasKey('path', $storedLogs[0][1]);
    }

    /**
     * @throws InvalidCacheConfigurationException
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    public function test_store_failure_logs_warning_with_path_and_error(): void
    {
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );
        $logger->method('debug');

        $filesystemReviewerCache = new FilesystemReviewerCache('/proc/cannot-write', new Filesystem(), $logger);
        $filesystemReviewerCache->store($this->makeVulnerability('src/A.php'), 'code', ['accepted' => true]);

        $failures = array_values(array_filter($warnings, static fn (array $e): bool => 'Failed to write reviewer cache entry' === $e[0]));
        self::assertCount(1, $failures);
        self::assertArrayHasKey('path', $failures[0][1]);
        self::assertArrayHasKey('error', $failures[0][1]);
        self::assertNotSame('', $failures[0][1]['error']);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeVulnerability(string $filePath, string $title = 'Finding'): Vulnerability
    {
        return $this->makeVulnerabilityWithCode($filePath, 'code', $title);
    }

    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     */
    private function makeVulnerabilityWithCode(string $filePath, string $vulnerableCode, string $title = 'Finding'): Vulnerability
    {
        return Vulnerability::of(
            new VulnerabilityClassification(VulnerabilityType::SQL_INJECTION, VulnerabilitySeverity::HIGH, $title, 0.9),
            new CodeLocation($filePath, 1, 5),
            new VulnerabilityNarrative('desc', 'vec', 'proof', 'fix'),
            $vulnerableCode,
        );
    }

    /**
     * @throws InvalidCacheConfigurationException
     */
    #[Override]
    protected function setUp(): void
    {
        $this->cacheDir = sys_get_temp_dir().'/reviewer_cache_'.uniqid('', true);
        $this->filesystemReviewerCache = new FilesystemReviewerCache($this->cacheDir, new Filesystem(), new NullLogger());
    }

    #[Override]
    protected function tearDown(): void
    {
        $filesystem = new Filesystem();
        if ($filesystem->exists($this->cacheDir)) {
            $filesystem->remove($this->cacheDir);
        }
    }
}
