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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Advisory;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\LockfileHasher;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Advisory\Fixture\WarningRecordingLogger;

final class LockfileHasherTest extends TestCase
{
    private string $projectDir;

    public function test_it_hashes_the_content_of_the_lockfile(): void
    {
        file_put_contents($this->projectDir.'/composer.lock', '{"lock": "v1"}');

        self::assertSame(hash('sha256', '{"lock": "v1"}'), $this->hasher()->hash($this->projectDir));
    }

    public function test_it_hashes_the_lockfile_of_a_project_whose_name_is_not_valid_utf8(): void
    {
        $project = $this->projectDir."/jos\xE9/";
        mkdir($project, 0o777, true);
        file_put_contents($project.'composer.lock', '{"lock": "v1"}');

        self::assertSame(hash('sha256', '{"lock": "v1"}'), $this->hasher()->hash($project));
    }

    public function test_a_trailing_slash_on_the_project_path_does_not_double_the_separator_before_the_lockfile(): void
    {
        $target = sys_get_temp_dir().'/lockfile_hasher_outside_'.uniqid('', true).'.lock';
        file_put_contents($target, '{"lock": "v1"}');
        symlink($target, $this->projectDir.'/composer.lock');
        $warningRecordingLogger = new WarningRecordingLogger();

        try {
            $this->hasher($warningRecordingLogger)->hash($this->projectDir.'//');
        } finally {
            unlink($target);
        }

        self::assertSame([['composer.lock is a symlink that does not lead to a regular file inside the project; skipping advisory cache', ['path' => $this->projectDir.'/composer.lock']]], $warningRecordingLogger->warnings);
    }

    public function test_it_has_no_hash_for_a_project_without_a_lockfile(): void
    {
        self::assertNull($this->hasher()->hash($this->projectDir));
    }

    public function test_it_hashes_the_target_of_a_lockfile_symlinked_to_a_file_inside_the_project(): void
    {
        file_put_contents($this->projectDir.'/elsewhere.lock', '{"lock": "v1"}');
        symlink($this->projectDir.'/elsewhere.lock', $this->projectDir.'/composer.lock');
        $warningRecordingLogger = new WarningRecordingLogger();

        $hash = $this->hasher($warningRecordingLogger)->hash($this->projectDir);

        self::assertSame(hash('sha256', '{"lock": "v1"}'), $hash);
        self::assertSame([], $warningRecordingLogger->warnings);
    }

    public function test_it_has_no_hash_for_a_lockfile_symlinked_outside_the_project_and_says_why(): void
    {
        $target = sys_get_temp_dir().'/lockfile_hasher_outside_'.uniqid('', true).'.lock';
        file_put_contents($target, '{"lock": "v1"}');
        symlink($target, $this->projectDir.'/composer.lock');
        $warningRecordingLogger = new WarningRecordingLogger();

        try {
            $hash = $this->hasher($warningRecordingLogger)->hash($this->projectDir);
        } finally {
            unlink($target);
        }

        self::assertNull($hash);
        self::assertSame([['composer.lock is a symlink that does not lead to a regular file inside the project; skipping advisory cache', ['path' => $this->projectDir.'/composer.lock']]], $warningRecordingLogger->warnings);
    }

    public function test_it_has_no_hash_for_a_symlinked_lockfile_over_the_size_cap_and_says_why(): void
    {
        $handle = fopen($this->projectDir.'/elsewhere.lock', 'w');
        self::assertIsResource($handle);
        ftruncate($handle, LockfileHasher::MAX_LOCKFILE_BYTES + 1);
        fclose($handle);
        symlink($this->projectDir.'/elsewhere.lock', $this->projectDir.'/composer.lock');
        $warningRecordingLogger = new WarningRecordingLogger();

        $hash = $this->hasher($warningRecordingLogger)->hash($this->projectDir);

        self::assertNull($hash);
        self::assertSame(
            [['composer.lock is too large; skipping advisory cache', [
                'path' => $this->projectDir.'/composer.lock',
                'bytes' => LockfileHasher::MAX_LOCKFILE_BYTES + 1,
                'max_bytes' => LockfileHasher::MAX_LOCKFILE_BYTES,
            ]]],
            $warningRecordingLogger->warnings,
        );
    }

    public function test_it_has_no_hash_for_a_lockfile_over_the_size_cap_and_says_why(): void
    {
        $this->writeLockfileOfSize(LockfileHasher::MAX_LOCKFILE_BYTES + 1);
        $warningRecordingLogger = new WarningRecordingLogger();

        $hash = $this->hasher($warningRecordingLogger)->hash($this->projectDir);

        self::assertNull($hash);
        self::assertSame(
            [['composer.lock is too large; skipping advisory cache', [
                'path' => $this->projectDir.'/composer.lock',
                'bytes' => LockfileHasher::MAX_LOCKFILE_BYTES + 1,
                'max_bytes' => LockfileHasher::MAX_LOCKFILE_BYTES,
            ]]],
            $warningRecordingLogger->warnings,
        );
    }

    public function test_it_hashes_a_lockfile_exactly_at_the_size_cap(): void
    {
        $this->writeLockfileOfSize(LockfileHasher::MAX_LOCKFILE_BYTES);

        self::assertSame(hash('sha256', str_repeat("\0", LockfileHasher::MAX_LOCKFILE_BYTES)), $this->hasher()->hash($this->projectDir));
    }

    #[Override]
    protected function setUp(): void
    {
        $this->projectDir = sys_get_temp_dir().'/lockfile_hasher_'.uniqid('', true);
        mkdir($this->projectDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->projectDir);
    }

    private function hasher(?LoggerInterface $logger = null): LockfileHasher
    {
        return new LockfileHasher(new Filesystem(), $logger ?? new NullLogger());
    }

    /**
     * @param int<0, max> $bytes
     */
    private function writeLockfileOfSize(int $bytes): void
    {
        $handle = fopen($this->projectDir.'/composer.lock', 'w');
        self::assertIsResource($handle);
        ftruncate($handle, $bytes);
        fclose($handle);
    }
}
