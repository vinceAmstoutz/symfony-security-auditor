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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\LockfileInstalledPackagesReader;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Advisory\Fixture\WarningRecordingLogger;

final class LockfileInstalledPackagesReaderTest extends TestCase
{
    private string $projectDir;

    public function test_it_reads_every_locked_package_with_its_version(): void
    {
        file_put_contents($this->projectDir.'/composer.lock', (string) json_encode([
            'packages' => [['name' => 'symfony/http-kernel', 'version' => 'v8.2.0']],
            'packages-dev' => [['name' => 'phpunit/phpunit', 'version' => '13.4.1']],
        ]));

        self::assertSame(['symfony/http-kernel' => 'v8.2.0', 'phpunit/phpunit' => '13.4.1'], $this->reader()->read($this->projectDir));
    }

    public function test_a_project_without_a_lockfile_has_no_known_packages(): void
    {
        self::assertNull($this->reader()->read($this->projectDir));
    }

    public function test_a_lockfile_that_is_not_json_has_no_known_packages(): void
    {
        file_put_contents($this->projectDir.'/composer.lock', '{"packages": [');

        self::assertNull($this->reader()->read($this->projectDir));
    }

    public function test_it_warns_about_a_lockfile_it_cannot_read(): void
    {
        file_put_contents($this->projectDir.'/composer.lock', '{"packages": [');
        $warningRecordingLogger = new WarningRecordingLogger();

        $this->reader($warningRecordingLogger)->read($this->projectDir);

        self::assertCount(1, $warningRecordingLogger->warnings);
    }

    public function test_json_that_lists_no_packages_is_no_lockfile(): void
    {
        file_put_contents($this->projectDir.'/composer.lock', '{"content-hash": "abc"}');

        self::assertNull($this->reader()->read($this->projectDir));
    }

    public function test_a_lockfile_that_is_no_json_object_is_no_lockfile(): void
    {
        file_put_contents($this->projectDir.'/composer.lock', '42');

        self::assertNull($this->reader()->read($this->projectDir));
    }

    public function test_it_skips_a_locked_entry_without_a_name_and_a_version(): void
    {
        file_put_contents($this->projectDir.'/composer.lock', '{"packages": [{"version": "1.0.0"}, {"name": "acme/kept", "version": "2.0.0"}, {"name": "acme/no-version"}, "acme/flat"]}');

        self::assertSame(['acme/kept' => '2.0.0'], $this->reader()->read($this->projectDir));
    }

    public function test_it_reads_a_lockfile_that_only_lists_development_packages(): void
    {
        file_put_contents($this->projectDir.'/composer.lock', '{"packages-dev": [{"name": "acme/dev", "version": "1.0.0"}]}');

        self::assertSame(['acme/dev' => '1.0.0'], $this->reader()->read($this->projectDir));
    }

    public function test_a_lockfile_linked_from_outside_the_project_is_not_read(): void
    {
        $outside = sys_get_temp_dir().'/installed_packages_outside_'.uniqid('', true).'.lock';
        file_put_contents($outside, '{"packages": [{"name": "acme/outside", "version": "1.0.0"}]}');
        symlink($outside, $this->projectDir.'/composer.lock');

        try {
            self::assertNull($this->reader()->read($this->projectDir));
        } finally {
            unlink($outside);
        }
    }

    public function test_it_warns_about_a_lockfile_linked_from_outside_the_project(): void
    {
        $outside = sys_get_temp_dir().'/installed_packages_outside_'.uniqid('', true).'.lock';
        file_put_contents($outside, '{"packages": []}');
        symlink($outside, $this->projectDir.'/composer.lock');
        $warningRecordingLogger = new WarningRecordingLogger();

        try {
            $this->reader($warningRecordingLogger)->read($this->projectDir);
            self::assertCount(1, $warningRecordingLogger->warnings);
        } finally {
            unlink($outside);
        }
    }

    public function test_a_lockfile_over_the_size_limit_is_not_read(): void
    {
        $lock = '{"packages": [{"name": "acme/big", "version": "1.0.0"}]}';
        file_put_contents($this->projectDir.'/composer.lock', $lock.str_repeat(' ', LockfileHasher::MAX_LOCKFILE_BYTES + 1 - \strlen($lock)));

        self::assertNull($this->reader()->read($this->projectDir));
    }

    public function test_a_lockfile_at_the_size_limit_is_read(): void
    {
        $lock = '{"packages": [{"name": "acme/big", "version": "1.0.0"}]}';
        file_put_contents($this->projectDir.'/composer.lock', $lock.str_repeat(' ', LockfileHasher::MAX_LOCKFILE_BYTES - \strlen($lock)));

        self::assertSame(['acme/big' => '1.0.0'], $this->reader()->read($this->projectDir));
    }

    public function test_it_warns_about_a_lockfile_over_the_size_limit(): void
    {
        file_put_contents($this->projectDir.'/composer.lock', str_repeat(' ', LockfileHasher::MAX_LOCKFILE_BYTES + 1));
        $warningRecordingLogger = new WarningRecordingLogger();

        $this->reader($warningRecordingLogger)->read($this->projectDir);

        self::assertCount(1, $warningRecordingLogger->warnings);
    }

    public function test_a_lockfile_that_cannot_be_read_has_no_known_packages(): void
    {
        mkdir($this->projectDir.'/composer.lock');

        self::assertNull($this->reader()->read($this->projectDir));
    }

    public function test_it_warns_about_a_lockfile_that_cannot_be_read(): void
    {
        mkdir($this->projectDir.'/composer.lock');
        $warningRecordingLogger = new WarningRecordingLogger();

        $this->reader($warningRecordingLogger)->read($this->projectDir);

        self::assertCount(1, $warningRecordingLogger->warnings);
    }

    #[Override]
    protected function setUp(): void
    {
        $this->projectDir = sys_get_temp_dir().'/installed_packages_reader_'.uniqid('', true);
        mkdir($this->projectDir, 0o777, true);
    }

    #[Override]
    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->projectDir);
    }

    private function reader(?LoggerInterface $logger = null): LockfileInstalledPackagesReader
    {
        return new LockfileInstalledPackagesReader(new Filesystem(), $logger ?? new NullLogger());
    }
}
