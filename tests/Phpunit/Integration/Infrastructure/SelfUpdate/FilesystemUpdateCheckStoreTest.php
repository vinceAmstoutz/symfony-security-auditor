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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Infrastructure\SelfUpdate;

use DateTimeImmutable;
use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\XdgConfigPathResolver;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\FilesystemUpdateCheckStore;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\UpdateCheckState;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Infrastructure\SelfUpdate\Fixture\RecordingLogger;

final class FilesystemUpdateCheckStoreTest extends TestCase
{
    private Filesystem $filesystem;

    private string $cacheHome;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->cacheHome = sys_get_temp_dir().'/ssa-update-cache-'.bin2hex(random_bytes(6));
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->cacheHome);
    }

    public function test_it_round_trips_a_state(): void
    {
        $filesystemUpdateCheckStore = $this->resolvableStore();
        $filesystemUpdateCheckStore->write(new UpdateCheckState(new DateTimeImmutable('@1700000000'), '2.0.0'));

        self::assertEquals(new UpdateCheckState(new DateTimeImmutable('@1700000000'), '2.0.0'), $filesystemUpdateCheckStore->read());
    }

    public function test_it_treats_a_missing_cache_as_absent(): void
    {
        self::assertNull($this->resolvableStore()->read());
    }

    public function test_it_treats_malformed_json_as_absent(): void
    {
        $this->filesystem->dumpFile($this->cacheFile(), 'not json{');

        self::assertNull($this->resolvableStore()->read());
    }

    #[DataProvider('structurallyInvalidPayloads')]
    public function test_it_rejects_a_structurally_invalid_payload(string $payload): void
    {
        $this->filesystem->dumpFile($this->cacheFile(), $payload);

        self::assertNull($this->resolvableStore()->read());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function structurallyInvalidPayloads(): iterable
    {
        yield 'json null' => ['null'];
        yield 'json scalar' => ['42'];
        yield 'missing keys' => ['{}'];
        yield 'checked_at is not an integer' => ['{"checked_at":"soon","latest_version":"2.0.0"}'];
        yield 'latest_version is not a string' => ['{"checked_at":1700000000,"latest_version":5}'];
        yield 'latest_version is empty' => ['{"checked_at":1700000000,"latest_version":""}'];
    }

    public function test_it_neither_reads_nor_writes_when_the_cache_path_is_unresolvable(): void
    {
        $filesystemUpdateCheckStore = $this->unresolvableStore();
        $filesystemUpdateCheckStore->write(new UpdateCheckState(new DateTimeImmutable('@1700000000'), '2.0.0'));

        self::assertNull($filesystemUpdateCheckStore->read());
    }

    public function test_it_treats_an_unreadable_cache_entry_as_absent(): void
    {
        $this->filesystem->mkdir($this->cacheFile());

        self::assertNull($this->resolvableStore()->read());
    }

    public function test_it_logs_the_error_when_the_cache_entry_is_unreadable(): void
    {
        $this->filesystem->mkdir($this->cacheFile());
        $recordingLogger = new RecordingLogger();

        $this->resolvableStore($recordingLogger)->read();

        self::assertSame([['error']], $recordingLogger->contextKeys());
    }

    public function test_it_silently_skips_a_failed_write(): void
    {
        $this->filesystem->dumpFile($this->cacheDir(), 'blocks the cache directory');

        $this->resolvableStore()->write(new UpdateCheckState(new DateTimeImmutable('@1700000000'), '2.0.0'));

        self::assertNull($this->resolvableStore()->read());
    }

    public function test_it_logs_the_error_when_writing_the_cache_fails(): void
    {
        $this->filesystem->dumpFile($this->cacheDir(), 'blocks the cache directory');
        $recordingLogger = new RecordingLogger();

        $this->resolvableStore($recordingLogger)->write(new UpdateCheckState(new DateTimeImmutable('@1700000000'), '2.0.0'));

        self::assertSame([['error']], $recordingLogger->contextKeys());
    }

    private function resolvableStore(?LoggerInterface $logger = null): FilesystemUpdateCheckStore
    {
        return new FilesystemUpdateCheckStore(new XdgConfigPathResolver(null, $this->cacheHome, null), $this->filesystem, $logger ?? new NullLogger());
    }

    private function unresolvableStore(): FilesystemUpdateCheckStore
    {
        return new FilesystemUpdateCheckStore(new XdgConfigPathResolver(null, null, null), $this->filesystem, new NullLogger());
    }

    private function cacheDir(): string
    {
        return $this->cacheHome.'/symfony-security-auditor';
    }

    private function cacheFile(): string
    {
        return $this->cacheDir().'/update-check.json';
    }
}
