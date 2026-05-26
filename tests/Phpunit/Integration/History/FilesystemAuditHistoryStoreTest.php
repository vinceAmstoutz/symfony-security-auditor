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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\History;

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\History\Exception\InvalidHistoryDirectoryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\History\FilesystemAuditHistoryStore;

final class FilesystemAuditHistoryStoreTest extends TestCase
{
    private string $tmpDir;

    private Filesystem $filesystem;

    public function test_it_throws_on_empty_history_dir(): void
    {
        $this->expectException(InvalidHistoryDirectoryException::class);

        new FilesystemAuditHistoryStore('   ', new Filesystem(), new NullLogger());
    }

    public function test_loading_unknown_project_returns_empty_list(): void
    {
        $filesystemAuditHistoryStore = $this->makeStore();

        self::assertSame([], $filesystemAuditHistoryStore->loadFingerprints('/some/project'));
    }

    public function test_stored_fingerprints_round_trip(): void
    {
        $filesystemAuditHistoryStore = $this->makeStore();

        $filesystemAuditHistoryStore->storeFingerprints('/some/project', ['FP-AAA', 'FP-BBB']);

        self::assertSame(['FP-AAA', 'FP-BBB'], $filesystemAuditHistoryStore->loadFingerprints('/some/project'));
    }

    public function test_storing_overwrites_previous_snapshot(): void
    {
        $filesystemAuditHistoryStore = $this->makeStore();

        $filesystemAuditHistoryStore->storeFingerprints('/p', ['FP-OLD']);
        $filesystemAuditHistoryStore->storeFingerprints('/p', ['FP-NEW']);

        self::assertSame(['FP-NEW'], $filesystemAuditHistoryStore->loadFingerprints('/p'));
    }

    public function test_different_projects_have_isolated_snapshots(): void
    {
        $filesystemAuditHistoryStore = $this->makeStore();

        $filesystemAuditHistoryStore->storeFingerprints('/project-a', ['FP-A']);
        $filesystemAuditHistoryStore->storeFingerprints('/project-b', ['FP-B']);

        self::assertSame(['FP-A'], $filesystemAuditHistoryStore->loadFingerprints('/project-a'));
        self::assertSame(['FP-B'], $filesystemAuditHistoryStore->loadFingerprints('/project-b'));
    }

    public function test_corrupt_history_file_is_treated_as_empty(): void
    {
        $filesystemAuditHistoryStore = $this->makeStore();
        $filesystemAuditHistoryStore->storeFingerprints('/p', ['FP-A']);

        $file = $this->onlyJsonFile();
        file_put_contents($file, 'not-json{{{');

        self::assertSame([], $filesystemAuditHistoryStore->loadFingerprints('/p'));
    }

    public function test_history_file_without_fingerprints_key_is_treated_as_empty(): void
    {
        $filesystemAuditHistoryStore = $this->makeStore();
        $filesystemAuditHistoryStore->storeFingerprints('/p', ['FP-A']);

        $file = $this->onlyJsonFile();
        file_put_contents($file, json_encode(['something_else' => true]));

        self::assertSame([], $filesystemAuditHistoryStore->loadFingerprints('/p'));
    }

    public function test_non_string_fingerprint_entries_are_dropped_on_load(): void
    {
        $filesystemAuditHistoryStore = $this->makeStore();
        $filesystemAuditHistoryStore->storeFingerprints('/p', ['FP-A']);

        $file = $this->onlyJsonFile();
        file_put_contents($file, json_encode(['fingerprints' => ['FP-A', 123, null, 'FP-B']]));

        self::assertSame(['FP-A', 'FP-B'], $filesystemAuditHistoryStore->loadFingerprints('/p'));
    }

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir().'/fs_history_store_test_'.uniqid('', true);
        mkdir($this->tmpDir, 0o777, true);
        $this->filesystem = new Filesystem();
    }

    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    private function makeStore(): FilesystemAuditHistoryStore
    {
        return new FilesystemAuditHistoryStore($this->tmpDir, $this->filesystem, new NullLogger());
    }

    private function onlyJsonFile(): string
    {
        $files = glob($this->tmpDir.'/*.json') ?: [];
        self::assertCount(1, $files);

        return $files[0];
    }
}
