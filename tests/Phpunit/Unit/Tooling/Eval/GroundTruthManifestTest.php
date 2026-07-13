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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Tooling\Eval;

use Override;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\Exception\InvalidGroundTruthManifestException;
use VinceAmstoutz\SymfonySecurityAuditor\Tooling\Eval\GroundTruthManifest;

final class GroundTruthManifestTest extends TestCase
{
    private Filesystem $filesystem;

    private string $tmpDir;

    #[Override]
    protected function setUp(): void
    {
        $this->filesystem = new Filesystem();
        $this->tmpDir = sys_get_temp_dir().'/ground_truth_test_'.uniqid('', true);
        $this->filesystem->mkdir($this->tmpDir);
    }

    #[Override]
    protected function tearDown(): void
    {
        $this->filesystem->remove($this->tmpDir);
    }

    /**
     * @throws InvalidGroundTruthManifestException
     */
    public function test_it_loads_the_seeded_findings(): void
    {
        $path = $this->write('{"findings":[{"file":"src/A.php","type":"sql_injection"}]}');

        $groundTruthManifest = GroundTruthManifest::fromFile($path);

        self::assertCount(1, $groundTruthManifest->findings);
        self::assertSame('src/A.php', $groundTruthManifest->findings[0]->file);
        self::assertSame('sql_injection', $groundTruthManifest->findings[0]->type);
        self::assertSame('src/A.php::sql_injection', $groundTruthManifest->findings[0]->key());
    }

    /**
     * @throws InvalidGroundTruthManifestException
     */
    public function test_the_shipped_example_manifest_is_valid(): void
    {
        $groundTruthManifest = GroundTruthManifest::fromFile(__DIR__.'/../../../../../examples/vulnerable-app/ground-truth.json');

        self::assertNotEmpty($groundTruthManifest->findings);
    }

    /**
     * @throws InvalidGroundTruthManifestException
     */
    public function test_a_missing_file_is_rejected(): void
    {
        $this->expectException(InvalidGroundTruthManifestException::class);
        $this->expectExceptionMessage('does not exist or is not readable');

        GroundTruthManifest::fromFile($this->tmpDir.'/absent.json');
    }

    /**
     * @throws InvalidGroundTruthManifestException
     */
    public function test_invalid_json_is_rejected(): void
    {
        $this->expectException(InvalidGroundTruthManifestException::class);
        $this->expectExceptionMessage('is not valid JSON');

        GroundTruthManifest::fromFile($this->write('{not json'));
    }

    /**
     * @throws InvalidGroundTruthManifestException
     */
    public function test_a_document_without_a_findings_array_is_rejected(): void
    {
        $this->expectException(InvalidGroundTruthManifestException::class);
        $this->expectExceptionMessage('must be a JSON object with a "findings" array');

        GroundTruthManifest::fromFile($this->write('{"version":1}'));
    }

    /**
     * @throws InvalidGroundTruthManifestException
     */
    public function test_a_finding_missing_its_type_is_rejected(): void
    {
        $this->expectException(InvalidGroundTruthManifestException::class);
        $this->expectExceptionMessage('index 0');

        GroundTruthManifest::fromFile($this->write('{"findings":[{"file":"src/A.php"}]}'));
    }

    /**
     * @throws InvalidGroundTruthManifestException
     */
    public function test_a_finding_with_a_blank_file_is_rejected(): void
    {
        $this->expectException(InvalidGroundTruthManifestException::class);

        GroundTruthManifest::fromFile($this->write('{"findings":[{"file":"","type":"sql_injection"}]}'));
    }

    private function write(string $contents): string
    {
        $path = $this->tmpDir.'/ground-truth.json';
        $this->filesystem->dumpFile($path, $contents);

        return $path;
    }
}
