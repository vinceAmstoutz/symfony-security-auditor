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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture;

use Override;
use Symfony\Component\Filesystem\Exception\IOException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ReviewerFeedback;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Baseline;
use VinceAmstoutz\SymfonySecurityAuditor\Command\BaselineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\BaselineWriteFailedException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\MalformedBaselineFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\UnsafeBaselineWriteException;

/**
 * Test fake — a real baseline whose path passes the check made before the
 * run, yet whose save fails once the run is over, as a full disk would.
 *
 * @internal scoped to AuditCommand save-failure integration tests
 */
final readonly class UnsavableBaseline implements BaselineInterface
{
    public const string FAILURE = 'No space left on device';

    public function __construct(
        private Baseline $baseline = new Baseline(),
    ) {}

    /**
     * @throws MalformedBaselineFileException
     */
    #[Override]
    public function load(string $path): array
    {
        return $this->baseline->load($path);
    }

    /**
     * @throws MalformedBaselineFileException
     */
    #[Override]
    public function entries(string $path): array
    {
        return $this->baseline->entries($path);
    }

    /**
     * @throws MalformedBaselineFileException
     */
    #[Override]
    public function feedback(string $path): ReviewerFeedback
    {
        return $this->baseline->feedback($path);
    }

    /**
     * @throws UnsafeBaselineWriteException
     * @throws BaselineWriteFailedException
     */
    #[Override]
    public function assertWritable(string $path, string $projectPath): void
    {
        $this->baseline->assertWritable($path, $projectPath);
    }

    /**
     * @throws MalformedBaselineFileException
     */
    #[Override]
    public function save(string $path, array $entries, ?string $projectPath = null): void
    {
        throw MalformedBaselineFileException::fromIOException($path, new IOException(self::FAILURE));
    }
}
