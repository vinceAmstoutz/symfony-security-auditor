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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Chunk;

use Closure;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Validator\Validation;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\AttackerChunkCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\OversizedChunkRecovery;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMFixedPromptTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityHydrationResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class OversizedChunkRecoveryTest extends TestCase
{
    private const int FILE_BYTES = 100;

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_single_file_that_is_exactly_a_tenth_of_the_refused_prompt_is_recorded_errored_and_the_run_goes_on(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $vulnerabilityHydrationResult = $this->recovery()->recover(
            [$this->file()],
            new ChunkContext(str_repeat('s', 400), str_repeat('u', 600), '', false, self::FILE_BYTES),
            'prompt is too long',
            $recordingCoverageRecorder,
            $this->unreachableAnalysis(),
        );

        self::assertSame([], $vulnerabilityHydrationResult->vulnerabilities());
        self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_single_file_just_under_a_tenth_of_the_refused_system_prompt_and_user_message_stops_the_run(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $this->expectException(LLMFixedPromptTooLargeException::class);
        $this->expectExceptionMessage('even with only the 100-byte file "src/A.php" in it (prompt is too long)');

        try {
            $this->recovery()->recover(
                [$this->file()],
                new ChunkContext(str_repeat('s', 401), str_repeat('u', 600), '', false, self::FILE_BYTES),
                'prompt is too long',
                $recordingCoverageRecorder,
                $this->unreachableAnalysis(),
            );
        } finally {
            self::assertSame([['stage' => 'attacker', 'filePath' => 'src/A.php', 'status' => 'errored']], $recordingCoverageRecorder->coverage);
        }
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_the_file_is_measured_as_the_prompt_carried_it_after_code_slicing(): void
    {
        $this->expectException(LLMFixedPromptTooLargeException::class);
        $this->expectExceptionMessage('even with only the 100-byte file "src/A.php" in it');

        $this->recovery()->recover(
            [ProjectFile::create('src/A.php', '/app/src/A.php', str_repeat('x', 5000))],
            new ChunkContext(str_repeat('s', 401), str_repeat('u', 600), '', false, self::FILE_BYTES),
            'prompt is too long',
            new RecordingCoverageRecorder(),
            $this->unreachableAnalysis(),
        );
    }

    private function recovery(): OversizedChunkRecovery
    {
        $vulnerabilityFactory = new VulnerabilityFactory(new NullLogger(), Validation::createValidator());

        return new OversizedChunkRecovery(new NullLogger(), new AttackerChunkCache(new NullAttackerCache(), $vulnerabilityFactory, new NullLogger()), $vulnerabilityFactory);
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function file(): ProjectFile
    {
        return ProjectFile::create('src/A.php', '/app/src/A.php', str_repeat('x', self::FILE_BYTES));
    }

    /**
     * @return Closure(list<ProjectFile>, CoverageRecorderInterface): VulnerabilityHydrationResult
     */
    private function unreachableAnalysis(): Closure
    {
        return static function (): VulnerabilityHydrationResult {
            self::fail('a single file is never split, so no half is analyzed');
        };
    }
}
