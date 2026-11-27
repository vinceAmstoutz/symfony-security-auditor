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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityHydrationResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Cache\NullAttackerCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\CliAgentPromptTooLongException;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\ExpectsExceptionMessageTrait;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\RecordingCoverageRecorder;

final class OversizedChunkRecoveryTest extends TestCase
{
    use ExpectsExceptionMessageTrait;

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
            new LLMRequestTooLargeException('prompt is too long'),
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
        $this->expectExceptionMessageContaining('even with only the 100-byte file "src/A.php" in it (prompt is too long)');

        try {
            $this->recovery()->recover(
                [$this->file()],
                new ChunkContext(str_repeat('s', 401), str_repeat('u', 600), '', false, self::FILE_BYTES),
                new LLMRequestTooLargeException('prompt is too long'),
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
        $this->expectExceptionMessageContaining('even with only the 100-byte file "src/A.php" in it');

        $this->recovery()->recover(
            [ProjectFile::create('src/A.php', '/app/src/A.php', str_repeat('x', 5000))],
            new ChunkContext(str_repeat('s', 401), str_repeat('u', 600), '', false, self::FILE_BYTES),
            new LLMRequestTooLargeException('prompt is too long'),
            new RecordingCoverageRecorder(),
            $this->unreachableAnalysis(),
        );
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_file_code_slicing_cannot_trim_is_not_told_to_turn_it_on(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $this->recovery()->recover(
            [ProjectFile::create('config/huge.yaml', '/app/config/huge.yaml', str_repeat('x', 2049))],
            new ChunkContext(str_repeat('s', 400), str_repeat('u', 600), '', false, 2049),
            new LLMRequestTooLargeException('prompt is too long'),
            $recordingCoverageRecorder,
            $this->unreachableAnalysis(),
        );

        self::assertSame('the file is too large for the model input limit: use a model with a larger context window or set scan.max_file_size_kb below 3 to skip it', $recordingCoverageRecorder->failureReasons[0]['reason']);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_file_code_slicing_already_trimmed_is_not_told_to_turn_it_on(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $this->recovery()->recover(
            [ProjectFile::create('src/Huge.php', '/app/src/Huge.php', str_repeat('x', 4096))],
            new ChunkContext(str_repeat('s', 400), str_repeat('u', 600), '', false, 4095),
            new LLMRequestTooLargeException('prompt is too long'),
            $recordingCoverageRecorder,
            $this->unreachableAnalysis(),
        );

        self::assertSame('the file is too large for the model input limit: use a model with a larger context window or set scan.max_file_size_kb below 4 to skip it', $recordingCoverageRecorder->failureReasons[0]['reason']);
    }

    /**
     * @throws InvalidProjectFileException
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function test_a_file_the_command_line_of_a_subscription_cli_cannot_carry_is_not_told_to_use_a_larger_context_window(): void
    {
        $recordingCoverageRecorder = new RecordingCoverageRecorder();

        $this->recovery()->recover(
            [ProjectFile::create('src/Huge.php', '/app/src/Huge.php', str_repeat('x', 4096))],
            new ChunkContext(str_repeat('s', 400), str_repeat('u', 600), '', false, 4096),
            LLMRequestTooLargeException::fromProviderRejection(CliAgentPromptTooLongException::forOneArgument(131071)),
            $recordingCoverageRecorder,
            $this->unreachableAnalysis(),
        );

        self::assertSame('the file is too large for the command-line limit of the subscription CLI: turn on audit.code_slicing.enabled, set scan.max_file_size_kb below 4 to skip it or run on an API platform', $recordingCoverageRecorder->failureReasons[0]['reason']);
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
