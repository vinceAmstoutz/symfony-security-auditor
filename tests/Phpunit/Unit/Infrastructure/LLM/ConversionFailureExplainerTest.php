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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\AI\Platform\Exception\BadRequestException;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\RawHttpResult;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Contracts\HttpClient\ResponseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\ConversionFailureExplainer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnconvertedAnswerException;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Fixture\FailingResultConverter;

final class ConversionFailureExplainerTest extends TestCase
{
    private const string AZURE_FILTERED = "The response was filtered due to the prompt triggering Azure OpenAI's content management policy.";

    public function test_a_content_filter_the_raw_answer_names_by_its_error_code_cuts_the_answer_short(): void
    {
        $badRequestException = new BadRequestException(self::AZURE_FILTERED);

        $throwable = (new ConversionFailureExplainer())->explain($badRequestException, $this->failedConversion($badRequestException, $this->azureContentFilterBody()));

        self::assertInstanceOf(UnconvertedAnswerException::class, $throwable);
        self::assertSame('content-filter', $throwable->stopReason);
        self::assertSame(self::AZURE_FILTERED, $throwable->getMessage());
        self::assertSame($badRequestException, $throwable->getPrevious());
    }

    /**
     * @param array<string, mixed> $rawAnswer
     */
    #[DataProvider('rawAnswersThatExplainNothingCases')]
    public function test_a_raw_answer_that_names_nothing_the_bridge_lost_leaves_the_failure_as_it_is(array $rawAnswer): void
    {
        $badRequestException = new BadRequestException('Bad Request');

        self::assertSame($badRequestException, (new ConversionFailureExplainer())->explain($badRequestException, $this->failedConversion($badRequestException, $rawAnswer)));
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function rawAnswersThatExplainNothingCases(): iterable
    {
        yield 'another error code' => [['error' => ['message' => 'Bad Request', 'code' => 'invalid_request_error']]];
        yield 'an error without a code' => [['error' => ['message' => 'Bad Request']]];
        yield 'an error that is only a message' => [['error' => 'content_filter']];
        yield 'no error at all' => [[]];
    }

    public function test_a_raw_answer_that_cannot_be_read_leaves_the_failure_as_it_is(): void
    {
        $badRequestException = new BadRequestException('Bad Request');
        $unreadable = self::createStub(ResponseInterface::class);
        $unreadable->method('toArray')->willThrowException(new TransportException('Transfer closed with 512 bytes remaining to read for "https://gw.example.com/v1/chat/completions".'));
        $deferredResult = new DeferredResult(new FailingResultConverter($badRequestException), new RawHttpResult($unreadable));
        $this->expectConversionToFailWith($badRequestException, $deferredResult);

        self::assertSame($badRequestException, (new ConversionFailureExplainer())->explain($badRequestException, $deferredResult));
    }

    public function test_a_failure_before_any_answer_came_back_is_left_as_it_is(): void
    {
        $runtimeException = new RuntimeException('dispatch failed');

        self::assertSame($runtimeException, (new ConversionFailureExplainer())->explain($runtimeException, null));
    }

    public function test_a_failure_after_the_answer_converted_is_not_read_against_that_answer(): void
    {
        $runtimeException = new RuntimeException('token usage could not be extracted');
        $deferredResult = new DeferredResult(new PlainConverter(new TextResult('converted')), new InMemoryRawResult($this->azureContentFilterBody()));
        $deferredResult->getResult();

        self::assertSame($runtimeException, (new ConversionFailureExplainer())->explain($runtimeException, $deferredResult));
    }

    /**
     * @param array<string, mixed> $rawAnswer
     */
    private function failedConversion(RuntimeException $runtimeException, array $rawAnswer): DeferredResult
    {
        $deferredResult = new DeferredResult(new FailingResultConverter($runtimeException), new InMemoryRawResult($rawAnswer));
        $this->expectConversionToFailWith($runtimeException, $deferredResult);

        return $deferredResult;
    }

    private function expectConversionToFailWith(RuntimeException $runtimeException, DeferredResult $deferredResult): void
    {
        try {
            $deferredResult->getResult();
        } catch (RuntimeException $conversionFailure) {
            self::assertSame($runtimeException, $conversionFailure);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function azureContentFilterBody(): array
    {
        return ['error' => ['message' => self::AZURE_FILTERED, 'type' => null, 'param' => 'prompt', 'code' => 'content_filter', 'status' => 400]];
    }
}
