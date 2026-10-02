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
use Symfony\AI\Platform\Exception\MalformedToolCallException;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\RawHttpResult;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\Contracts\HttpClient\ResponseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\ConversionFailureExplainer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\UnconvertedAnswerException;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Fixture\FailingResultConverter;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Fixture\UnreadableResponse;

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
    #[DataProvider('rawAnswersCutOffByTheOutputLimitCases')]
    public function test_an_answer_whose_raw_answer_shows_the_output_limit_cut_it_off_is_cut_short_by_length(array $rawAnswer): void
    {
        $malformedToolCallException = new MalformedToolCallException('Model returned malformed JSON arguments for the "record_vulnerability" tool: "Syntax error"');

        $throwable = (new ConversionFailureExplainer())->explain($malformedToolCallException, $this->failedConversion($malformedToolCallException, $rawAnswer));

        self::assertInstanceOf(UnconvertedAnswerException::class, $throwable);
        self::assertSame('length', $throwable->stopReason);
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function rawAnswersCutOffByTheOutputLimitCases(): iterable
    {
        yield 'chat completions finish reason' => [['choices' => [['index' => 0, 'finish_reason' => 'length']]]];
        yield 'chat completions finish reason of a later choice' => [['choices' => [['index' => 0, 'finish_reason' => 'tool_calls'], ['index' => 1, 'finish_reason' => 'length']]]];
        yield 'responses api incomplete reason' => [['status' => 'incomplete', 'incomplete_details' => ['reason' => 'max_output_tokens']]];
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
        yield 'a choice the model finished' => [['choices' => [['index' => 0, 'finish_reason' => 'tool_calls']]]];
        yield 'choices that are not a list' => [['choices' => 'length']];
        yield 'a choice that is not an object' => [['choices' => ['length']]];
        yield 'a responses answer incomplete for another reason' => [['status' => 'incomplete', 'incomplete_details' => ['reason' => 'unknown']]];
        yield 'incomplete details that are not an object' => [['status' => 'incomplete', 'incomplete_details' => 'max_output_tokens']];
    }

    public function test_a_gateway_refusing_the_request_with_http_413_refuses_it_as_too_large_whatever_body_it_sent(): void
    {
        $runtimeException = new RuntimeException('Syntax error for "https://gw.example.com/v1/chat/completions".');
        $payloadTooLarge = self::createStub(ResponseInterface::class);
        $payloadTooLarge->method('getStatusCode')->willReturn(413);
        $deferredResult = new DeferredResult(new FailingResultConverter($runtimeException), new RawHttpResult($payloadTooLarge));
        $this->expectConversionToFailWith($runtimeException, $deferredResult);

        $throwable = (new ConversionFailureExplainer())->explain($runtimeException, $deferredResult);

        self::assertInstanceOf(UnconvertedAnswerException::class, $throwable);
        self::assertTrue($throwable->refusedAsTooLarge);
        self::assertSame('The provider refused the request as too large (HTTP 413): Syntax error for "https://gw.example.com/v1/chat/completions".', $throwable->getMessage());
    }

    public function test_a_status_other_than_413_refuses_nothing(): void
    {
        $badRequestException = new BadRequestException('Bad Request');
        $badRequest = self::createStub(ResponseInterface::class);
        $badRequest->method('getStatusCode')->willReturn(400);
        $deferredResult = new DeferredResult(new FailingResultConverter($badRequestException), new RawHttpResult($badRequest));
        $this->expectConversionToFailWith($badRequestException, $deferredResult);

        self::assertSame($badRequestException, (new ConversionFailureExplainer())->explain($badRequestException, $deferredResult));
    }

    public function test_a_raw_answer_that_cannot_be_read_leaves_the_failure_as_it_is(): void
    {
        $badRequestException = new BadRequestException('Bad Request');
        $deferredResult = new DeferredResult(new FailingResultConverter($badRequestException), new RawHttpResult(new UnreadableResponse()));
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
