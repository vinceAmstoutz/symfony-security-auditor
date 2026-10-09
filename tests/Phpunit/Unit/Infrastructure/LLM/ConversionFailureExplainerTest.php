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
        self::assertFalse($throwable->refusedWithClientError);
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
        self::assertFalse($throwable->refusedWithClientError);
        self::assertSame('The provider refused the request as too large (HTTP 413): Syntax error for "https://gw.example.com/v1/chat/completions".', $throwable->getMessage());
    }

    #[DataProvider('clientErrorStatusesTheGatewayRefusedWithCases')]
    public function test_a_gateway_answering_a_client_error_refuses_the_request_whatever_body_it_sent(int $status): void
    {
        $runtimeException = new RuntimeException('Response does not contain choices.');
        $deferredResult = $this->failedConversionWithStatus($runtimeException, $status, ['detail' => 'Not Found']);

        $throwable = (new ConversionFailureExplainer())->explain($runtimeException, $deferredResult);

        self::assertInstanceOf(UnconvertedAnswerException::class, $throwable);
        self::assertNull($throwable->stopReason);
        self::assertFalse($throwable->refusedAsTooLarge);
        self::assertTrue($throwable->refusedWithClientError);
        self::assertSame(\sprintf('The provider refused the request (HTTP %d): Response does not contain choices.', $status), $throwable->getMessage());
        self::assertSame($runtimeException, $throwable->getPrevious());
    }

    /** @return iterable<string, array{int}> */
    public static function clientErrorStatusesTheGatewayRefusedWithCases(): iterable
    {
        yield 'the first client error' => [400];
        yield 'unauthorized' => [401];
        yield 'forbidden' => [403];
        yield 'not found' => [404];
        yield 'unprocessable' => [422];
        yield 'the last client error' => [499];
    }

    #[DataProvider('statusesThatRefuseNothingCases')]
    public function test_a_status_that_is_not_a_refusal_leaves_the_failure_as_it_is(int $status): void
    {
        $runtimeException = new RuntimeException('Response does not contain choices.');
        $deferredResult = $this->failedConversionWithStatus($runtimeException, $status, ['detail' => 'Not Found']);

        self::assertSame($runtimeException, (new ConversionFailureExplainer())->explain($runtimeException, $deferredResult));
    }

    /** @return iterable<string, array{int}> */
    public static function statusesThatRefuseNothingCases(): iterable
    {
        yield 'below the client errors' => [399];
        yield 'a request timeout, which is retried' => [408];
        yield 'a request that came too early, which is retried' => [425];
        yield 'a rate limit, which is retried' => [429];
        yield 'above the client errors' => [500];
    }

    public function test_a_content_filter_the_raw_answer_names_wins_over_the_status_it_came_with(): void
    {
        $badRequestException = new BadRequestException(self::AZURE_FILTERED);
        $deferredResult = $this->failedConversionWithStatus($badRequestException, 400, $this->azureContentFilterBody());

        $throwable = (new ConversionFailureExplainer())->explain($badRequestException, $deferredResult);

        self::assertInstanceOf(UnconvertedAnswerException::class, $throwable);
        self::assertSame('content-filter', $throwable->stopReason);
        self::assertSame(self::AZURE_FILTERED, $throwable->getMessage());
    }

    public function test_a_refusal_as_too_large_does_not_repeat_a_credential_the_failure_quoted(): void
    {
        $runtimeException = new RuntimeException('Syntax error for "https://gw.example.com/v1/chat?key=AIzaSECRET".');
        $payloadTooLarge = self::createStub(ResponseInterface::class);
        $payloadTooLarge->method('getStatusCode')->willReturn(413);
        $deferredResult = new DeferredResult(new FailingResultConverter($runtimeException), new RawHttpResult($payloadTooLarge));
        $this->expectConversionToFailWith($runtimeException, $deferredResult);

        $throwable = (new ConversionFailureExplainer())->explain($runtimeException, $deferredResult);

        self::assertSame('The provider refused the request as too large (HTTP 413): Syntax error for "https://gw.example.com/v1/chat?key=***REDACTED***".', $throwable->getMessage());
        self::assertSame($runtimeException, $throwable->getPrevious());
        self::assertSame('Syntax error for "https://gw.example.com/v1/chat?key=AIzaSECRET".', $runtimeException->getMessage());
    }

    public function test_a_refusal_with_a_client_error_does_not_repeat_a_credential_the_failure_quoted(): void
    {
        $runtimeException = new RuntimeException('Response does not contain choices for "https://gw.example.com/v1/chat?alt=sse&api_key=AIzaSECRET".');

        $throwable = (new ConversionFailureExplainer())->explain($runtimeException, $this->failedConversionWithStatus($runtimeException, 403, ['detail' => 'Forbidden']));

        self::assertSame('The provider refused the request (HTTP 403): Response does not contain choices for "https://gw.example.com/v1/chat?alt=sse&api_key=***REDACTED***".', $throwable->getMessage());
    }

    public function test_an_answer_cut_short_does_not_repeat_a_credential_the_failure_quoted(): void
    {
        $badRequestException = new BadRequestException('Filtered for "https://gw.example.com/v1/chat?token=AIzaSECRET".');

        $throwable = (new ConversionFailureExplainer())->explain($badRequestException, $this->failedConversion($badRequestException, $this->azureContentFilterBody()));

        self::assertSame('Filtered for "https://gw.example.com/v1/chat?token=***REDACTED***".', $throwable->getMessage());
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

    /**
     * @param array<string, mixed> $body
     */
    private function failedConversionWithStatus(RuntimeException $runtimeException, int $status, array $body): DeferredResult
    {
        $response = self::createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn($status);
        $response->method('toArray')->willReturn($body);
        $deferredResult = new DeferredResult(new FailingResultConverter($runtimeException), new RawHttpResult($response));
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
