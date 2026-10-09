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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Exception;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\ProviderMessageRedactor;

final class ProviderMessageRedactorTest extends TestCase
{
    #[DataProvider('queryParameterNamedAsACredentialCases')]
    public function test_it_redacts_a_credential_query_parameter_in_either_position(string $name): void
    {
        self::assertSame(
            \sprintf('Idle timeout for "https://host/v1/m:generate?%s=***REDACTED***".', $name),
            ProviderMessageRedactor::redact(\sprintf('Idle timeout for "https://host/v1/m:generate?%s=AIzaSECRET".', $name)),
        );
        self::assertSame(
            \sprintf('Idle timeout for "https://host/v1/m:generate?alt=sse&%s=***REDACTED***".', $name),
            ProviderMessageRedactor::redact(\sprintf('Idle timeout for "https://host/v1/m:generate?alt=sse&%s=AIzaSECRET".', $name)),
        );
    }

    /** @return iterable<string, array{0: string}> */
    public static function queryParameterNamedAsACredentialCases(): iterable
    {
        yield 'key' => ['key'];
        yield 'api_key' => ['api_key'];
        yield 'apikey' => ['apikey'];
        yield 'access_token' => ['access_token'];
        yield 'token' => ['token'];
    }

    public function test_it_keeps_the_spelling_of_the_parameter_name_it_redacts(): void
    {
        self::assertSame('GET /v1?Key=***REDACTED***&API_KEY=***REDACTED***', ProviderMessageRedactor::redact('GET /v1?Key=AIzaSECRET&API_KEY=sk-SECRET'));
    }

    public function test_it_redacts_every_credential_of_a_message(): void
    {
        self::assertSame(
            'first https://a/b?key=***REDACTED*** then https://c/d?alt=sse&token=***REDACTED***',
            ProviderMessageRedactor::redact('first https://a/b?key=ONE then https://c/d?alt=sse&token=TWO'),
        );
    }

    public function test_it_leaves_the_parameters_that_follow_the_credential(): void
    {
        self::assertSame('https://host/v1?key=***REDACTED***&alt=sse&n=1', ProviderMessageRedactor::redact('https://host/v1?key=AIzaSECRET&alt=sse&n=1'));
    }

    public function test_a_message_already_redacted_is_returned_as_it_is(): void
    {
        $redacted = ProviderMessageRedactor::redact('Idle timeout for "https://host/v1/m:generate?alt=sse&key=AIzaSECRET".');

        self::assertSame('Idle timeout for "https://host/v1/m:generate?alt=sse&key=***REDACTED***".', ProviderMessageRedactor::redact($redacted));
    }

    #[DataProvider('charactersEndingAValueCases')]
    public function test_it_ends_the_value_at_the_character_that_closes_a_url_in_a_message(string $closing): void
    {
        self::assertSame(
            \sprintf('see https://host/v1?key=***REDACTED***%sand more', $closing),
            ProviderMessageRedactor::redact(\sprintf('see https://host/v1?key=AIzaSECRET%sand more', $closing)),
        );
    }

    /** @return iterable<string, array{0: string}> */
    public static function charactersEndingAValueCases(): iterable
    {
        yield 'ampersand' => ['&'];
        yield 'hash' => ['#'];
        yield 'space' => [' '];
        yield 'newline' => ["\n"];
        yield 'tab' => ["\t"];
        yield 'double quote' => ['"'];
        yield 'single quote' => ["'"];
        yield 'less than' => ['<'];
        yield 'greater than' => ['>'];
        yield 'closing parenthesis' => [')'];
        yield 'closing bracket' => [']'];
    }

    #[DataProvider('messagesWithoutACredentialCases')]
    public function test_it_leaves_a_message_without_a_credential_as_it_is(string $message): void
    {
        self::assertSame($message, ProviderMessageRedactor::redact($message));
    }

    /** @return iterable<string, array{0: string}> */
    public static function messagesWithoutACredentialCases(): iterable
    {
        yield 'a plain failure' => ['HTTP 503 first failure message'];
        yield 'an empty message' => [''];
        yield 'a url without a query' => ['Idle timeout reached for "https://host/v1/m:generate".'];
        yield 'a query without a credential' => ['returned for "https://host/v1/m:generate?alt=sse&max_tokens=100".'];
        yield 'a parameter that only ends like a credential name' => ['https://host/v1?monkey=1&next_page_token=abc&x-api_key=def'];
        yield 'a credential name that is not in a query' => ['The key=abc setting and token=def are not query parameters'];
        yield 'a credential name without a value' => ['https://host/v1?key=&token=#frag'];
        yield 'the word key' => ['Incorrect API key provided: sk-abc***xyz'];
    }

    #[RunInSeparateProcess]
    public function test_a_message_it_could_not_evaluate_is_withheld_rather_than_returned_as_it_was(): void
    {
        ini_set('pcre.jit', '0');

        $redacted = $this->underATightBacktrackLimit(static fn (): string => ProviderMessageRedactor::redact('Idle timeout for "https://host/v1/m:generate?key=AIzaSECRET".'));

        self::assertSame('[provider message withheld: it could not be checked for credentials]', $redacted);
    }

    /**
     * @param callable(): string $redact
     */
    private function underATightBacktrackLimit(callable $redact): string
    {
        $previousLimit = \ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', '1');

        try {
            return $redact();
        } finally {
            ini_set('pcre.backtrack_limit', false === $previousLimit ? '1000000' : $previousLimit);
        }
    }
}
