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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\FileSystem;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\NonSecretValue;

final class NonSecretValueTest extends TestCase
{
    #[DataProvider('valuesCases')]
    public function test_it_tells_a_value_that_names_a_thing_from_one_that_may_be_a_secret(string $prefix, string $value, bool $holdsNoSecret): void
    {
        self::assertSame($holdsNoSecret, (new NonSecretValue())->holdsNoSecret($prefix, $value));
    }

    /** @return iterable<string, array{0: string, 1: string, 2: bool}> */
    public static function valuesCases(): iterable
    {
        yield 'a namespaced class' => ['password: ', 'App\\Entity\\User', true];
        yield 'a namespaced class from the root' => ['password: ', '\\App\\Entity\\User', true];
        yield 'a class constant' => ['password: ', 'App\\Entity\\User::class', true];
        yield 'a class with doubled separators' => ['password: ', 'App\\\\Entity\\\\User', true];
        yield 'a name of one segment' => ['password: ', 'AppEntityUser', false];
        yield 'a name with a segment starting with a digit' => ['password: ', 'App\\1Entity', false];
        yield 'a name with a tripled separator' => ['password: ', 'App\\\\\\Entity', false];
        yield 'a parameter inside a path' => ['secret_key: ', '%kernel.project_dir%/config/jwt/private.pem', true];
        yield 'an environment variable inside a path' => ['secret_key: ', '%env(JWT_DIR)%/private.pem', true];
        yield 'an environment variable with a processor' => ['secret_key: ', '%env(resolve:JWT_DIR)%/private.pem', true];
        yield 'a parameter with dashes' => ['secret_key: ', 'x%app.my-secret%y', true];
        yield 'a parameter with an upper-case name' => ['secret_key: ', 'x%App.Secret%y', true];
        yield 'a percent pair without a dot' => ['secret_key: ', 'Pa%ss%word', false];
        yield 'a parameter with a trailing dot' => ['secret_key: ', 'Pa%ss.%word', false];
        yield 'an absolute path' => ['private_key: ', '/var/oauth/private.key', true];
        yield 'an absolute path with a trailing slash' => ['private_key: ', '/var/oauth/', true];
        yield 'a relative path' => ['private_key: ', './config/private.key', true];
        yield 'a parent path' => ['private_key: ', '../config/private.key', true];
        yield 'a home path' => ['private_key: ', '~/keys/private.key', true];
        yield 'a path of one segment' => ['private_key: ', '/private.key', false];
        yield 'a path with a space' => ['private_key: ', '/var/my key', false];
        yield 'a path with a deeper parent' => ['private_key: ', '.../config/private.key', false];
        yield 'a url under a url key' => ['access_token_url: ', 'https://github.com/login/oauth/access_token', true];
        yield 'a plain http url' => ['access_token_url: ', 'http://localhost:8080', true];
        yield 'an upper-case url' => ['access_token_url: ', 'HTTPS://GITHUB.COM/token', true];
        yield 'a url under a uri key' => ['access_token_uri: ', 'https://github.com/token', true];
        yield 'a url under an endpoint key' => ['access_token_endpoint: ', 'https://github.com/token', true];
        yield 'a url under a dashed url key' => ['access-token-url: ', 'https://github.com/token', true];
        yield 'a url under a quoted url key' => ["'access_token_url' => ", 'https://github.com/token', true];
        yield 'a url under an offset url key' => ["\$cfg['access_token_url'] = ", 'https://github.com/token', true];
        yield 'a url under an equals url key' => ['access_token_url = ', 'https://github.com/token', true];
        yield 'a url under a key that is no url key' => ['access_token: ', 'https://github.com/token', false];
        yield 'a url under a key merely containing url' => ['access_token_urlsafe: ', 'https://github.com/token', false];
        yield 'a url with a user part' => ['access_token_url: ', 'https://user@github.com/token', false];
        yield 'a url with a query' => ['access_token_url: ', 'https://github.com/token?a=b', false];
        yield 'a url with a fragment' => ['access_token_url: ', 'https://github.com/token#a', false];
        yield 'a url with a space' => ['access_token_url: ', 'https://github.com/to ken', false];
        yield 'a url on another scheme' => ['access_token_url: ', 'ftp://github.com/token', false];
        yield 'a word under a url key' => ['access_token_url: ', 'abcdefgh', false];
        yield 'a number under a validity key' => ['reset_password_code_validity: ', '14400', true];
        yield 'a number under a ttl key' => ['access_token_ttl: ', '3600', true];
        yield 'a number under a lifetime key' => ['access_token_lifetime: ', '3600', true];
        yield 'a number under an expiry key' => ['access_token_expiry: ', '3600', true];
        yield 'a number under an expires key' => ['access_token_expires: ', '3600', true];
        yield 'a number under an expiration key' => ['access_token_expiration: ', '3600', true];
        yield 'a number under a timeout key' => ['access_token_timeout: ', '3600', true];
        yield 'a number under a length key' => ['secret_length: ', '3600', true];
        yield 'a number under a size key' => ['secret_size: ', '3600', true];
        yield 'a number under a bits key' => ['private_key_bits: ', '3600', true];
        yield 'a number under a count key' => ['secret_count: ', '3600', true];
        yield 'a number under an age key' => ['secret_age: ', '3600', true];
        yield 'a number under an interval key' => ['secret_interval: ', '3600', true];
        yield 'a number under a duration key' => ['secret_duration: ', '3600', true];
        yield 'a number under a quoted duration key' => ["'access_token_ttl' => ", '3600', true];
        yield 'a number under a duration key set with an equals sign' => ['access_token_ttl = ', '3600', true];
        yield 'a number under a key that is no duration key' => ['password: ', '12345678', false];
        yield 'a number under a key merely containing a duration word' => ['password_agent: ', '12345678', false];
        yield 'a number followed by a letter under a duration key' => ['access_token_ttl: ', '3600a', false];
        yield 'a decimal under a duration key' => ['access_token_ttl: ', '36.5', false];
        yield 'a word under a duration key' => ['access_token_ttl: ', 'abcdefgh', false];
        yield 'a signed number under a duration key' => ['access_token_ttl: ', '-3600', false];
        yield 'a word that may be a secret' => ['password: ', 'hunter2hunter2', false];
    }
}
