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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\FileSystem;

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\SecretScrubberConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyYamlSecurityConfigParser;

final class ScrubbedSecurityConfigTest extends TestCase
{
    private RegexSecretScrubber $regexSecretScrubber;

    private SymfonyYamlSecurityConfigParser $symfonyYamlSecurityConfigParser;

    /**
     * @throws SecretScrubberConfigurationException
     */
    #[Override]
    protected function setUp(): void
    {
        $this->regexSecretScrubber = new RegexSecretScrubber();
        $this->symfonyYamlSecurityConfigParser = new SymfonyYamlSecurityConfigParser();
    }

    #[DataProvider('securityConfigsHoldingACredentialCases')]
    public function test_a_security_config_holding_a_credential_keeps_its_access_control_once_scrubbed(string $config, string $credential): void
    {
        $scrubbed = $this->regexSecretScrubber->scrub($config);

        self::assertStringNotContainsString($credential, $scrubbed);
        self::assertSame(['^/admin' => ['ROLE_ADMIN']], $this->symfonyYamlSecurityConfigParser->parseAccessControl($scrubbed));
        self::assertSame(['^/_profiler (security: false)', 'main'], $this->symfonyYamlSecurityConfigParser->parseFirewallRules($scrubbed));
    }

    /** @return iterable<string, array{0: string, 1: string}> */
    public static function securityConfigsHoldingACredentialCases(): iterable
    {
        yield 'an unquoted ldap password' => [
            "security:\n    firewalls:\n        dev:\n            pattern: ^/_profiler\n            security: false\n        main:\n            form_login_ldap:\n                search_password: s3cretValue99\n    access_control:\n        - { path: ^/admin, roles: ROLE_ADMIN }\n",
            's3cretValue99',
        ];
        yield 'an in-memory user in a flow mapping' => [
            "security:\n    providers:\n        memory:\n            memory:\n                users:\n                    admin: { password: hunter2supersecure, roles: [ROLE_ADMIN] }\n    firewalls:\n        dev:\n            pattern: ^/_profiler\n            security: false\n        main:\n            lazy: true\n    access_control:\n        - { path: ^/admin, roles: ROLE_ADMIN }\n",
            'hunter2supersecure',
        ];
        yield 'an ldap password ending in a semicolon' => [
            "security:\n    firewalls:\n        dev:\n            pattern: ^/_profiler\n            security: false\n        main:\n            form_login_ldap:\n                search_password: s3cretValue99;\n    access_control:\n        - { path: ^/admin, roles: ROLE_ADMIN }\n",
            's3cretValue99',
        ];
        yield 'a null password and a false flag next to a real secret' => [
            "security:\n    firewalls:\n        dev:\n            pattern: ^/_profiler\n            security: false\n        main:\n            remember_me:\n                secret: null\n                persist-credentials: false\n                signature_properties: [password]\n    access_control:\n        - { path: ^/admin, roles: ROLE_ADMIN }\nparameters:\n    app_secret: xk9LmN3pQ7rS5tU8\n",
            'xk9LmN3pQ7rS5tU8',
        ];
    }
}
