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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\SecretScrubberConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserControllerAccessControlParser;

final class ScrubbedControllerTest extends TestCase
{
    private RegexSecretScrubber $regexSecretScrubber;

    private PhpParserControllerAccessControlParser $phpParserControllerAccessControlParser;

    /**
     * @throws SecretScrubberConfigurationException
     */
    #[Override]
    protected function setUp(): void
    {
        $this->regexSecretScrubber = new RegexSecretScrubber();
        $this->phpParserControllerAccessControlParser = new PhpParserControllerAccessControlParser();
    }

    /**
     * @throws InvalidProjectFileException
     */
    #[DataProvider('statementsNamingACredentialCases')]
    public function test_a_controller_keeps_its_routes_and_guards_once_scrubbed(string $statement): void
    {
        $source = <<<PHP
            <?php
            namespace App\\Controller;
            use Symfony\\Component\\Routing\\Attribute\\Route;
            use Symfony\\Component\\Security\\Http\\Attribute\\IsGranted;
            #[IsGranted('ROLE_ADMIN')]
            final class ExportController {
                {$statement}

                #[Route('/admin/export')]
                public function export(): void {}
            }
            PHP;
        $unscrubbed = $this->phpParserControllerAccessControlParser->parse(ProjectFile::create('src/Controller/ExportController.php', '/app/src/Controller/ExportController.php', $source));

        $scrubbed = $this->phpParserControllerAccessControlParser->parse(ProjectFile::create('src/Controller/ExportController.php', '/app/src/Controller/ExportController.php', $this->regexSecretScrubber->scrub($source)));

        self::assertNotEmpty($unscrubbed);
        self::assertEquals($unscrubbed, $scrubbed);
    }

    /** @return iterable<string, array{0: string}> */
    public static function statementsNamingACredentialCases(): iterable
    {
        yield 'a credential parameter defaulted to null before a typed one' => ['public function __construct(private ?string $apiKey = null, private \\Psr\\Log\\LoggerInterface $logger) {}'];
        yield 'a late static class name' => ['private function name(): string { $secret = static::class; return $secret; }'];
        yield 'a static property read with an offset' => ['private function cached(string $id): ?string { $token = self::$cache[$id] ?? null; return $token; }'];
        yield 'a call followed by an operator' => ["private function expiry(): array { return ['access_token_expires_at' => time() + 3600]; }"];
        yield 'a constant' => ['private function password(): string { $password = DEFAULT_PASSWORD; return $password; }'];
        yield 'a string closed right after the key' => ["private function redact(string \$enc, string \$content): string { return str_replace('_password='.\$enc, '_password=******', \$content); }"];
    }
}
