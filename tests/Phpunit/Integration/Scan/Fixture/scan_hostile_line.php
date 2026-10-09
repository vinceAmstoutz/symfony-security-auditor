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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\BlockCommentStripper;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\RegexStaticPreScanner;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\StringLiteralMasker;

require dirname(__DIR__, 5).'/vendor/autoload.php';

/**
 * Scans one hostile file in a process of its own, so the PCRE JIT setting the
 * test passes with `-d pcre.jit=0` is in force before any pattern is compiled
 * and cached, and prints what came out.
 */
$case = $argv[1] ?? '';

$preScan = static function (string $path, string $content): array {
    $markers = (new RegexStaticPreScanner())->scan([ProjectFile::create($path, '/app/'.$path, $content)]);

    return array_map(static fn (RiskMarker $riskMarker): string => sprintf('%s@%d', $riskMarker->pattern(), $riskMarker->line()), $markers);
};

$result = match ($case) {
    'dynamic_file_inclusion' => $preScan('src/Service/Loader.php', "<?php\n".str_repeat('include ', 12000).";\$x\ninclude \$file;\n"),
    'live_prop_writable' => $preScan('src/Twig/Components/Counter.php', "<?php\n#[AsLiveComponent]\n".str_repeat('#[LiveProp(', 12000)."\n#[LiveProp(writable: true)]\n"),
    'supports_returns_null' => $preScan('src/Security/FooAuthenticator.php', "<?php\nclass FooAuthenticator implements AuthenticatorInterface\n".str_repeat('public function supports(', 20000).') : bool { x'.str_repeat(' ', 600)."\npublic function supports(Request \$request): bool { return null; }\n"),
    'trusted_proxies_wildcard' => $preScan('config/packages/framework.yaml', str_repeat('trusted_proxies: ', 6000)."0.0.0.0/\ntrusted_proxies: ['0.0.0.0/0']\n"),
    'hsts_disabled' => $preScan('config/packages/nelmio_security.yaml', str_repeat('forced_ssl: ', 12000)."enabled: \nforced_ssl: { enabled: false }\n"),
    'ldap_search' => $preScan('src/Ldap/Directory.php', "<?php\n".str_repeat('ldap_search(', 12000).".x\$\nldap_search(\$link, \$base, 'uid='.\$name);\n"),
    'string_literal' => (static function (): array {
        $masked = (new StringLiteralMasker())->mask("'".str_repeat("a\\'", 12000).' "abc"');

        return [substr($masked, -5), strlen($masked)];
    })(),
    'block_comment' => (new BlockCommentStripper())->strip(str_repeat('/**/', 64000).'code', false),
    'block_comment_after_escaped_quote' => (new BlockCommentStripper())->strip(str_repeat("/**/\\'", 30000).'code', false),
    default => throw new InvalidArgumentException(sprintf('Unknown hostile line "%s".', $case)),
};

echo json_encode($result, \JSON_THROW_ON_ERROR);
