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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Scenario;

use VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Platform\CompatPlatform;

/**
 * The audited projects the scenarios share. A `FINDING {json}` comment in a
 * file is a finding the scripted model reports on it; a title holding REJECT,
 * DOWNGRADE or UPGRADE is a verdict the scripted reviewer gives.
 */
final readonly class ProjectFixtures
{
    private const int HUGE_FILE_LINES = 1500;

    /**
     * @param array<string, bool|float|int|string> $fields
     */
    public static function finding(array $fields): string
    {
        return \sprintf('FINDING %s', (string) json_encode($fields, \JSON_UNESCAPED_SLASHES));
    }

    /**
     * @param list<string> $comments
     */
    public static function controller(string $class, array $comments = []): string
    {
        $lines = array_map(static fn (string $comment): string => \sprintf('        // %s', $comment), $comments);

        return \sprintf("<?php\nnamespace App\\Controller;\nclass %s\n{\n    public function index()\n    {\n%s\n        return null;\n    }\n}\n", $class, implode("\n", $lines));
    }

    /**
     * Four controllers whose findings the reviewer confirms, rejects and
     * downgrades, one below the confidence floor, a clean service, the
     * security configuration, a template, and a git-ignored cache file.
     *
     * @return array<string, string>
     */
    public static function base(): array
    {
        return [
            'src/Controller/AdminController.php' => self::controller('AdminController', [self::finding(['type' => 'broken_access_control', 'severity' => 'critical', 'title' => 'Unprotected admin', 'confidence' => 0.95, 'line_start' => 7, 'line_end' => 8])]),
            'src/Controller/ApiController.php' => self::controller('ApiController', [
                self::finding(['type' => 'sql_injection', 'severity' => 'high', 'title' => 'SQLi in api', 'confidence' => 0.9, 'line_start' => 7]),
                self::finding(['type' => 'ssrf', 'severity' => 'medium', 'title' => 'REJECT me', 'confidence' => 0.8]),
            ]),
            'src/Controller/UserController.php' => self::controller('UserController', [self::finding(['type' => 'insecure_direct_object_reference', 'severity' => 'medium', 'title' => 'DOWNGRADE idor', 'confidence' => 0.6])]),
            'src/Controller/LowConfController.php' => self::controller('LowConfController', [self::finding(['type' => 'missing_csrf_protection', 'severity' => 'high', 'title' => 'low conf', 'confidence' => 0.59])]),
            'src/Service/Clean.php' => "<?php\nnamespace App\\Service;\nclass Clean { }\n",
            'config/packages/security.yaml' => "security:\n  firewalls:\n    main:\n      pattern: ^/\n  access_control:\n    - { path: ^/admin, roles: ROLE_ADMIN }\n",
            'templates/base.html.twig' => '<html>{{ x|raw }}</html>',
            'composer.json' => '{"name":"a/b","require":{"php":">=8.2"}}',
            '.gitignore' => "var/\n",
            'var/cache/x.php' => '<?php // ignored',
        ];
    }

    /**
     * One controller with one confirmed critical finding.
     *
     * @return array<string, string>
     */
    public static function single(): array
    {
        return [
            'src/Controller/AdminController.php' => self::controller('AdminController', [self::finding(['type' => 'broken_access_control', 'severity' => 'critical', 'title' => 'Unprotected admin', 'confidence' => 0.95, 'line_start' => 7, 'line_end' => 8])]),
            'src/Service/Clean.php' => "<?php\nnamespace App\\Service;\nclass Clean { }\n",
        ];
    }

    /**
     * The clean project and a controller no request holding it fits the
     * model, so the audit leaves that file unanalyzed and the run incomplete
     * with no finding to trip another gate. The controller is large enough
     * that the auditor blames it, not its own prompt, and goes on.
     *
     * @return array<string, string>
     */
    public static function incomplete(): array
    {
        return [
            ...self::clean(),
            'src/Controller/HugeController.php' => \sprintf("<?php\nnamespace App\\Controller;\n// %s\nclass HugeController\n{\n%s}\n", CompatPlatform::TOO_LONG_MARKER, str_repeat("    public const LABEL = 'a label long enough to make this file weigh in the prompt';\n", self::HUGE_FILE_LINES)),
        ];
    }

    /**
     * @return array<string, string>
     */
    public static function clean(): array
    {
        return [
            'src/Service/Clean.php' => "<?php\nnamespace App\\Service;\nclass Clean { }\n",
            'src/Controller/HomeController.php' => self::controller('HomeController'),
        ];
    }
}
