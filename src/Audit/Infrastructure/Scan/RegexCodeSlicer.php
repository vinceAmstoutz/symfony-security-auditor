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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Lightweight line classifier that retains only the security-relevant lines of
 * a PHP file and replaces every other line with a `// elided` placeholder. A
 * line is kept when it is either:
 *
 *   - structural — a `<?php` tag, `namespace`/`use` declaration, PHP attribute,
 *     class/interface/trait/enum signature (with optional modifiers), method
 *     signature, or property/visibility-prefixed declaration; or
 *   - dangerous — it contains at least one security-relevant token (Request::
 *     access, Doctrine query builder, unserialize, shell exec, mailer setters,
 *     HttpClient request, weak crypto, …).
 *
 * Because elided lines are replaced one-for-one (never removed), the file's
 * total line count is preserved and the attacker prompt's `line_start` /
 * `line_end` numbering protocol stays accurate against the original source.
 *
 * Non-PHP files (Twig, YAML, XML) pass through unchanged — they are already
 * small enough that slicing would only cost context. PHP files shorter than
 * `minLinesBeforeSlicing` also pass through: slicing a short service has no
 * token-saving upside.
 */
final readonly class RegexCodeSlicer implements CodeSlicerInterface
{
    public const int DEFAULT_MIN_LINES_BEFORE_SLICING = 80;

    private const string ELIDED_PLACEHOLDER = '// elided';

    /**
     * Prefixes (matched after left-trim) that mark a line as structurally
     * relevant and therefore always retained.
     *
     * @var list<string>
     */
    private const array STRUCTURAL_PREFIXES = [
        '<?php',
        'namespace ',
        'use ',
        '#[',
        'class ',
        'interface ',
        'trait ',
        'enum ',
        'final ',
        'abstract ',
        'readonly ',
        'public ',
        'protected ',
        'private ',
    ];

    /**
     * @var list<string>
     */
    private const array SECURITY_TOKENS = [
        '$request->',
        '$this->getUser(',
        '->denyAccessUnlessGranted(',
        '#[IsGranted',
        '#[MapRequestPayload',
        '#[MapQueryString',
        '->isGranted(',
        '->getRoles(',
        '->createQuery(',
        '->createQueryBuilder(',
        '->executeQuery(',
        '->executeStatement(',
        '->setParameter(',
        'getConnection()',
        '->orderBy(',
        'unserialize(',
        'igbinary_unserialize(',
        'shell_exec(',
        'passthru(',
        'proc_open(',
        'system(',
        'popen(',
        'eval(',
        ' exec(',
        '(exec(',
        '=exec(',
        'new Process(',
        'HttpClient',
        '->request(',
        '->redirect(',
        'RedirectResponse',
        '->submit(',
        'allow_extra_fields',
        '|raw',
        '->getContent(',
        'random_int(',
        'mt_rand(',
        ' rand(',
        '(rand(',
        '=rand(',
        'md5(',
        'sha1(',
        'hash_equals(',
        '$_GET',
        '$_POST',
        '$_REQUEST',
        '$_COOKIE',
        '$_SERVER',
        '->from(',
        '->subject(',
        '->addBcc(',
        '->to(',
        'MailerInterface',
        'CacheInterface',
        'LockFactory',
        '->createLock(',
        'RateLimiterFactory',
        '->loadByIdentifier(',
        'AccessTokenHandler',
        'SelfValidatingPassport',
        'hash_hmac(',
        'evaluate(',
        'simplexml_load_string(',
        '->writeln(',
        'json_decode(',
        'getSession()',
        ' include(',
        '(include(',
        '=include(',
    ];

    public function __construct(
        private int $minLinesBeforeSlicing = self::DEFAULT_MIN_LINES_BEFORE_SLICING,
    ) {}

    public function slice(ProjectFile $projectFile): string
    {
        if (!$this->shouldSlice($projectFile)) {
            return $projectFile->content();
        }

        $output = [];
        foreach (explode("\n", $projectFile->content()) as $line) {
            $output[] = $this->shouldRetain($line) ? $line : self::ELIDED_PLACEHOLDER;
        }

        return implode("\n", $output);
    }

    private function shouldSlice(ProjectFile $projectFile): bool
    {
        if ('php' !== pathinfo($projectFile->relativePath(), \PATHINFO_EXTENSION)) {
            return false;
        }

        return $projectFile->linesCount() >= $this->minLinesBeforeSlicing;
    }

    private function shouldRetain(string $line): bool
    {
        return $this->isStructural($line) || $this->containsSecurityToken($line);
    }

    private function isStructural(string $line): bool
    {
        $trimmed = ltrim($line);

        foreach (self::STRUCTURAL_PREFIXES as $prefix) {
            if (str_starts_with($trimmed, $prefix)) {
                return true;
            }
        }

        return false;
    }

    private function containsSecurityToken(string $line): bool
    {
        foreach (self::SECURITY_TOKENS as $token) {
            if (str_contains($line, $token)) {
                return true;
            }
        }

        return false;
    }
}
