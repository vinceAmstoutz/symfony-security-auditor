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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;

use function Symfony\Component\String\u;

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
 * A retained line with an unclosed `(` (a multi-line method signature or
 * attribute argument list) keeps every continuation line until its
 * parentheses close, even if a continuation line matches neither rule on its
 * own — otherwise parameter types/names would be silently dropped mid-signature.
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
    ];

    /**
     * Bare-keyword security tokens that must be word-boundary matched rather
     * than substring matched: a leading-character enumeration (space, `(`,
     * `=`) misses column-0 statements (e.g. a bootstrap script's first line)
     * and tab-indented ones — silently eliding a real file-inclusion or
     * command-execution line instead of retaining it.
     */
    private const string BARE_KEYWORD_PATTERN = '/\b(?:exec|rand|include|include_once|require|require_once)\b/';

    /**
     * Matches single- or double-quoted string literals (with basic
     * backslash-escape handling) so their contents can be stripped before
     * counting parentheses — a default value like `'Confirm)'` must not be
     * mistaken for a real closing paren that ends a multi-line signature.
     */
    private const string STRING_LITERAL_PATTERN = '/\'(?:\\\\.|[^\'\\\\])*\'|"(?:\\\\.|[^"\\\\])*"/';

    public function __construct(
        private int $minLinesBeforeSlicing = self::DEFAULT_MIN_LINES_BEFORE_SLICING,
    ) {}

    #[Override]
    public function slice(ProjectFile $projectFile): string
    {
        if (!$this->shouldSlice($projectFile)) {
            return $projectFile->content();
        }

        $output = [];
        $openParenDepth = 0;
        foreach (explode("\n", $projectFile->content()) as $line) {
            $retain = $openParenDepth > 0 || $this->shouldRetain($line);
            $output[] = $retain ? $line : self::ELIDED_PLACEHOLDER;

            if ($retain) {
                $openParenDepth = max(0, $openParenDepth + $this->parenDelta($line));
            }
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
        if ($this->isStructural($line)) {
            return true;
        }

        return $this->containsSecurityToken($line);
    }

    private function isStructural(string $line): bool
    {
        return u($line)->trimStart()->startsWith(self::STRUCTURAL_PREFIXES);
    }

    private function containsSecurityToken(string $line): bool
    {
        if (u($line)->containsAny(self::SECURITY_TOKENS)) {
            return true;
        }

        return 1 === preg_match(self::BARE_KEYWORD_PATTERN, $line);
    }

    private function parenDelta(string $line): int
    {
        $withoutStringLiterals = preg_replace(self::STRING_LITERAL_PATTERN, '', $line) ?? $line;

        return substr_count($withoutStringLiterals, '(') - substr_count($withoutStringLiterals, ')');
    }
}
