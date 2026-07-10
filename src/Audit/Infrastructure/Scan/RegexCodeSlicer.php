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
 *     access, Doctrine query builder, file I/O and upload handling, unserialize,
 *     shell exec, mailer setters, HttpClient request, weak crypto, …).
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
        'case ',
        'final ',
        'abstract ',
        'readonly ',
        'public ',
        'protected ',
        'private ',
        'static ',
        'function ',
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
        '->where(',
        '->andWhere(',
        '->having(',
        'file_get_contents(',
        'file_put_contents(',
        'fopen(',
        'readfile(',
        'unlink(',
        'move_uploaded_file(',
        '->move(',
        'getClientOriginalName(',
        'unserialize(',
        'igbinary_unserialize(',
        'shell_exec(',
        'passthru(',
        'proc_open(',
        'system(',
        'popen(',
        'eval(',
        'new Process(',
        'Process::fromShellCommandline(',
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
        $openStringDelimiter = null;
        $insideBlockComment = false;
        $openHeredocIdentifier = null;
        foreach (explode("\n", $projectFile->content()) as $line) {
            if (null !== $openHeredocIdentifier) {
                $output[] = $line;
                [$openHeredocIdentifier, $openParenDepth, $openStringDelimiter] = $this->consumeHeredocLine($line, $openHeredocIdentifier, $openParenDepth, $openStringDelimiter);

                continue;
            }

            $blockCommentState = $this->stripBlockComments($line, $insideBlockComment);
            $insideBlockComment = $blockCommentState['inside_block_comment'];

            $heredocIdentifier = $this->heredocIdentifierOpenedBy($blockCommentState['line']);
            $retain = null !== $heredocIdentifier || $openParenDepth > 0 || $this->shouldRetain($line);
            $output[] = $retain ? $line : self::ELIDED_PLACEHOLDER;

            if (null !== $heredocIdentifier) {
                $openHeredocIdentifier = $heredocIdentifier;

                continue;
            }

            [$openParenDepth, $openStringDelimiter] = $this->advanceParenTracking($retain, $blockCommentState['line'], $openParenDepth, $openStringDelimiter);
        }

        return implode("\n", $output);
    }

    /**
     * @return array{0: int, 1: ?string}
     */
    private function advanceParenTracking(bool $retain, string $line, int $openParenDepth, ?string $openStringDelimiter): array
    {
        if (!$retain) {
            return [$openParenDepth, $openStringDelimiter];
        }

        $parenState = $this->parenDelta($line, $openStringDelimiter);

        return [max(0, $openParenDepth + $parenState['delta']), $parenState['open_string_delimiter']];
    }

    /**
     * @return array{0: ?string, 1: int, 2: ?string}
     */
    private function consumeHeredocLine(string $line, string $openHeredocIdentifier, int $openParenDepth, ?string $openStringDelimiter): array
    {
        $trailer = $this->heredocCloseTrailer($line, $openHeredocIdentifier);
        if (null === $trailer) {
            return [$openHeredocIdentifier, $openParenDepth, $openStringDelimiter];
        }

        [$openParenDepth, $openStringDelimiter] = $this->advanceParenTracking(true, $trailer, $openParenDepth, $openStringDelimiter);

        return [null, $openParenDepth, $openStringDelimiter];
    }

    private function heredocIdentifierOpenedBy(string $line): ?string
    {
        if (1 !== preg_match('/<<<\s*[\'"]?([A-Za-z_]\w*)[\'"]?\s*$/', $line, $matches)) {
            return null;
        }

        return $matches[1];
    }

    /**
     * A heredoc/nowdoc body is arbitrary text, not PHP code — treating it as
     * such would misfire the security-token/structural checks on its content
     * (a false negative when the body itself is the vulnerable line, e.g. raw
     * SQL built with a heredoc) and feed unbalanced quotes/parens from prose
     * into {@see self::parenDelta()}, desyncing continuation tracking for the
     * rest of the file. The opener line and every line up to and including
     * the closing identifier are retained verbatim instead. PHP allows the
     * closing identifier to be indented (flexible heredoc syntax, PHP 7.3+)
     * and requires nothing but whitespace before it, so it is matched at the
     * start of the line rather than requiring column 0. Any code trailing
     * the identifier on the same line (e.g. the `);` that closes an
     * enclosing multi-line call, a common Doctrine/DBAL idiom) is real PHP,
     * not heredoc body — it is returned so the caller can still feed it into
     * continuation tracking instead of silently dropping it.
     */
    private function heredocCloseTrailer(string $line, string $identifier): ?string
    {
        if (1 !== preg_match(\sprintf('/^\s*%s\b(.*)$/', preg_quote($identifier, '/')), $line, $matches)) {
            return null;
        }

        return $matches[1];
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

    /**
     * A retained line's `(`/`)` count drives the multi-line-signature
     * continuation in {@see self::slice()}. A string literal that opens on
     * this line but only closes on a later one (a raw newline inside a
     * single- or double-quoted string, legal PHP) is invisible to
     * `STRING_LITERAL_PATTERN`, which only matches a pair on the same line —
     * an unbalanced `(` inside such a literal would otherwise never be
     * stripped, permanently desyncing `openParenDepth` and forcing every
     * remaining line in the file to be retained. The returned
     * `open_string_delimiter` carries the open quote character forward until
     * its match closes on a later line.
     *
     * @return array{delta: int, open_string_delimiter: ?string}
     */
    private function parenDelta(string $line, ?string $openStringDelimiter): array
    {
        if (null !== $openStringDelimiter) {
            $closingQuoteOffset = $this->closingQuoteOffset($line, $openStringDelimiter);
            if (null === $closingQuoteOffset) {
                return ['delta' => 0, 'open_string_delimiter' => $openStringDelimiter];
            }

            $line = substr($line, $closingQuoteOffset + 1);
        }

        $withoutStringLiterals = preg_replace(self::STRING_LITERAL_PATTERN, '', $line) ?? $line;
        $withoutStringLiterals = $this->stripTrailingComment($withoutStringLiterals);

        $danglingQuoteOffset = $this->danglingQuoteOffset($withoutStringLiterals);
        $nextOpenStringDelimiter = null;
        if (null !== $danglingQuoteOffset) {
            $nextOpenStringDelimiter = $withoutStringLiterals[$danglingQuoteOffset];
            $withoutStringLiterals = substr($withoutStringLiterals, 0, $danglingQuoteOffset);
        }

        return [
            'delta' => substr_count($withoutStringLiterals, '(') - substr_count($withoutStringLiterals, ')'),
            'open_string_delimiter' => $nextOpenStringDelimiter,
        ];
    }

    private function closingQuoteOffset(string $line, string $quoteChar): ?int
    {
        $pattern = \sprintf('/^(?:\\\\.|[^%s\\\\])*%s/', $quoteChar, $quoteChar);
        if (1 !== preg_match($pattern, $line, $matches)) {
            return null;
        }

        return \strlen($matches[0]) - 1;
    }

    private function danglingQuoteOffset(string $text): ?int
    {
        if (1 !== preg_match('/[\'"]/', $text, $matches, \PREG_OFFSET_CAPTURE)) {
            return null;
        }

        return $matches[0][1];
    }

    /**
     * An apostrophe inside a `//` line comment (e.g. `// don't remove this`)
     * is indistinguishable from a genuine unterminated string open once
     * {@see self::STRING_LITERAL_PATTERN} has already stripped every complete
     * same-line pair — left unhandled, {@see self::danglingQuoteOffset()}
     * would latch onto it and desync paren tracking for the rest of the file.
     * Truncating unconditionally at the first `//` is still correct for a
     * genuine unterminated string containing `//` (e.g. a URL split across
     * lines, `'http://`): its opening quote sits before the `//` and survives
     * the truncation, so {@see self::danglingQuoteOffset()} still finds it.
     */
    private function stripTrailingComment(string $text): string
    {
        $offsets = array_filter(
            [$this->falseToNull(strpos($text, '//')), $this->hashCommentOffset($text)],
            static fn (?int $offset): bool => null !== $offset,
        );

        return [] === $offsets ? $text : substr($text, 0, min($offsets));
    }

    /**
     * A `#[` starts a PHP attribute, not a comment — the negative lookahead
     * keeps an attribute's own argument list (which may span multiple lines
     * and must be paren-tracked like any other retained line) from being
     * truncated away at the `#`.
     */
    private function hashCommentOffset(string $text): ?int
    {
        return 1 === preg_match('/#(?!\[)/', $text, $matches, \PREG_OFFSET_CAPTURE) ? $matches[0][1] : null;
    }

    private function falseToNull(int|false $offset): ?int
    {
        return false === $offset ? null : $offset;
    }

    /**
     * `/* *\/` block-comment boundaries must be tracked on every line — even
     * an elided one — because they are a property of the raw source text, not
     * of the elision decision. An elided `/**` opening line still needs its
     * "inside a block comment" state carried forward so a later, independently
     * retained continuation line (e.g. a PHPDoc note mentioning a
     * security-token function by name) has its comment content stripped
     * before {@see self::parenDelta()} counts parentheses in it — otherwise a
     * stray unbalanced paren inside prose desyncs tracking for the rest of the
     * file.
     *
     * @return array{line: string, inside_block_comment: bool}
     */
    private function stripBlockComments(string $line, bool $insideBlockComment): array
    {
        if ($insideBlockComment) {
            $closeOffset = strpos($line, '*/');
            if (false === $closeOffset) {
                return ['line' => '', 'inside_block_comment' => true];
            }

            return $this->stripBlockComments(substr($line, $closeOffset + 2), false);
        }

        $openOffset = strpos($this->maskStringLiterals($line), '/*');
        if (false === $openOffset) {
            return ['line' => $line, 'inside_block_comment' => false];
        }

        $before = substr($line, 0, $openOffset);
        $after = $this->stripBlockComments(substr($line, $openOffset + 2), true);

        return ['line' => $before.$after['line'], 'inside_block_comment' => $after['inside_block_comment']];
    }

    /**
     * A string literal containing a bare `/*` (e.g. the `'image/*'` MIME
     * wildcard) is indistinguishable from a genuine block-comment opener to a
     * plain {@see strpos()} scan — masking same-line string literals to a
     * same-length run of `x` before searching keeps offsets aligned with the
     * original line (so the caller can still slice it correctly) while
     * preventing a quoted `/*` from ever being mistaken for real comment
     * syntax and permanently desyncing tracking for the rest of the file.
     */
    private function maskStringLiterals(string $line): string
    {
        return preg_replace_callback(
            self::STRING_LITERAL_PATTERN,
            static fn (array $matches): string => str_repeat('x', \strlen($matches[0])),
            $line,
        ) ?? $line;
    }
}
