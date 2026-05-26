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
 * Lightweight regex-driven slicer that retains only the security-relevant
 * portions of a PHP file:
 *
 *   - the namespace + use declarations (so the LLM knows the type-resolution
 *     context),
 *   - every PHP attribute (`#[…]`), class/trait/interface/enum signature, and
 *     property declaration,
 *   - method signatures, plus the FULL body of methods that contain at least
 *     one security-relevant token (Request:: access, Doctrine query builder,
 *     unserialize, shell exec, mailer send, HttpClient request, …).
 *
 * Non-PHP files (Twig, YAML, XML) pass through unchanged because they are
 * already small enough that slicing them would lose context. PHP files
 * shorter than `MIN_LINES_BEFORE_SLICING` also pass through — slicing a 30-line
 * service has no token-saving upside.
 *
 * Eliminated lines are replaced one-for-one with a `// elided` placeholder so
 * the file's TOTAL line count is preserved — the attacker prompt's
 * `line_start` / `line_end` protocol (which counts lines from 1 in the
 * post-numbered output) remains accurate against the original source.
 */
final readonly class RegexCodeSlicer implements CodeSlicerInterface
{
    public const int DEFAULT_MIN_LINES_BEFORE_SLICING = 80;

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

    public function slice(ProjectFile $file): string
    {
        if (!$this->shouldSlice($file)) {
            return $file->content();
        }

        return $this->slicePhpContent($file->content());
    }

    private function shouldSlice(ProjectFile $file): bool
    {
        if ('php' !== pathinfo($file->relativePath(), \PATHINFO_EXTENSION)) {
            return false;
        }

        return $file->linesCount() >= $this->minLinesBeforeSlicing;
    }

    private function slicePhpContent(string $content): string
    {
        $lines = explode("\n", $content);
        $totalLines = \count($lines);

        $methodRanges = $this->detectMethodRanges($lines);
        $hotMethods = $this->detectHotMethods($lines, $methodRanges);

        $retain = $this->initialRetention($totalLines);
        $this->retainAlwaysKeptLines($lines, $retain);
        $this->retainHotMethodBodies($hotMethods, $retain);

        return $this->renderWithElisions($lines, $retain);
    }

    /**
     * @return array<int, bool>
     */
    private function initialRetention(int $totalLines): array
    {
        $retain = [];
        for ($i = 0; $i < $totalLines; ++$i) {
            $retain[$i] = false;
        }

        return $retain;
    }

    /**
     * @param list<string>     $lines
     * @param array<int, bool> $retain
     */
    private function retainAlwaysKeptLines(array $lines, array &$retain): void
    {
        foreach ($lines as $index => $line) {
            $trimmed = ltrim($line);

            if (1 === preg_match('/^(<\?php|namespace\s|use\s|use\s+function\s|use\s+const\s)/', $trimmed)) {
                $retain[$index] = true;

                continue;
            }

            if (1 === preg_match('/^#\[/', $trimmed)) {
                $retain[$index] = true;

                continue;
            }

            if (1 === preg_match('/^(abstract\s+|final\s+|readonly\s+|final\s+readonly\s+)?(class|interface|trait|enum)\s/', $trimmed)) {
                $retain[$index] = true;

                continue;
            }

            if (1 === preg_match('/^(public|protected|private)\s+(static\s+)?(readonly\s+)?[^(]*\$[A-Za-z_][A-Za-z0-9_]*\s*[=;]/', $trimmed)) {
                $retain[$index] = true;

                continue;
            }

            if (1 === preg_match('/^(public|protected|private)\s+(static\s+)?function\s/', $trimmed)) {
                $retain[$index] = true;
            }
        }
    }

    /**
     * @return list<array{start: int, end: int}>
     */
    private function detectMethodRanges(array $lines): array
    {
        $ranges = [];
        $totalLines = \count($lines);

        foreach ($lines as $index => $line) {
            if (1 !== preg_match('/^\s*(public|protected|private)\s+(static\s+)?function\s/', $line)) {
                continue;
            }

            $bodyStart = $this->findOpeningBrace($lines, $index);
            if (null === $bodyStart) {
                continue;
            }

            $bodyEnd = $this->findMatchingClose($lines, $bodyStart);
            if (null === $bodyEnd || $bodyEnd >= $totalLines) {
                continue;
            }

            $ranges[] = ['start' => $index, 'end' => $bodyEnd];
        }

        return $ranges;
    }

    /**
     * @param list<string>                          $lines
     * @param list<array{start: int, end: int}>     $methodRanges
     *
     * @return list<array{start: int, end: int}>
     */
    private function detectHotMethods(array $lines, array $methodRanges): array
    {
        $hot = [];

        foreach ($methodRanges as $range) {
            $body = '';
            for ($i = $range['start']; $i <= $range['end']; ++$i) {
                $body .= $lines[$i]."\n";
            }

            if ($this->containsSecurityToken($body)) {
                $hot[] = $range;
            }
        }

        return $hot;
    }

    private function containsSecurityToken(string $body): bool
    {
        foreach (self::SECURITY_TOKENS as $token) {
            if (str_contains($body, $token)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<array{start: int, end: int}> $hotMethods
     * @param array<int, bool>                  $retain
     */
    private function retainHotMethodBodies(array $hotMethods, array &$retain): void
    {
        foreach ($hotMethods as $range) {
            for ($i = $range['start']; $i <= $range['end']; ++$i) {
                $retain[$i] = true;
            }
        }
    }

    /**
     * @param list<string> $lines
     */
    private function findOpeningBrace(array $lines, int $signatureIndex): ?int
    {
        $totalLines = \count($lines);

        for ($i = $signatureIndex; $i < $totalLines; ++$i) {
            if (str_contains($lines[$i], '{')) {
                return $i;
            }

            if (str_contains($lines[$i], ';')) {
                return null;
            }
        }

        return null;
    }

    /**
     * @param list<string> $lines
     */
    private function findMatchingClose(array $lines, int $openLineIndex): ?int
    {
        $depth = 0;
        $totalLines = \count($lines);

        for ($i = $openLineIndex; $i < $totalLines; ++$i) {
            $stripped = $this->stripStringsAndComments($lines[$i]);
            foreach (str_split($stripped) as $char) {
                if ('{' === $char) {
                    ++$depth;
                } elseif ('}' === $char) {
                    --$depth;

                    if (0 === $depth) {
                        return $i;
                    }
                }
            }
        }

        return null;
    }

    private function stripStringsAndComments(string $line): string
    {
        $without = (string) preg_replace('/(?<!\\\\)\'(?:\\\\.|[^\'\\\\])*\'/', "''", $line);
        $without = (string) preg_replace('/(?<!\\\\)"(?:\\\\.|[^"\\\\])*"/', '""', $without);
        $without = (string) preg_replace('/\/\/.*$/', '', $without);

        return (string) preg_replace('/#(?!\[).*$/', '', $without);
    }

    /**
     * @param list<string>     $lines
     * @param array<int, bool> $retain
     */
    private function renderWithElisions(array $lines, array $retain): string
    {
        $output = [];

        foreach ($lines as $index => $line) {
            $output[] = $retain[$index] ? $line : '// elided';
        }

        return implode("\n", $output);
    }
}
