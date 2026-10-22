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

use function Symfony\Component\String\u;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Retains a line that is either structural (declarations, attributes) or
 * dangerous (matches a known security-relevant token or keyword).
 */
final readonly class SecurityRelevantLineClassifier implements LineRetentionDeciderInterface
{
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
        '->createNativeQuery(',
        '->query(',
        '->prepare(',
        '->fetchAllAssociative(',
        '->find(',
        '->findOneBy(',
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
        '->createTemplate(',
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

    private const string NON_ASCII_BYTE = '/[^\x00-\x7F]/';

    /**
     * The leading characters `u()->trimStart()` drops that a line of ASCII
     * alone can hold.
     */
    private const string ASCII_LEADING_SPACE = " \t\n\r\0\x0B\x0C";

    #[Override]
    public function isRetained(string $line, LineRetentionContext $lineRetentionContext): bool
    {
        return $this->isStructuralOrHoldsSecurityToken($line) || 1 === preg_match(self::BARE_KEYWORD_PATTERN, $line);
    }

    /**
     * A line of ASCII alone holds no grapheme, normalization form or Unicode
     * space that would set its bytes apart from its text, so it is matched
     * byte by byte, with the same outcome and many times faster than as a
     * Unicode string; any other line is read as Unicode text.
     */
    private function isStructuralOrHoldsSecurityToken(string $line): bool
    {
        if (1 === preg_match(self::NON_ASCII_BYTE, $line)) {
            $text = u($line);

            return $text->trimStart()->startsWith(self::STRUCTURAL_PREFIXES) || $text->containsAny(self::SECURITY_TOKENS);
        }

        return $this->startsWithStructuralPrefix(ltrim($line, self::ASCII_LEADING_SPACE)) || $this->holdsSecurityToken($line);
    }

    private function startsWithStructuralPrefix(string $line): bool
    {
        foreach (self::STRUCTURAL_PREFIXES as $structuralPrefix) {
            if (str_starts_with($line, $structuralPrefix)) {
                return true;
            }
        }

        return false;
    }

    private function holdsSecurityToken(string $line): bool
    {
        foreach (self::SECURITY_TOKENS as $securityToken) {
            if (str_contains($line, $securityToken)) {
                return true;
            }
        }

        return false;
    }
}
