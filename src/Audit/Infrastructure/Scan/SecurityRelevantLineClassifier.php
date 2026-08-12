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

    #[Override]
    public function isRetained(string $line, LineRetentionContext $lineRetentionContext): bool
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
}
