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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem;

use Override;
use PhpToken;
use Stringable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\UnmatchedClosers;

/**
 * Tells, byte by byte, what a PHP file is made of: code that PHP runs, or text it only carries (the
 * inside of a string, a comment, a heredoc body, the markup around a tag). A file that does not open
 * with a PHP tag — a YAML, dotenv or Twig file, even one that mentions `<?php` further down — is text
 * from end to end, and so is a file with so many unmatched closing brackets that PHP's tokenizer would
 * stall on it ({@see UnmatchedClosers}): more is redacted in it, never less.
 *
 * A placeholder written over code the parser needs — a constant, a call, a parameter default — leaves
 * a file that no longer parses; one written over text never does.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PhpDataMask implements Stringable
{
    private const string CODE = 'c';

    private const string TEXT = 't';

    private const string STRING_END = 'e';

    private const int DOUBLE_QUOTE = 34;

    private const string PHP_OPENING = '/\A(?:\xEF\xBB\xBF)?(?:#![^\n]*+\n)?\s*+<\?(?:php\s|=)/';

    private function __construct(private string $mask) {}

    #[Override]
    public function __toString(): string
    {
        return $this->mask;
    }

    public static function of(string $content): self
    {
        if (!self::opensWithPhpTag($content) || UnmatchedClosers::exceedLimit($content)) {
            return new self(str_repeat(self::TEXT, \strlen($content)));
        }

        $mask = '';
        $insideString = false;
        foreach (PhpToken::tokenize($content) as $phpToken) {
            $mask .= self::maskOfToken($phpToken, $insideString);
            $insideString = $insideString !== self::isDoubleQuote($phpToken);
        }

        return new self($mask);
    }

    public static function opensWithPhpTag(string $content): bool
    {
        return 1 === preg_match(self::PHP_OPENING, $content);
    }

    /**
     * How many bytes from the offset, within the length, are text.
     */
    public function textLength(int $offset, int $length): int
    {
        return strspn($this->mask, self::TEXT, $offset, $length);
    }

    /**
     * The length of a literal's body when the quotes a pattern paired are the two ends of one literal,
     * 0 when they are not: `'_password='.$enc, '…'` pairs the closing quote of the first string with the
     * opening quote of the second, and a string running over several lines has no closing quote on the
     * line where it opens.
     */
    public function literalLength(int $opening, int $length): int
    {
        return $this->isStringLiteral($opening, $opening + $length + 1) ? $length : 0;
    }

    /**
     * Both quotes inside a text, or the opening and the closing quote of a PHP string.
     */
    public function isStringLiteral(int $opening, int $closing): bool
    {
        return self::CODE === $this->mask[$opening] ? self::STRING_END === $this->mask[$closing] : self::TEXT === $this->mask[$opening] && self::TEXT === $this->mask[$closing];
    }

    private static function maskOfToken(PhpToken $phpToken, bool $insideString): string
    {
        return match (true) {
            \T_CONSTANT_ENCAPSED_STRING === $phpToken->id => self::CODE.str_repeat(self::TEXT, \strlen($phpToken->text) - 2).self::STRING_END,
            $phpToken->is([\T_COMMENT, \T_DOC_COMMENT]) => self::maskOfComment($phpToken->text),
            $phpToken->is([\T_INLINE_HTML, \T_ENCAPSED_AND_WHITESPACE]) => str_repeat(self::TEXT, \strlen($phpToken->text)),
            $insideString && self::isDoubleQuote($phpToken) => self::STRING_END,
            default => str_repeat(self::CODE, \strlen($phpToken->text)),
        };
    }

    private static function maskOfComment(string $text): string
    {
        $terminatorLength = str_starts_with($text, '/*') && str_ends_with($text, '*/') ? 2 : 0;

        return str_repeat(self::TEXT, \strlen($text) - $terminatorLength).str_repeat(self::CODE, $terminatorLength);
    }

    private static function isDoubleQuote(PhpToken $phpToken): bool
    {
        return self::DOUBLE_QUOTE === $phpToken->id;
    }
}
