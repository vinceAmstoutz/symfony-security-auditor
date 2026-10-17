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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Compat\Platform;

/**
 * The state of the scripted provider for the scenario being run: one scenario
 * runs per process, and the bundle and the standalone binary each build their
 * own platform instance, so the script and the call log live here.
 */
final class PlatformSession
{
    private static ?PlatformScript $platformScript = null;

    /**
     * @var list<string>
     */
    private static array $calls = [];

    private static int $invocations = 0;

    private static int $toolCallsMade = 0;

    /**
     * @var array<string, int>
     */
    private static array $reviews = [];

    /**
     * @var array<string, list<string>>
     */
    private static array $promptsByFile = [];

    public static function start(PlatformScript $platformScript): void
    {
        self::$platformScript = $platformScript;
        self::$calls = [];
        self::$invocations = 0;
        self::$toolCallsMade = 0;
        self::$reviews = [];
        self::$promptsByFile = [];
    }

    public static function script(): PlatformScript
    {
        return self::$platformScript ?? PlatformScript::default();
    }

    public static function countInvocation(): int
    {
        return ++self::$invocations;
    }

    public static function record(string $call): void
    {
        self::$calls[] = $call;
    }

    /**
     * @return list<string>
     */
    public static function calls(): array
    {
        return self::$calls;
    }

    /**
     * @return list<array{string, array<string, mixed>}>
     */
    public static function takeAttackerToolCalls(): array
    {
        $toolCalls = \array_slice(self::script()->attackerToolCalls, self::$toolCallsMade);
        self::$toolCallsMade += \count($toolCalls);

        return $toolCalls;
    }

    public static function nextReviewOf(string $titleFragment): int
    {
        self::$reviews[$titleFragment] = (self::$reviews[$titleFragment] ?? 0) + 1;

        return self::$reviews[$titleFragment];
    }

    /**
     * Which distinct attacker prompt this is among those that carried the file:
     * the first iteration reads it in prompt 1, the next in prompt 2, …
     */
    public static function promptOrdinal(string $filePath, string $prompt): int
    {
        $promptHash = md5($prompt);
        $seen = self::$promptsByFile[$filePath] ?? [];
        $position = array_search($promptHash, $seen, true);

        if (\is_int($position)) {
            return $position + 1;
        }

        self::$promptsByFile[$filePath] = [...$seen, $promptHash];

        return \count($seen) + 1;
    }
}
