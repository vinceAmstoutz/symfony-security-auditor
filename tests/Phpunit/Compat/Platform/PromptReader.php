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

use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\Message\Template;
use Symfony\AI\Platform\Message\ToolCallMessage;
use Symfony\AI\Platform\Tool\Tool;

final readonly class PromptReader
{
    /**
     * @param array<array-key, mixed>|string|object $input
     */
    public static function text(array|string|object $input): string
    {
        if (\is_string($input)) {
            return $input;
        }

        if (!$input instanceof MessageBag) {
            return '';
        }

        $systemContent = $input->getSystemMessage()?->getContent();

        return \sprintf('%s%s', $systemContent instanceof Template ? '' : (string) $systemContent, $input->getUserMessage()?->asText() ?? '');
    }

    /**
     * @param array<array-key, mixed>|string|object $input
     */
    public static function toolResultCount(array|string|object $input): int
    {
        if (!$input instanceof MessageBag) {
            return 0;
        }

        return \count(array_filter($input->getMessages(), static fn (object $message): bool => $message instanceof ToolCallMessage));
    }

    /**
     * @param array<array-key, mixed> $options
     *
     * @return list<string>
     */
    public static function toolNames(array $options): array
    {
        $tools = $options['tools'] ?? [];

        return array_values(array_map(
            static fn (Tool $tool): string => $tool->getName(),
            array_filter(\is_array($tools) ? $tools : [], static fn (mixed $tool): bool => $tool instanceof Tool),
        ));
    }

    /**
     * @return array<string, string> the content of each `<file path="…">` block, by path
     */
    public static function fileBlocks(string $prompt): array
    {
        preg_match_all('/<file path="([^"]+)"[^>]*>(.*?)<\/file>/s', $prompt, $matches, \PREG_SET_ORDER);

        $files = [];
        foreach ($matches as $match) {
            $files[$match[1]] = \sprintf('%s%s', $files[$match[1]] ?? '', $match[2]);
        }

        return $files;
    }

    /**
     * @return list<string>
     */
    public static function findingIds(string $prompt): array
    {
        preg_match_all('/VULN-[0-9A-F]{8}/', $prompt, $matches);

        return array_values(array_unique($matches[0]));
    }
}
