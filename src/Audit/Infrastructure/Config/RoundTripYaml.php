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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use Symfony\Component\Yaml\Yaml;

/**
 * YAML that `init` hands the user, read back as what was dumped: a document
 * holding a string the parser would read as a float (`.inf`, `1_000.5`) has
 * every value double-quoted.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class RoundTripYaml
{
    /**
     * @param array<array-key, mixed> $value
     */
    public static function dump(array $value, int $inline, int $indent): string
    {
        $yaml = Yaml::dump($value, $inline, $indent);

        return Yaml::parse($yaml) === $value
            ? $yaml
            : Yaml::dump($value, $inline, $indent, Yaml::DUMP_FORCE_DOUBLE_QUOTES_ON_VALUES);
    }
}
