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

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StringLiteralMasker
{
    public function mask(string $line): string
    {
        return $this->replaceLiterals($line, 'x');
    }

    public function strip(string $line): string
    {
        return $this->replaceLiterals($line, '');
    }

    /**
     * @param string $replacement stands for each character of a literal, quotes included
     */
    private function replaceLiterals(string $line, string $replacement): string
    {
        $closingLimits = LiteralScanState::closingLimits($line);
        $state = LiteralScanState::outside();
        $result = '';

        foreach (str_split($line) as $offset => $char) {
            $wasInside = $state->isInside();
            $state = $state->next($char, $offset, $closingLimits);
            $result .= $wasInside || $state->isInside() ? $replacement : $char;
        }

        return $result;
    }
}
