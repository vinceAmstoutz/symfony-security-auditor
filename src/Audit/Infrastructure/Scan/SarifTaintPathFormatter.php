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

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class SarifTaintPathFormatter
{
    /**
     * @param list<string|null> $rawSteps each dropped (null) step collapses to
     *                                    a single `...` so a surviving step is
     *                                    never mistaken for the taint source
     */
    public function describe(string $message, array $rawSteps): string
    {
        $steps = $this->collapseDroppedStepsToEllipses($rawSteps);
        if ([] === $steps) {
            return $message;
        }

        return \sprintf('%s (taint path: %s)', $message, implode(' -> ', $steps));
    }

    /**
     * @param list<string|null> $rawSteps
     *
     * @return list<string>
     */
    private function collapseDroppedStepsToEllipses(array $rawSteps): array
    {
        $steps = [];
        $droppedSincePreviousStep = false;
        foreach ($rawSteps as $rawStep) {
            if (null === $rawStep) {
                $droppedSincePreviousStep = true;

                continue;
            }

            if ($droppedSincePreviousStep) {
                $steps[] = '...';
            }

            $steps[] = $rawStep;
            $droppedSincePreviousStep = false;
        }

        if ($droppedSincePreviousStep && [] !== $steps) {
            $steps[] = '...';
        }

        return $steps;
    }
}
