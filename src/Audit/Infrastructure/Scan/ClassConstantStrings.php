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

use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\Class_;

/**
 * The string each of a class's own constants holds, by constant name: what a
 * `self::ADMIN_PATH` route path or a `PostVoter::EDIT` guard stands for. A
 * constant declared elsewhere, or holding anything but a string literal, is
 * left out rather than guessed at.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ClassConstantStrings
{
    /**
     * @return array<string, string>
     */
    public static function of(Class_ $class): array
    {
        $constants = [];
        foreach ($class->getConstants() as $classConst) {
            foreach ($classConst->consts as $const) {
                if ($const->value instanceof String_) {
                    $constants[$const->name->toString()] = $const->value->value;
                }
            }
        }

        return $constants;
    }
}
