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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\CweReference;

final class CweReferenceTest extends TestCase
{
    public function test_it_exposes_the_id(): void
    {
        self::assertSame(89, CweReference::of(89)->id());
    }

    public function test_it_formats_the_label(): void
    {
        self::assertSame('CWE-89', CweReference::of(89)->label());
    }

    public function test_it_formats_the_definition_url(): void
    {
        self::assertSame('https://cwe.mitre.org/data/definitions/89.html', CweReference::of(89)->url());
    }
}
