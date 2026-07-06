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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Report;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\JsonReportRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportRendererInterface;

final class JsonReportRendererTest extends AbstractReportRendererTestCase
{
    #[Override]
    protected function createRenderer(): ReportRendererInterface
    {
        return new JsonReportRenderer();
    }

    public function test_it_advertises_the_json_format(): void
    {
        self::assertSame('json', $this->renderer->format());
    }

    /**
     * @throws InvalidAuditContextException
     */
    public function test_render_returns_valid_json_array(): void
    {
        $decoded = json_decode($this->renderer->render($this->makeReport()), true);

        self::assertIsArray($decoded);
        self::assertArrayHasKey('audit_id', $decoded);
        self::assertArrayHasKey('vulnerabilities', $decoded);
    }
}
