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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Mcp\Fixture;

use Mcp\Server\Transport\StdioTransport;
use Mcp\Server\Transport\TransportInterface;
use Override;
use RuntimeException;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Mcp\McpTransportFactoryInterface;

final class PreloadedStdioTransportFactory implements McpTransportFactoryInterface
{
    public string $outputPath = '';

    /**
     * @param list<string> $messages
     */
    public function __construct(private readonly array $messages) {}

    /**
     * @return TransportInterface<mixed>
     */
    #[Override]
    public function create(): TransportInterface
    {
        $inputPath = tempnam(sys_get_temp_dir(), 'ssa-mcp-in');
        $outputPath = tempnam(sys_get_temp_dir(), 'ssa-mcp-out');
        if (false === $inputPath || false === $outputPath) {
            throw new RuntimeException('Unable to create temporary MCP transport streams.');
        }

        file_put_contents($inputPath, implode("\n", $this->messages)."\n");
        $this->outputPath = $outputPath;

        $input = fopen($inputPath, 'r');
        $output = fopen($outputPath, 'w');
        if (false === $input || false === $output) {
            throw new RuntimeException('Unable to open temporary MCP transport streams.');
        }

        return new StdioTransport($input, $output);
    }

    public function capturedOutput(): string
    {
        $output = file_get_contents($this->outputPath);
        if (false === $output) {
            throw new RuntimeException('Unable to read captured MCP transport output.');
        }

        return $output;
    }
}
