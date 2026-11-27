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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Pipeline;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidCodeLocationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityClassificationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidVulnerabilityNarrativeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ScrubbedSecretFindings;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception\SecretScrubberConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\RegexSecretScrubber;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\ReviewerPromptBuilder;

final class RedactedDotenvCredentialReviewTest extends TestCase
{
    /**
     * @throws InvalidCodeLocationException
     * @throws InvalidProjectFileException
     * @throws InvalidVulnerabilityClassificationException
     * @throws InvalidVulnerabilityNarrativeException
     * @throws SecretScrubberConfigurationException
     */
    public function test_the_reviewer_reads_the_variable_name_of_each_credential_redacted_in_a_dev_dotenv_file(): void
    {
        $scrubbed = (new RegexSecretScrubber())->scrubFile('.env.dev', \sprintf("APP_SECRET=0123456789abcdef0123456789abcdef\nGITHUB_TOKEN=ghp_%s\n", str_repeat('a1B2', 9)));
        $candidates = ScrubbedSecretFindings::in(ProjectFile::create('.env.dev', '/project/.env.dev', $scrubbed));
        $codeContexts = [];
        foreach ($candidates as $candidate) {
            $codeContexts[$candidate->id()] = $scrubbed;
        }

        $message = (new ReviewerPromptBuilder())->buildBatchUserMessage($candidates, $codeContexts);

        self::assertCount(2, $candidates);
        self::assertStringContainsString('APP_SECRET=***REDACTED:env_assignment***', $message);
        self::assertStringContainsString('GITHUB_TOKEN=***REDACTED:env_assignment***', $message);
    }
}
