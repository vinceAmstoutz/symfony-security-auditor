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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

/**
 * Opt-in extension of {@see ReviewerPromptBuilderInterface} for builders that
 * can state either answer contract: the `record_review` tool calls of
 * structured collection, or the JSON array of the default mode. The reviewer
 * agent knows which of the two a review will run, whatever the configured
 * default, and asks for the builder that matches it, so a prompt never
 * demands a tool the review does not offer. Consumers check
 * `instanceof StructuredCollectionAwareReviewerPromptBuilderInterface` and use
 * the builder they were given when it is not implemented, so adding this
 * capability never breaks an existing builder.
 */
interface StructuredCollectionAwareReviewerPromptBuilderInterface extends ReviewerPromptBuilderInterface
{
    /**
     * A builder equal to this one in every respect but the answer contract it
     * states; this builder is left as it was.
     */
    public function withStructuredCollection(bool $structuredCollection): ReviewerPromptBuilderInterface;
}
