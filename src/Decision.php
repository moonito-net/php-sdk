<?php

namespace Moonito;

/**
 * What Moonito decided, plus everything the caller needs to act on it.
 *
 * Constructed from either a v2 or a v1 response, so code written against this
 * class keeps working when the SDK falls back to v1.
 */
final class Decision
{
    const ALLOW = 'allow';
    const CHALLENGE = 'challenge';
    const BLOCK = 'block';

    private $action;
    private $score;
    private $confidence;
    private $reasons;
    private $raw;
    private $degraded;
    private $decisionId;
    private $nonce;
    private $setClientToken;
    private $challengeUrl;

    private function __construct(string $action, array $raw, bool $degraded = false)
    {
        $this->action = $action;
        $this->raw = $raw;
        $this->degraded = $degraded;

        $risk = isset($raw['data']['status']['risk']) ? $raw['data']['status']['risk'] : [];
        $this->score = isset($risk['score']) ? (int) $risk['score'] : 0;
        $this->confidence = isset($risk['confidence']) ? (float) $risk['confidence'] : 0.0;
        $this->reasons = isset($risk['reasons']) && is_array($risk['reasons']) ? $risk['reasons'] : [];

        $this->decisionId = isset($raw['data']['decision_id']) ? $raw['data']['decision_id'] : null;
        $this->nonce = isset($raw['data']['nonce']) ? $raw['data']['nonce'] : null;
        $this->setClientToken = isset($raw['data']['set_client_token']) ? $raw['data']['set_client_token'] : null;

        // Absent whenever the server decided there was no point sending the
        // visitor anywhere: challenges turned off, no CAPTCHA configured, the
        // allowance exhausted, or a pass already in hand.
        $this->challengeUrl = isset($raw['data']['challenge_url']) && is_string($raw['data']['challenge_url'])
            ? $raw['data']['challenge_url']
            : null;
    }

    public static function fromResponse(array $raw, string $challengeAction = self::ALLOW): self
    {
        $status = isset($raw['data']['status']) ? $raw['data']['status'] : [];
        $risk = isset($status['risk']) ? $status['risk'] : [];

        $action = isset($risk['decision']) ? (string) $risk['decision'] : null;

        if ($action === null) {
            // A v1 response carries only the boolean.
            $action = !empty($status['need_to_block']) ? self::BLOCK : self::ALLOW;
        }

        // A challenge this SDK cannot render falls back to what the site chose,
        // so a caller never receives a decision it has no way to act on.
        if ($action === self::CHALLENGE && $challengeAction !== self::CHALLENGE) {
            $action = $challengeAction === self::BLOCK ? self::BLOCK : self::ALLOW;
        }

        return new self($action, $raw);
    }

    /** Used when the check could not run. The visitor is let through. */
    public static function degraded(string $failMode = 'open'): self
    {
        $action = $failMode === 'closed' ? self::BLOCK : self::ALLOW;

        return new self($action, ['data' => ['status' => ['need_to_block' => $action === self::BLOCK]]], true);
    }

    public function action(): string
    {
        return $this->action;
    }

    public function isAllow(): bool
    {
        return $this->action === self::ALLOW;
    }

    public function isChallenge(): bool
    {
        return $this->action === self::CHALLENGE;
    }

    public function isBlock(): bool
    {
        return $this->action === self::BLOCK;
    }

    /** The v1 accessor, kept so existing integrations read the same thing. */
    public function needToBlock(): bool
    {
        return $this->action === self::BLOCK;
    }

    public function score(): int
    {
        return $this->score;
    }

    public function confidence(): float
    {
        return $this->confidence;
    }

    public function reasons(): array
    {
        return $this->reasons;
    }

    public function isDegraded(): bool
    {
        return $this->degraded;
    }

    public function decisionId(): ?string
    {
        return $this->decisionId;
    }

    public function nonce(): ?string
    {
        return $this->nonce;
    }

    /**
     * Where to send a challenged visitor.
     *
     * Null with action CHALLENGE is a real and expected combination. It means
     * the engine wanted a challenge and the server declined to issue one, and
     * the caller should fall back to its configured behaviour rather than
     * invent a destination.
     */
    public function challengeUrl(): ?string
    {
        return $this->challengeUrl;
    }

    /** Downgrades a challenge in place. Used to break a redirect loop. */
    public function withoutChallenge(string $to = self::ALLOW): self
    {
        $clone = clone $this;
        $clone->action = $to;
        $clone->challengeUrl = null;

        return $clone;
    }

    public function clientTokenCookie(): ?array
    {
        return $this->setClientToken;
    }

    public function raw(): array
    {
        return $this->raw;
    }

    /** True only for a real allow, never for a degraded one. */
    public function isCacheable(): bool
    {
        return $this->action === self::ALLOW && !$this->degraded;
    }
}
