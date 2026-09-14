<?php
/**
 * Evidence - LinkTester
 * 
 * Immutable data class representing a single detection signal.
 * All analyzers produce Evidence objects. Only the RiskScorer consumes them.
 * PHP 8.0+ compatible.
 */

class Evidence
{
    public string $signal;
    public mixed $value;
    public string $source;
    public array $metadata;
    public float $confidence;

    private function __construct(string $signal, mixed $value, string $source, array $metadata, float $confidence)
    {
        $this->signal = $signal;
        $this->value = $value;
        $this->source = $source;
        $this->metadata = $metadata;
        $this->confidence = min(1.0, max(0.0, $confidence));
    }

    /**
     * Factory: create a new Evidence.
     */
    public static function create(
        string $signal,
        mixed $value,
        string $source = 'unknown',
        array $metadata = [],
        float $confidence = 1.0
    ): self {
        return new self($signal, $value, $source, $metadata, $confidence);
    }

    /**
     * Serialize to array for JSON output.
     */
    public function toArray(): array
    {
        return [
            'signal'     => $this->signal,
            'value'      => $this->value,
            'source'     => $this->source,
            'metadata'   => $this->metadata,
            'confidence' => $this->confidence,
        ];
    }
}
