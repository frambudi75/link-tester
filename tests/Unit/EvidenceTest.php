<?php
/**
 * Evidence Test - LinkTester
 */

require_once __DIR__ . '/../../core/Evidence.php';

function testEvidenceCreation() {
    $ev = Evidence::create('punycode_detected', true, 'heuristic', ['host' => 'xn--example.com'], 0.95);
    assert($ev->signal === 'punycode_detected', 'Evidence signal should match');
    assert($ev->value === true, 'Evidence value should match');
    assert($ev->source === 'heuristic', 'Evidence source should match');
    assert($ev->confidence === 0.95, 'Evidence confidence should match');
    assert($ev->metadata['host'] === 'xn--example.com', 'Evidence metadata should match');

    $arr = $ev->toArray();
    assert(is_array($arr), 'Evidence toArray should return array');
    assert($arr['signal'] === 'punycode_detected', 'toArray signal should match');
    echo "  [PASS] testEvidenceCreation\n";
}

testEvidenceCreation();
