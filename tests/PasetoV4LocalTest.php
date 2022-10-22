<?php
use PHPUnit\Framework\TestCase;

class PasetoV4LocalTest extends TestCase
{
    /** @var array<string, PasetoV4Local> $keyCache */
    private $keyCache = array();

    public function getTestVectors()
    {
        $loaded = json_decode(file_get_contents(__DIR__ . '/v4.local.json'), true);
        if (!is_array($loaded)) {
            $this->fail('Could not load test vectors');
        }
        return $loaded;
    }

    public function cacheKey($hex)
    {
        if (!array_key_exists($hex, $this->keyCache)) {
            $this->keyCache[$hex] = new PasetoV4Local(sodium_hex2bin($hex));
        }
        return $this->keyCache[$hex];
    }

    public function testVectors()
    {
        $testFile = $this->getTestVectors();
        $name = $testFile['name'];
        foreach ($testFile['tests'] as $test) {
            try {
                $decoded = $this->cacheKey($test['key'])->decrypt(
                    $test['token'],
                    $test['implicit-assertion'],
                    $test['footer']
                );
                $this->assertSame($decoded, $test['payload'],  $name . ' - ' . $test['name']);
            } catch (PasetoException $ex) {
                continue;
            } catch (SodiumException $ex) {
                continue;
            }
            $this->assertFalse($test['expect-fail'], 'This test was expected to fail: ' . $name . ' - ' . $test['name']);
        }
    }
}
