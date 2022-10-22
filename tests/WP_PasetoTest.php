<?php
use PHPUnit\Framework\TestCase;

/**
 * @covers WP_Paseto
 */
class WP_PasetoTest extends TestCase
{
    /**
     * @throws Exception
     */
    public function keySetProvider()
    {
        return array(
            array(array(
                'foo' => str_repeat("\x00", 32),
                'bar' => str_repeat("\xff", 32)
            )), array(array(
                'foo' => random_bytes(32),
                'bar' => random_bytes(32)
            ))
        );
    }

    /** @test */
    public function testClassExists()
    {
        $this->assertTrue(class_exists('WP_Paseto'));
    }

    /**
     * @dataProvider keySetProvider
     * @throws PasetoException
     * @test
     */
    public function testClaims(array $keySet)
    {
        $paseto = new WP_Paseto($keySet, new DateInterval('PT05M'));
        $paseto->setAudience('test.wordpress.org');
        $paseto->setIdentifier('phpunit');
        $paseto->setIssuer('phpunit-localhost')->setSubject('test');

        $token = $paseto->encode(array('foo' => 'bar'));
        $claims = $paseto->decode($token);
        $this->assertSame($claims['foo'], 'bar');
        $this->assertSame($claims['sub'], 'test');
    }

    /**
     * @dataProvider keySetProvider
     * @throws PasetoException
     * @test
     */
    public function testExpiredToken(array $keySet)
    {
        $paseto = new WP_Paseto($keySet, new DateInterval('PT01M'));
        $now = (new DateTime())->sub(new DateInterval('PT02M'))->format(DATE_ATOM);

        $token  = $paseto->encode(array('exp' => $now, 'test' => 'foo'), 'foo');
        $decode = $paseto->decode($token, '', true);
        $this->assertSame($now, $decode['exp']);
        try {
            $paseto->decode($token);
            $this->fail('Should fail with invalid time');
        } catch (PasetoException $ex) {
            $this->assertSame('This token has expired', $ex->getMessage());
        }
    }

    /**
     * @dataProvider keySetProvider
     * @throws PasetoException
     * @test
     */
    public function testEncodeDecode(array $keySet)
    {
        $paseto = new WP_Paseto($keySet);
        $token1 = $paseto->encode(array('tests' => 'Soatok'), 'foo');
        $token2 = $paseto->encode(array('tests' => 'Soatok'), 'bar');
        $token3 = $paseto->encode(array('tests' => 'Soatok'), 'foo', 'dhole');
        $token4 = $paseto->encode(array('tests' => 'Soatok'), 'bar', 'dhole');

        $claims1 = $paseto->decode($token1);
        $claims2 = $paseto->decode($token2);
        $claims3 = $paseto->decode($token3, 'dhole');
        $claims4 = $paseto->decode($token4, 'dhole');

        $this->assertSame($claims1['tests'], 'Soatok');
        $this->assertSame($claims2['tests'], 'Soatok');
        $this->assertSame($claims3['tests'], 'Soatok');
        $this->assertSame($claims4['tests'], 'Soatok');

        try {
            $paseto->decode($token1, 'dhole');
            $this->fail('Implicit assertions are not being validated');
        } catch (PasetoException $ex) {
            $this->assertSame('Token has been tampered with', $ex->getMessage());
        }
        try {
            $paseto->decode($token2, 'dhole');
            $this->fail('Implicit assertions are not being validated');
        } catch (PasetoException $ex) {
            $this->assertSame('Token has been tampered with', $ex->getMessage());
        }
        try {
            $paseto->decode($token3);
            $this->fail('Implicit assertions are not being validated');
        } catch (PasetoException $ex) {
            $this->assertSame('Token has been tampered with', $ex->getMessage());
        }
        try {
            $paseto->decode($token4);
            $this->fail('Implicit assertions are not being validated');
        } catch (PasetoException $ex) {
            $this->assertSame('Token has been tampered with', $ex->getMessage());
        }
    }
}
