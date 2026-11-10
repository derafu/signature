<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsSignature;

use Derafu\Signature\Service\SignatureGenerator;
use Derafu\Signature\Service\SignatureService;
use Derafu\Signature\Service\SignatureValidator;
use Derafu\Signature\Signature;
use Derafu\Signature\SignatureValidationResult;
use Derafu\Signature\Support\Algorithms;
use Derafu\Signature\Support\RawSignature;
use Derafu\Signature\Support\ReferenceData;
use Derafu\Signature\Support\ReferenceTarget;
use Derafu\Signature\Support\SignatureElements;
use Derafu\Signature\Support\SignatureOptions;
use Derafu\TestsSignature\Support\ReadsFixtures;
use Derafu\Xml\Service\XmlDecoder;
use Derafu\Xml\Service\XmlEncoder;
use Derafu\Xml\Service\XmlService;
use Derafu\Xml\Service\XmlValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Signature::class)]
#[CoversClass(SignatureService::class)]
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
#[CoversClass(SignatureValidationResult::class)]
#[UsesClass(ReferenceTarget::class)]
#[UsesClass(SignatureElements::class)]
#[UsesClass(Algorithms::class)]
#[UsesClass(RawSignature::class)]
#[UsesClass(ReferenceData::class)]
#[UsesClass(SignatureOptions::class)]
class SignatureSerializationTest extends TestCase
{
    use ReadsFixtures;

    private SignatureService $service;

    protected function setUp(): void
    {
        $xmlService = new XmlService(
            new XmlEncoder(),
            new XmlDecoder(),
            new XmlValidator()
        );
        $generator = new SignatureGenerator($xmlService);
        $this->service = new SignatureService(
            $generator,
            new SignatureValidator($generator, $xmlService)
        );
    }

    /**
     * @return array<SignatureValidationResult>
     */
    private function results(string $fixture): array
    {
        return $this->service->validateXml(
            $this->readFixture(__DIR__ . '/../fixtures/' . $fixture)
        );
    }

    public function testValidResultIsSerializedWithTheSignatureData(): void
    {
        $result = $this->results('valid_signed.xml')[0];

        $array = $result->toArray();

        $this->assertTrue($array['valid']);
        $this->assertNull($array['error']);
        $this->assertSame($result->getSignatureNode()->toArray(), $array['signature']);
        $this->assertNotEmpty($array['signature']['digest_value']);
        $this->assertNotEmpty($array['signature']['signature_value']);
        $this->assertNotEmpty($array['signature']['modulus']);
        $this->assertNotEmpty($array['signature']['exponent']);
        $this->assertNotEmpty($array['signature']['certificate']);
        $this->assertIsArray($array['signature']['signer']);
        $this->assertArrayHasKey('name', $array['signature']['signer']);
        $this->assertArrayNotHasKey('pkey', $array['signature']['signer']);
        $this->assertSame($array, $result->jsonSerialize());
        $this->assertSame(json_encode($array), json_encode($result));
    }

    public function testInvalidResultsAreSerializedWithTheError(): void
    {
        foreach (['invalid_signed.xml', 'invalid_signature_value.xml'] as $fixture) {
            $invalid = array_values(array_filter(
                $this->results($fixture),
                fn ($r) => !$r->isValid()
            ));
            $this->assertNotEmpty($invalid);

            $result = $invalid[0];
            $error = $result->getError();
            $this->assertNotNull($error);

            $array = $result->toArray();
            $arrayError = $array['error'];

            $this->assertFalse($array['valid']);
            $this->assertNotNull($arrayError);
            $this->assertSame($error->getMessage(), $arrayError['message']);
            $this->assertSame($error->getCode(), $arrayError['code']);
            $this->assertSame(
                array_map(strval(...), $error->getErrors()),
                $arrayError['errors']
            );
            $this->assertNotEmpty($array['signature']['signature_value']);
            $this->assertJson((string) json_encode($result));
        }
    }

    public function testSignatureWithoutDataHasNullsAndNoSigner(): void
    {
        $array = (new Signature())->toArray();

        $this->assertSame([
            'reference',
            'canonicalization_method',
            'signature_method',
            'digest_method',
            'digest_value',
            'signature_value',
            'modulus',
            'exponent',
            'certificate',
            'certificate_chain',
            'signer',
        ], array_keys($array));
        $this->assertNull($array['reference']);
        $this->assertNull($array['digest_value']);
        $this->assertNull($array['signature_value']);
        $this->assertNull($array['modulus']);
        $this->assertNull($array['certificate']);
        $this->assertSame([], $array['certificate_chain']);
        $this->assertNull($array['signer']);
        $this->assertSame(
            'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            $array['signature_method']
        );
        $this->assertSame($array, (new Signature())->jsonSerialize());
    }

    public function testSignatureWithReferenceAndUnreadableCertificate(): void
    {
        $signature = (new Signature())->setData([
            'Signature' => [
                'SignedInfo' => [
                    'Reference' => [
                        '@attributes' => ['URI' => '#ID1'],
                        'DigestValue' => 'abc',
                    ],
                ],
                'KeyInfo' => [
                    'X509Data' => [
                        'X509Certificate' => ['not a certificate', 'chain1', 'chain2'],
                    ],
                ],
            ],
        ]);

        $array = $signature->toArray();

        $this->assertSame('ID1', $array['reference']);
        $this->assertSame('abc', $array['digest_value']);
        $this->assertSame('not a certificate', $array['certificate']);
        $this->assertSame(['chain1', 'chain2'], $array['certificate_chain']);
        $this->assertNull($array['signer']);
    }
}
