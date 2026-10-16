<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsSignature;

use Derafu\Signature\Contract\SignatureServiceInterface;
use Derafu\Signature\Exception\SignatureException;
use Derafu\Signature\Service\SignatureGenerator;
use Derafu\Signature\Service\SignatureService;
use Derafu\Signature\Service\SignatureValidator;
use Derafu\Signature\Signature;
use Derafu\Signature\SignatureValidationResult;
use Derafu\TestsSignature\Support\ReadsFixtures;
use Derafu\Xml\Exception\XmlQueryException;
use Derafu\Xml\Service\XmlDecoder;
use Derafu\Xml\Service\XmlEncoder;
use Derafu\Xml\Service\XmlService;
use Derafu\Xml\Service\XmlValidator;
use Derafu\Xml\XmlDocument;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Signature::class)]
#[CoversClass(SignatureService::class)]
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
#[CoversClass(SignatureValidationResult::class)]
class SignatureValidatorTest extends TestCase
{
    use ReadsFixtures;

    private string $fixturesDir;

    private SignatureServiceInterface $service;

    protected function setUp(): void
    {
        $this->fixturesDir = __DIR__ . '/../fixtures';

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

    public function testValidateExternallySignedXml(): void
    {
        $xml = $this->readFixture($this->fixturesDir . '/valid_signed.xml');

        $results = $this->service->validateXml($xml);

        $this->assertNotEmpty($results);
        foreach ($results as $result) {
            $this->assertTrue($result->isValid());
            $this->assertNull($result->getError());
        }
    }

    public function testValidateXmlWithoutSignatureThrows(): void
    {
        $this->expectException(SignatureException::class);

        $xml = $this->readFixture($this->fixturesDir . '/unsigned.xml');
        $results = $this->service->validateXml($xml);

        $this->assertNotEmpty($results);
        foreach ($results as $result) {
            $this->assertTrue($result->isValid());
        }
    }

    public function testValidateXmlWithInvalidDigestValueReturnsInvalidResult(): void
    {
        $xml = $this->readFixture($this->fixturesDir . '/invalid_signed.xml');

        $results = $this->service->validateXml($xml);

        $this->assertNotEmpty($results);
        $invalidResults = array_filter($results, fn ($r) => !$r->isValid());
        $this->assertNotEmpty($invalidResults);

        foreach ($invalidResults as $result) {
            $this->assertFalse($result->isValid());
            $this->assertInstanceOf(SignatureException::class, $result->getError());
        }
    }

    public function testValidateXmlWithInvalidSignatureValueReturnsInvalidResult(): void
    {
        $xml = $this->readFixture($this->fixturesDir . '/invalid_signature_value.xml');

        $results = $this->service->validateXml($xml);

        $this->assertNotEmpty($results);
        $invalidResults = array_filter($results, fn ($r) => !$r->isValid());
        $this->assertNotEmpty($invalidResults);

        foreach ($invalidResults as $result) {
            $this->assertFalse($result->isValid());
            $this->assertInstanceOf(SignatureException::class, $result->getError());
        }
    }

    public function testValidateXmlSignatureValueWithMissingSignatureValueThrows(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('The SignatureValue is missing from the signature node.');

        // A fresh Signature has empty SignatureValue, which getSignatureValue() returns as null.
        $signatureNode = new Signature();
        $this->service->validateXmlSignatureValue($signatureNode);
    }

    public function testValidateXmlSignatureValueWithMissingX509CertificateThrows(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('The X509Certificate is missing from the signature node.');

        // Set a dummy SignatureValue so the first guard passes, but leave X509Certificate empty.
        $signatureNode = new Signature();
        $signatureNode->setSignatureValue('dummyvalue');
        $this->service->validateXmlSignatureValue($signatureNode);
    }

    public function testValidateXmlOfADocumentWithoutRootElementThrows(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('Could not get the documentElement from the XML to validate its signature');

        (void) $this->service->validateXml(new XmlDocument());
    }

    public function testGenerateXmlDigestValueOfADocumentWithoutRootElementThrows(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('Could not get the documentElement from the XML to sign');

        (void) $this->service->generateXmlDigestValue(new XmlDocument());
    }

    public function testValidateXmlDigestValueWithoutDigestValueThrows(): void
    {
        $signatureNode = (new Signature())->setData([
            'Signature' => [
                'SignedInfo' => [
                    'Reference' => ['@attributes' => ['URI' => '#Derafu_SetDoc']],
                ],
            ],
        ]);

        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('The DigestValue is missing from the signature node.');

        $this->service->validateXmlDigestValue(
            $this->readFixture($this->fixturesDir . '/unsigned.xml'),
            $signatureNode
        );
    }

    public function testCreateSignatureNodeReadsTheSignatureOfAnXml(): void
    {
        $xml = $this->readFixture($this->fixturesDir . '/valid_signed.xml');
        $signatureXml = $this->service->validateXml($xml)[0]->getSignatureNode()->getXml()->saveXml();

        $signatureNode = $this->service->createSignatureNode($signatureXml);

        $this->assertNotNull($signatureNode->getDigestValue());
        $this->assertNotNull($signatureNode->getSignatureValue());
        $this->assertNotNull($signatureNode->getX509Certificate());
    }

    public function testValidateXmlSignatureValueOfAnXmlWithoutSignedInfoThrows(): void
    {
        $signatureNode = (new Signature())->setData(['Signature' => [
            'SignatureValue' => 'value',
            'KeyInfo' => ['X509Data' => ['X509Certificate' => 'certificate']],
        ]]);
        $xml = new XmlDocument();
        $xml->loadXml('<Signature><Other/></Signature>');
        $signatureNode->setXml($xml);

        $this->expectException(XmlQueryException::class);

        $this->service->validateXmlSignatureValue($signatureNode);
    }
}
