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
use Derafu\Xml\Service\XmlDecoder;
use Derafu\Xml\Service\XmlEncoder;
use Derafu\Xml\Service\XmlService;
use Derafu\Xml\Service\XmlValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Signature::class)]
#[CoversClass(SignatureService::class)]
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
class SignatureValidatorTest extends TestCase
{
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
        $xml = file_get_contents($this->fixturesDir . '/valid_signed.xml');

        $this->service->validateXml($xml);
        $this->assertTrue(true);
    }

    public function testValidateXmlWithoutSignatureThrows(): void
    {
        $this->expectException(SignatureException::class);

        $xml = file_get_contents($this->fixturesDir . '/unsigned.xml');
        $this->service->validateXml($xml);
    }

    public function testValidateXmlWithInvalidDigestValueThrows(): void
    {
        $this->expectException(SignatureException::class);

        $xml = file_get_contents($this->fixturesDir . '/invalid_signed.xml');
        $this->service->validateXml($xml);
    }

    public function testValidateXmlWithInvalidSignatureValueThrows(): void
    {
        $this->expectException(SignatureException::class);

        $xml = file_get_contents($this->fixturesDir . '/invalid_signature_value.xml');
        $this->service->validateXml($xml);
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
}
