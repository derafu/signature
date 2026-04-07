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

use Derafu\Certificate\Contract\CertificateInterface;
use Derafu\Certificate\Service\CertificateFaker;
use Derafu\Certificate\Service\CertificateLoader;
use Derafu\Signature\Contract\SignatureServiceInterface;
use Derafu\Signature\Service\SignatureGenerator;
use Derafu\Signature\Service\SignatureService;
use Derafu\Signature\Service\SignatureValidator;
use Derafu\Signature\Signature;
use Derafu\Signature\SignatureValidationResult;
use Derafu\Xml\Exception\XmlException;
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
class SignatureServiceTest extends TestCase
{
    private string $fixturesDir;

    private SignatureServiceInterface $service;

    private CertificateInterface $certificate;

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

        $this->certificate = (new CertificateFaker(new CertificateLoader()))
            ->createFake()
        ;
    }

    public function testSignXmlStringIso88591(): void
    {
        $xml = file_get_contents($this->fixturesDir . '/unsigned.xml');

        $xmlSigned = $this->service->signXml($xml, $this->certificate);

        $this->assertStringContainsString('<Signature', $xmlSigned);
        $this->service->validateXml($xmlSigned);
    }

    public function testSignXmlObjectIso88591(): void
    {
        $xml = new XmlDocument();
        $xml->loadXml(file_get_contents($this->fixturesDir . '/unsigned.xml'));

        $xmlSigned = $this->service->signXml($xml, $this->certificate);

        $this->assertStringContainsString('<Signature', $xmlSigned);
        $this->service->validateXml($xmlSigned);
    }

    public function testSignXmlWithReferenceIso88591(): void
    {
        $xml = new XmlDocument();
        $xml->loadXml(file_get_contents($this->fixturesDir . '/unsigned.xml'));

        $xmlSigned = $this->service->signXml($xml, $this->certificate, 'Derafu_SetDoc');

        $this->assertStringContainsString('<Signature', $xmlSigned);
        $this->service->validateXml($xmlSigned);
    }

    public function testSignXmlStringIso88591WithSpecialChars(): void
    {
        $xml = file_get_contents($this->fixturesDir . '/unsigned_iso88591.xml');

        $xmlSigned = $this->service->signXml($xml, $this->certificate);

        $this->assertStringContainsString('<Signature', $xmlSigned);
        $this->service->validateXml($xmlSigned);
    }

    public function testSignXmlStringUtf8WithSpecialChars(): void
    {
        $xml = file_get_contents($this->fixturesDir . '/unsigned_utf8.xml');

        $xmlSigned = $this->service->signXml($xml, $this->certificate);

        $this->assertStringContainsString('<Signature', $xmlSigned);
        $this->service->validateXml($xmlSigned);
    }

    public function testSignXmlWithReferenceUtf8WithSpecialChars(): void
    {
        $xml = new XmlDocument();
        $xml->loadXml(file_get_contents($this->fixturesDir . '/unsigned_utf8.xml'));

        $xmlSigned = $this->service->signXml($xml, $this->certificate, 'Derafu_SetDoc');

        $this->assertStringContainsString('<Signature', $xmlSigned);
        $this->service->validateXml($xmlSigned);
    }

    public function testSignXmlWithCustomSignatureNamespace(): void
    {
        $xml = new XmlDocument();
        $xml->loadXml(file_get_contents($this->fixturesDir . '/unsigned.xml'));

        $customNamespace = 'http://www.sii.cl/SiiDte';
        $xmlSigned = $this->service->signXml(
            $xml,
            $this->certificate,
            'Derafu_SetDoc',
            $customNamespace
        );

        // The Signature element must carry the custom namespace.
        $this->assertStringContainsString(
            '<Signature xmlns="' . $customNamespace . '"',
            $xmlSigned
        );

        // The signature must remain mathematically valid with the custom namespace.
        $results = $this->service->validateXml($xmlSigned);
        $this->assertTrue(
            $results[0]->isValid(),
            $results[0]->getError()?->getMessage() ?? 'Signature is not valid.'
        );
    }

    public function testSignXmlWithInvalidReference(): void
    {
        $this->expectException(XmlException::class);

        $xml = new XmlDocument();
        $xml->loadXml(file_get_contents($this->fixturesDir . '/unsigned.xml'));

        $this->service->signXml($xml, $this->certificate, 'nonexistent_id');
    }

    public function testSignAndValidateRawData(): void
    {
        $data = 'hello world';
        $privateKey = $this->certificate->getPrivateKey();
        $publicKey = $this->certificate->getCertificate();

        $signature = $this->service->sign($data, $privateKey);

        $this->assertTrue($this->service->validate($data, $signature, $publicKey));
    }

    public function testValidateRawDataReturnsFalseForTamperedData(): void
    {
        $data = 'hello world';
        $privateKey = $this->certificate->getPrivateKey();
        $publicKey = $this->certificate->getCertificate();

        $signature = $this->service->sign($data, $privateKey);

        $this->assertFalse($this->service->validate('tampered data', $signature, $publicKey));
    }
}
