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
use Derafu\Signature\Service\SignatureGenerator;
use Derafu\Signature\Service\SignatureService;
use Derafu\Signature\Service\SignatureValidator;
use Derafu\Signature\Signature;
use Derafu\Signature\SignatureValidationResult;
use Derafu\Signature\Support\ReferenceTarget;
use Derafu\Signature\Support\SignatureElements;
use Derafu\Translation\Exception\Logic\TranslatableInvalidArgumentException;
use Derafu\Xml\Service\XmlDecoder;
use Derafu\Xml\Service\XmlEncoder;
use Derafu\Xml\Service\XmlService;
use Derafu\Xml\Service\XmlValidator;
use Derafu\Xml\XmlDocument;
use DOMDocument;
use DOMElement;
use DOMXPath;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * Signatures whose elements have a namespace prefix (`ds:Signature`), signed
 * and validated, in documents with different namespaces.
 */
#[CoversClass(Signature::class)]
#[CoversClass(SignatureService::class)]
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
#[CoversClass(SignatureValidationResult::class)]
#[UsesClass(ReferenceTarget::class)]
#[UsesClass(SignatureElements::class)]
final class SignatureNamespacePrefixTest extends TestCase
{
    private const DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    private SignatureService $service;

    private CertificateInterface $certificate;

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
        $this->certificate = (new CertificateFaker(new CertificateLoader()))
            ->createFake()
        ;
    }

    /**
     * Documents with the namespaces that real XML have, signed with each
     * prefix and with and without reference.
     *
     * @return array<string, array{string, string|null, string|null}>
     */
    public static function signedDocumentProvider(): array
    {
        $documents = [
            'without namespaces' => "<Root>\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n</Root>\n",
            'default namespace' => "<Root xmlns=\"http://example.com/x\">\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n</Root>\n",
            'namespace of the signature declared in the root' => "<Root xmlns=\"http://example.com/x\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:ds=\"" . self::DSIG . "\">\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n</Root>\n",
        ];

        $cases = [];
        foreach ($documents as $name => $xml) {
            foreach ([null, 'ds', 'dsig'] as $prefix) {
                foreach (['A', null] as $reference) {
                    $cases[$name . ', prefix ' . ($prefix ?? 'none') . ', ' . ($reference === null ? 'whole document' : 'reference')] = [
                        $xml,
                        $prefix,
                        $reference,
                    ];
                }
            }
        }

        return $cases;
    }

    #[DataProvider('signedDocumentProvider')]
    public function testSignedXmlIsValidated(string $xml, ?string $prefix, ?string $reference): void
    {
        $signed = $this->service->signXml(
            $xml,
            $this->certificate,
            $reference,
            signaturePrefix: $prefix
        );

        $results = $this->service->validateXml($signed);

        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid());
        $this->assertNull($results[0]->getError());
    }

    public function testSignatureElementsAreNamedWithThePrefix(): void
    {
        $xml = "<Root>\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n</Root>\n";

        $signed = $this->service->signXml(
            $xml,
            $this->certificate,
            'A',
            signaturePrefix: 'ds'
        );

        $this->assertStringContainsString('<ds:Signature xmlns:ds="' . self::DSIG . '">', $signed);
        $this->assertStringContainsString('<ds:SignedInfo', $signed);
        $this->assertStringContainsString('<ds:X509Certificate>', $signed);
        $this->assertStringNotContainsString('<Signature', $signed);
        $this->assertStringNotContainsString('<SignedInfo', $signed);

        $doc = new DOMDocument();
        $doc->loadXML($signed);
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('ds', self::DSIG);
        $this->assertSame(1.0, $xpath->evaluate('count(/Root/ds:Signature/ds:SignedInfo/ds:Reference)'));
    }

    public function testSignatureNamespaceIsDeclaredWithThePrefix(): void
    {
        $xml = "<Root>\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n</Root>\n";

        $signed = $this->service->signXml(
            $xml,
            $this->certificate,
            'A',
            'http://example.com/signature',
            signaturePrefix: 'ds'
        );

        $this->assertStringContainsString('<ds:Signature xmlns:ds="http://example.com/signature">', $signed);
        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
    }

    public function testTamperedXmlWithPrefixedSignatureIsNotValid(): void
    {
        $xml = "<Root>\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n</Root>\n";
        $signed = $this->service->signXml($xml, $this->certificate, 'A', signaturePrefix: 'ds');

        $results = $this->service->validateXml(
            str_replace('<V>1</V>', '<V>2</V>', $signed)
        );

        $this->assertFalse($results[0]->isValid());
        $this->assertNotNull($results[0]->getError());
    }

    public function testTamperedSignedInfoWithPrefixedSignatureIsNotValid(): void
    {
        $xml = "<Root>\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n</Root>\n";
        $signed = $this->service->signXml($xml, $this->certificate, 'A', signaturePrefix: 'ds');

        $results = $this->service->validateXml(
            str_replace('<ds:Reference URI="#A">', '<ds:Reference URI="#A" Id="x">', $signed)
        );

        $this->assertFalse($results[0]->isValid());
    }

    public function testPrefixedSignatureNodeIsReadWithoutThePrefix(): void
    {
        $xml = "<Root>\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n</Root>\n";
        $signed = $this->service->signXml($xml, $this->certificate, 'A', signaturePrefix: 'ds');
        $doc = new DOMDocument();
        $doc->loadXML($signed);

        $node = $this->service->createSignatureNode(
            (string) $doc->saveXML($doc->getElementsByTagNameNS(self::DSIG, 'Signature')->item(0))
        );

        $this->assertSame('A', $node->getReference());
        $this->assertNotNull($node->getDigestValue());
        $this->assertNotNull($node->getSignatureValue());
        $this->assertSame($this->certificate->getCertificate(true), $node->getX509Certificate());
        $data = $node->toArray();
        $this->assertSame('A', $data['reference']);
        $this->assertNotNull($data['modulus']);
        $this->assertNotNull($data['signer']);
    }

    public function testPrefixCanBeChanged(): void
    {
        $node = (new Signature())->configureSignatureData(
            digestValue: 'digest',
            certificate: $this->certificate,
            reference: 'A',
            signaturePrefix: 'ds'
        );

        $node->configureSignatureData(
            digestValue: 'digest',
            certificate: $this->certificate,
            reference: 'A',
            signatureNamespace: 'http://example.com/signature',
            signaturePrefix: 'dsig'
        );

        $data = $node->getData();
        $this->assertSame(['dsig:Signature'], array_keys($data));
        $element = $data['dsig:Signature'];
        $this->assertIsArray($element);
        $this->assertSame(
            ['xmlns:dsig' => 'http://example.com/signature'],
            $element['@attributes']
        );
        $this->assertArrayHasKey('dsig:SignedInfo', $element);
        $this->assertSame('A', $node->getReference());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidPrefixProvider(): array
    {
        return [
            'empty' => [''],
            'with colon' => ['a:b'],
            'starts with a digit' => ['1a'],
            'with a space' => ['a b'],
            'xml' => ['xml'],
            'xmlns' => ['XMLNS'],
        ];
    }

    #[DataProvider('invalidPrefixProvider')]
    public function testInvalidPrefixThrows(string $prefix): void
    {
        $this->expectException(TranslatableInvalidArgumentException::class);

        (new Signature())->configureSignatureData(
            digestValue: 'digest',
            certificate: $this->certificate,
            signaturePrefix: $prefix
        );
    }

    /**
     * Some systems sign the `SignedInfo` as a fragment that does not declare
     * the prefix of its elements, and the SII accepts those signatures.
     */
    public function testSignatureOfSignedInfoWithoutNamespaceDeclarationsIsValidated(): void
    {
        $xml = "<Root>\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n</Root>\n";
        $signed = $this->service->signXml($xml, $this->certificate, 'A', signaturePrefix: 'ds');
        $doc = new DOMDocument();
        $doc->loadXML($signed);
        $signedInfo = $doc->getElementsByTagNameNS(self::DSIG, 'SignedInfo')->item(0);
        $value = $doc->getElementsByTagNameNS(self::DSIG, 'SignatureValue')->item(0);
        $this->assertInstanceOf(DOMElement::class, $signedInfo);
        $this->assertInstanceOf(DOMElement::class, $value);
        $fragment = preg_replace('/^(<ds:SignedInfo)[^>]*>/', '$1>', $signedInfo->C14N());
        $value->nodeValue = $this->service->sign((string) $fragment, $this->certificate->getPrivateKey());

        $results = $this->service->validateXml((string) $doc->saveXML());

        $this->assertTrue($results[0]->isValid());
    }

    /**
     * A document signed alone and embedded later in an envelope inherits the
     * namespaces of the envelope, which were not there when signing.
     */
    #[DataProvider('prefixProvider')]
    public function testDocumentSignedAloneAndEmbeddedInAnEnvelopeIsValidated(?string $prefix): void
    {
        $xml = "<Cal xmlns=\"http://example.com/cal\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n  <Doc ID=\"C1\">\n    <V>1</V>\n  </Doc>\n</Cal>\n";
        $signed = $this->service->signXml($xml, $this->certificate, 'C1', signaturePrefix: $prefix);
        $cal = (string) preg_replace('/^<\?xml[^>]*>\s*/', '', $signed);
        $envelope = "<Envelope xmlns=\"http://example.com/envelope\" xmlns:ds=\"" . self::DSIG . "\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n"
            . $cal
            . "</Envelope>\n";

        $results = $this->service->validateXml($envelope);

        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid());
        $this->assertFalse(
            $this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $envelope))[0]->isValid()
        );
    }

    /**
     * @return array<string, array{string|null}>
     */
    public static function prefixProvider(): array
    {
        return ['without prefix' => [null], 'with prefix' => ['ds']];
    }

    public function testAllTheSignaturesOfADocumentAreValidated(): void
    {
        $xml = "<Root>\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n</Root>\n";
        $first = $this->service->signXml($xml, $this->certificate, 'A', signaturePrefix: 'ds');
        $both = $this->service->signXml($first, $this->certificate, 'A');

        $results = $this->service->validateXml($both);

        $this->assertCount(2, $results);
        $this->assertTrue($results[0]->isValid());
        $this->assertTrue($results[1]->isValid());
    }

    public function testXmlDocumentObjectIsSignedWithPrefixOverTheWholeDocument(): void
    {
        $xml = new XmlDocument();
        $xml->loadXml("<Root>\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n</Root>\n");

        $signed = $this->service->signXml($xml, $this->certificate, null, signaturePrefix: 'ds');

        $this->assertStringContainsString('<ds:Signature', $signed);
        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
    }
}
