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
use Derafu\Signature\Contract\SignatureGeneratorInterface;
use Derafu\Signature\Exception\SignatureException;
use Derafu\Signature\Service\SignatureGenerator;
use Derafu\Signature\Service\SignatureValidator;
use Derafu\Signature\Signature;
use Derafu\Translation\Contract\TranslatableInterface;
use Derafu\Xml\Exception\XmlException;
use Derafu\Xml\Service\XmlDecoder;
use Derafu\Xml\Service\XmlEncoder;
use Derafu\Xml\Service\XmlService;
use Derafu\Xml\Service\XmlValidator;
use Derafu\Xml\XmlDocument;
use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * What real input, or another implementation of a contract, can make happen: an
 * XML that can not be canonicalized, a certificate that has no content and a
 * generator of digests that does not look for the reference.
 */
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
#[CoversClass(Signature::class)]
#[CoversClass(SignatureException::class)]
final class SignatureEdgeCasesTest extends TestCase
{
    /**
     * An XML whose namespace is a relative URI is loaded by libxml, but it can
     * not be canonicalized (C14N), so it has no digest.
     */
    private const XML_THAT_CAN_NOT_BE_CANONICALIZED = '<?xml version="1.0"?><a xmlns="relative"><b ID="B1"/></a>';

    private XmlService $xmlService;

    protected function setUp(): void
    {
        $this->xmlService = new XmlService(
            new XmlEncoder(),
            new XmlDecoder(),
            new XmlValidator()
        );
    }

    public function testTheDigestOfAnXmlThatCanNotBeCanonicalizedIsAnException(): void
    {
        $generator = new SignatureGenerator($this->xmlService);
        $document = new XmlDocument();
        $document->loadXml(self::XML_THAT_CAN_NOT_BE_CANONICALIZED);

        $this->expectException(XmlException::class);
        $this->expectExceptionMessage('The XML could not be canonicalized.');

        $generator->generateXmlDigestValue($document);
    }

    public function testTheDigestOfAReferenceOfAnXmlThatCanNotBeCanonicalizedIsAnException(): void
    {
        $generator = new SignatureGenerator($this->xmlService);
        $document = new XmlDocument();
        $document->loadXml(self::XML_THAT_CAN_NOT_BE_CANONICALIZED);

        $this->expectException(XmlException::class);
        $this->expectExceptionMessage('The XML could not be canonicalized.');

        $generator->generateXmlDigestValue($document, '#B1');
    }

    public function testAnXmlThatCanNotBeCanonicalizedCanNotBeSigned(): void
    {
        $generator = new SignatureGenerator($this->xmlService);

        $this->expectException(XmlException::class);
        $this->expectExceptionMessage('The XML could not be canonicalized.');

        $generator->signXml(
            self::XML_THAT_CAN_NOT_BE_CANONICALIZED,
            $this->createStub(CertificateInterface::class)
        );
    }

    /**
     * A certificate is an implementation of a contract: one that has no content
     * (its certificate is an empty text) has nothing to put in the signature.
     */
    public function testACertificateWithoutContentCanNotSign(): void
    {
        $generator = new SignatureGenerator($this->xmlService);
        $certificate = $this->createStub(CertificateInterface::class);
        $certificate->method('getCertificate')->willReturn('');

        try {
            $generator->signXml('<?xml version="1.0"?><a><b/></a>', $certificate);
            $this->fail('It should have failed.');
        } catch (Throwable $e) {
            $this->assertInstanceOf(LogicException::class, $e);
            $this->assertInstanceOf(TranslatableInterface::class, $e);
            $this->assertSame(
                'It is not possible to generate the signature of the Signature node if the digital certificate is not assigned.',
                $e->getMessage()
            );
        }
    }

    /**
     * The validator receives any generator of digests. With one that does not
     * look for the reference in the XML there is no alternative digest to find,
     * and the digest that comes in the XML is the one that does not match.
     */
    public function testWithAGeneratorThatDoesNotFindTheReferenceThereIsNoAlternativeDigest(): void
    {
        $generator = $this->createStub(SignatureGeneratorInterface::class);
        $generator->method('generateXmlDigestValue')->willReturn('digest of the generator');
        $validator = new SignatureValidator($generator, $this->xmlService);
        $signature = (new Signature())->setData(['Signature' => ['SignedInfo' => ['Reference' => [
            '@attributes' => ['URI' => '#NotInTheXml'],
            'DigestValue' => 'digest of the xml',
        ]]]]);

        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('The DigestValue that comes in the XML "digest of the xml" for the reference "NotInTheXml" does not match');

        $validator->validateXmlDigestValue('<?xml version="1.0"?><a><b ID="B1"/></a>', $signature);
    }

    /**
     * What is in an XML that comes from outside is not controlled: a namespace
     * that is a relative URI in the `Signature` is an XML that can not be
     * canonicalized, so it can not be validated. It is an exception, not an
     * error of types.
     */
    public function testTheSignatureOfAnXmlThatComesFromOutsideCanNotBeCanonicalized(): void
    {
        $certificate = (new CertificateFaker(new CertificateLoader()))->createFake();
        $signed = (new SignatureGenerator($this->xmlService))
            ->signXml('<?xml version="1.0"?><a><b ID="B1"/></a>', $certificate, '#B1')
        ;
        $withRelativeNamespace = str_replace(
            '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">',
            '<Signature xmlns="relative">',
            $signed
        );
        $validator = new SignatureValidator(new SignatureGenerator($this->xmlService), $this->xmlService);

        $this->expectException(XmlException::class);
        $this->expectExceptionMessage('The XML could not be canonicalized.');

        $validator->validateXml($withRelativeNamespace);
    }

    public function testASignatureNamespaceThatIsARelativeUriCanNotBeSigned(): void
    {
        $certificate = (new CertificateFaker(new CertificateLoader()))->createFake();

        $this->expectException(XmlException::class);
        $this->expectExceptionMessage('The XML could not be canonicalized.');

        (new SignatureGenerator($this->xmlService))->signXml(
            '<?xml version="1.0"?><a><b/></a>',
            $certificate,
            signatureNamespace: 'relative'
        );
    }

    public function testASignedInfoThatCanNotBeCanonicalizedCanNotBeValidated(): void
    {
        $certificate = (new CertificateFaker(new CertificateLoader()))->createFake();
        $generator = new SignatureGenerator($this->xmlService);
        $validator = new SignatureValidator($generator, $this->xmlService);
        $signed = $generator->signXml('<?xml version="1.0"?><a><b ID="B1"/></a>', $certificate, '#B1');
        $document = new XmlDocument();
        $document->loadXml($signed);
        $signatureNode = $validator->createSignatureNode(
            $document->getTopLevelSignatureC14N() ?? ''
        );
        $signatureNode->getXml()->loadXml(str_replace(
            '<SignedInfo xmlns:xsi',
            '<SignedInfo xmlns="relative" xmlns:xsi',
            $signatureNode->getXml()->saveXml()
        ));

        $this->expectException(XmlException::class);
        $this->expectExceptionMessage('The XML could not be canonicalized.');

        $validator->validateXmlSignatureValue($signatureNode);
    }
}
