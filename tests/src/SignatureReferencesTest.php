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
use Derafu\Signature\Exception\SignatureException;
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
use Derafu\Xml\Exception\XmlException;
use Derafu\Xml\Service\XmlDecoder;
use Derafu\Xml\Service\XmlEncoder;
use Derafu\Xml\Service\XmlService;
use Derafu\Xml\Service\XmlValidator;
use Derafu\Xml\XmlDocument;
use DOMDocument;
use DOMElement;
use DOMNodeList;
use DOMXPath;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * Signatures with several references, references by any identifier attribute,
 * digest and signature algorithms, transforms (enveloped, XPath and the
 * canonicalization ones) and UBL documents.
 */
#[CoversClass(Signature::class)]
#[CoversClass(SignatureService::class)]
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
#[CoversClass(SignatureValidationResult::class)]
#[CoversClass(SignatureException::class)]
#[CoversClass(ReferenceTarget::class)]
#[CoversClass(SignatureElements::class)]
#[UsesClass(Algorithms::class)]
#[UsesClass(RawSignature::class)]
#[UsesClass(ReferenceData::class)]
#[UsesClass(SignatureOptions::class)]
final class SignatureReferencesTest extends TestCase
{
    use ReadsFixtures;

    private const DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    private const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';

    private const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    private const XPATH = 'http://www.w3.org/TR/1999/REC-xpath-19991116';

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
     * Gives the canonical form of what a reference points to, with DOM, to have
     * its digest independently of the code that validates.
     */
    private function c14nOf(string $xml, ?string $xpath = null, bool $exclusive = false, bool $withComments = false): string
    {
        $doc = new DOMDocument();
        $doc->preserveWhiteSpace = true;
        $doc->loadXML($xml);
        if ($xpath === null) {
            return $doc->C14N($exclusive, $withComments);
        }
        $nodes = (new DOMXPath($doc))->query($xpath);
        $this->assertInstanceOf(DOMNodeList::class, $nodes);
        $node = $nodes->item(0);
        $this->assertInstanceOf(DOMElement::class, $node);

        return $node->C14N($exclusive, $withComments);
    }

    /**
     * Builds the XML of a `Reference`.
     */
    private function reference(
        ?string $uri,
        string $data,
        string $hash = 'sha1',
        string $digestMethod = 'http://www.w3.org/2000/09/xmldsig#sha1',
        string $transforms = ''
    ): string {
        return '<ds:Reference' . ($uri !== null ? ' URI="' . $uri . '"' : '') . '>'
            . ($transforms !== '' ? '<ds:Transforms>' . $transforms . '</ds:Transforms>' : '')
            . '<ds:DigestMethod Algorithm="' . $digestMethod . '"></ds:DigestMethod>'
            . '<ds:DigestValue>' . base64_encode(hash($hash, $data, true)) . '</ds:DigestValue>'
            . '</ds:Reference>';
    }

    /**
     * Signs the references by hand, as other signing systems do, and puts the
     * signature in the last place of the document.
     *
     * @param string $xml Document, without the signature, with the root
     * `Root`.
     */
    private function sign(
        string $xml,
        string $references,
        string $signatureMethod = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
        int $algorithm = OPENSSL_ALGO_SHA1
    ): string {
        $signedInfo = '<ds:SignedInfo xmlns:ds="' . self::DSIG . '">'
            . '<ds:CanonicalizationMethod Algorithm="' . self::C14N . '"></ds:CanonicalizationMethod>'
            . '<ds:SignatureMethod Algorithm="' . $signatureMethod . '"></ds:SignatureMethod>'
            . $references
            . '</ds:SignedInfo>';
        $value = $this->service->sign(
            $this->c14nOf($signedInfo),
            $this->certificate->getPrivateKey(),
            $algorithm
        );

        $signature = '<ds:Signature xmlns:ds="' . self::DSIG . '">' . $signedInfo
            . '<ds:SignatureValue>' . $value . '</ds:SignatureValue>'
            . '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' . $this->certificate->getCertificate(true)
            . '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>'
            . '</ds:Signature>';

        return str_replace('</Root>', $signature . '</Root>', $xml);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function identifierAttributeProvider(): array
    {
        return [
            'ID' => ['ID'],
            'Id' => ['Id'],
            'id' => ['id'],
            'xml:id' => ['xml:id'],
        ];
    }

    #[DataProvider('identifierAttributeProvider')]
    public function testReferenceToAnElementWithAnyIdentifierAttribute(string $attribute): void
    {
        $xml = '<Root><Doc ' . $attribute . '="a"><V>1</V></Doc></Root>';
        $data = $this->c14nOf($xml, '//Doc');

        // One reference, and several.
        $one = $this->sign($xml, $this->reference('#a', $data));
        $two = $this->sign($xml, $this->reference('#a', $data) . $this->reference('#a', $data));

        foreach ([$one, $two] as $signed) {
            $results = $this->service->validateXml($signed);
            $this->assertCount(1, $results);
            $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
            $this->assertFalse(
                $this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $signed))[0]->isValid()
            );
        }
    }

    public function testElementWithTheAttributeOfTheSiiIsFoundBeforeTheOthers(): void
    {
        $xml = '<Root><A Id="a"><V>1</V></A><B ID="a"><V>2</V></B></Root>';

        $target = ReferenceTarget::find($this->xmlDocument($xml), '#a');

        $this->assertInstanceOf(DOMElement::class, $target);
        $this->assertSame('B', $target->localName);
        $this->assertNull(ReferenceTarget::find($this->xmlDocument($xml), 'b'));
    }

    private function xmlDocument(string $xml): XmlDocument
    {
        $doc = new XmlDocument();
        $doc->loadXml($xml);

        return $doc;
    }

    public function testElementWithIdentifierAttributeIsSigned(): void
    {
        $xml = "<Root>\n  <Doc Id=\"a\">\n    <V>1</V>\n  </Doc>\n</Root>\n";

        $signed = $this->service->signXml($xml, $this->certificate, ['reference' => 'a']);

        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
    }

    /**
     * @return array<string, array{string, string, string, int}>
     */
    public static function algorithmProvider(): array
    {
        return [
            'sha1' => ['sha1', 'http://www.w3.org/2000/09/xmldsig#sha1', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1', OPENSSL_ALGO_SHA1],
            'sha256' => ['sha256', 'http://www.w3.org/2001/04/xmlenc#sha256', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', OPENSSL_ALGO_SHA256],
            'sha384' => ['sha384', 'http://www.w3.org/2001/04/xmldsig-more#sha384', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384', OPENSSL_ALGO_SHA384],
            'sha512' => ['sha512', 'http://www.w3.org/2001/04/xmlenc#sha512', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512', OPENSSL_ALGO_SHA512],
        ];
    }

    #[DataProvider('algorithmProvider')]
    public function testDigestAndSignatureAlgorithms(string $hash, string $digestMethod, string $signatureMethod, int $algorithm): void
    {
        $xml = '<Root><Doc ID="a"><V>1</V></Doc></Root>';
        $data = $this->c14nOf($xml, '//Doc');
        $reference = $this->reference('#a', $data, $hash, $digestMethod);

        // One reference, and several.
        foreach ([$reference, $reference . $reference] as $references) {
            $signed = $this->sign($xml, $references, $signatureMethod, $algorithm);

            $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
            $this->assertFalse(
                $this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $signed))[0]->isValid()
            );
        }
    }

    public function testSignatureWithAnotherAlgorithmThanTheDeclaredIsNotValid(): void
    {
        $xml = '<Root><Doc ID="a"><V>1</V></Doc></Root>';
        $data = $this->c14nOf($xml, '//Doc');

        $signed = $this->sign(
            $xml,
            $this->reference('#a', $data),
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            OPENSSL_ALGO_SHA1
        );

        $this->assertFalse($this->service->validateXml($signed)[0]->isValid());
    }

    public function testUnsupportedDigestAlgorithmIsNotValid(): void
    {
        $xml = '<Root><Doc ID="a"><V>1</V></Doc></Root>';
        $data = $this->c14nOf($xml, '//Doc');

        $signed = $this->sign(
            $xml,
            $this->reference('#a', $data) . $this->reference('#a', $data, 'sha1', 'http://example.com/md5')
        );

        $error = $this->service->validateXml($signed)[0]->getError();
        $this->assertInstanceOf(SignatureException::class, $error);
        $this->assertStringContainsString('http://example.com/md5', $error->getMessage());
    }

    public function testReferenceWithoutDigestMethodUsesSha1(): void
    {
        $xml = '<Root><Doc ID="a"><V>1</V></Doc></Root>';
        $data = $this->c14nOf($xml, '//Doc');
        $withoutMethod = '<ds:Reference URI="#a"><ds:DigestValue>' . base64_encode(sha1($data, true)) . '</ds:DigestValue></ds:Reference>';

        $signed = $this->sign($xml, $withoutMethod . $withoutMethod);

        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
    }

    public function testReferenceWithoutDigestValueIsNotValid(): void
    {
        $xml = '<Root><Doc ID="a"><V>1</V></Doc></Root>';
        $data = $this->c14nOf($xml, '//Doc');
        $withoutValue = '<ds:Reference URI="#a"><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod></ds:Reference>';

        $signed = $this->sign($xml, $this->reference('#a', $data) . $withoutValue);

        $error = $this->service->validateXml($signed)[0]->getError();
        $this->assertInstanceOf(SignatureException::class, $error);
        $this->assertStringContainsString('DigestValue', $error->getMessage());
    }

    public function testReferenceToAnElementThatDoesNotExistThrows(): void
    {
        $xml = '<Root><Doc ID="a"><V>1</V></Doc></Root>';
        $data = $this->c14nOf($xml, '//Doc');
        $signed = $this->sign($xml, $this->reference('#a', $data) . $this->reference('#b', $data));

        $this->expectException(XmlException::class);

        $this->service->validateXml($signed);
    }

    public function testCanonicalizationTransformsOfTheReference(): void
    {
        $xml = '<Root xmlns:x="http://example.com/x"><Doc ID="a"><!--note--><V>1</V></Doc></Root>';
        $exclusive = 'http://www.w3.org/2001/10/xml-exc-c14n#';
        $transform = static fn (string $algorithm): string => '<ds:Transform Algorithm="' . $algorithm . '"></ds:Transform>';

        $references = [
            $this->reference('#a', $this->c14nOf($xml, '//Doc', true), transforms: $transform($exclusive)),
            $this->reference('#a', $this->c14nOf($xml, '//Doc', false, true), transforms: $transform(self::C14N . '#WithComments')),
            $this->reference('#a', $this->c14nOf($xml, '//Doc', true, true), transforms: $transform($exclusive . 'WithComments')),
        ];

        $signed = $this->sign($xml, implode('', $references));

        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
    }

    public function testWholeDocumentWithoutTheSignatureInSeveralReferences(): void
    {
        $xml = '<Root><Doc ID="a"><V>1</V></Doc></Root>';
        $withoutSignature = $this->c14nOf($xml);
        $envelopedTransform = '<ds:Transform Algorithm="' . self::ENVELOPED . '"></ds:Transform>';

        $signed = $this->sign(
            $xml,
            $this->reference('', $withoutSignature, transforms: $envelopedTransform)
            . $this->reference('#a', $this->c14nOf($xml, '//Doc'))
        );

        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
        $this->assertFalse(
            $this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $signed))[0]->isValid()
        );
    }

    /**
     * @return array<string, array{string|null, string}>
     */
    public static function xpathTransformProvider(): array
    {
        return [
            'whole document' => [null, 'true()'],
            'element' => ['#a', 'true()'],
            'whole document without the V' => [null, 'not(ancestor-or-self::V)'],
            'whole document, the expression uses here()' => [null, 'count(ancestor-or-self::ds:Signature | here()/ancestor::ds:Signature[1]) > count(ancestor-or-self::ds:Signature)'],
        ];
    }

    #[DataProvider('xpathTransformProvider')]
    public function testXPathTransform(?string $uri, string $expression): void
    {
        $xml = '<Root><Doc ID="a"><V>1</V><W>2</W></Doc></Root>';
        $xpathTransform = '<ds:Transform Algorithm="' . self::XPATH . '"><ds:XPath>' . htmlspecialchars($expression, ENT_XML1) . '</ds:XPath></ds:Transform>';
        $envelopedTransform = '<ds:Transform Algorithm="' . self::ENVELOPED . '"></ds:Transform>';

        // What each expression leaves, computed with DOM: the same document or
        // element, or the document without the V.
        $expected = match ($expression) {
            'not(ancestor-or-self::V)' => $this->c14nOf('<Root><Doc ID="a"><W>2</W></Doc></Root>'),
            default => $uri === null ? $this->c14nOf($xml) : $this->c14nOf($xml, '//Doc'),
        };

        $signed = $this->sign(
            $xml,
            $this->reference($uri, $expected, transforms: $envelopedTransform . $xpathTransform)
            . $this->reference('#a', $this->c14nOf($xml, '//Doc'))
        );

        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
        $this->assertFalse(
            $this->service->validateXml(str_replace('<W>2</W>', '<W>3</W>', $signed))[0]->isValid()
        );
    }

    public function testXPathTransformWithoutItsExpressionThrows(): void
    {
        $xml = '<Root><Doc ID="a"><V>1</V></Doc></Root>';
        $transform = '<ds:Transform Algorithm="' . self::XPATH . '"></ds:Transform>';
        $signed = $this->sign(
            $xml,
            $this->reference('#a', $this->c14nOf($xml, '//Doc'), transforms: $transform)
        );

        $error = $this->service->validateXml($signed)[0]->getError();

        $this->assertInstanceOf(SignatureException::class, $error);
        $this->assertStringContainsString('transforms', $error->getMessage());
    }

    public function testTransformsOfASignatureThatIsNotInTheDocumentCanNotBeApplied(): void
    {
        $xml = '<Root><Doc ID="a"><V>1</V></Doc></Root>';
        $transform = '<ds:Transform Algorithm="' . self::XPATH . '"><ds:XPath>true()</ds:XPath></ds:Transform>';
        $signed = $this->sign(
            $xml,
            $this->reference('#a', $this->c14nOf($xml, '//Doc'), transforms: $transform)
        );
        $signature = (string) preg_replace('#^.*?(<ds:Signature xmlns.*</ds:Signature>).*$#s', '$1', $signed);
        $node = $this->service->createSignatureNode($signature);

        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('transforms');

        $this->service->validateXmlDigestValue('<Root><Doc ID="a"><V>1</V></Doc></Root>', $node);
    }

    /**
     * Some signing systems declare a transform that is not one of XML Signature
     * (the Altova one) and sign the canonical form of the element, so the
     * transform that is not known is treated as that.
     */
    public function testUnknownTransformOfTheReferenceIsTreatedAsCanonicalization(): void
    {
        $xml = '<Root><Doc ID="a"><V>1</V></Doc></Root>';
        $transform = '<ds:Transform Algorithm="http://www.altova.com"></ds:Transform>';

        $signed = $this->sign($xml, $this->reference('#a', $this->c14nOf($xml, '//Doc'), transforms: $transform));

        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
        $this->assertFalse(
            $this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $signed))[0]->isValid()
        );
    }

    /**
     * A signed element that has inside another signed document, with the
     * unknown transform in both, as the books of the tax authority: the
     * signature of the outer element covers the signature of the inner one.
     */
    public function testElementThatContainsASignedDocumentIsValidated(): void
    {
        $transform = '<ds:Transform Algorithm="http://www.altova.com"></ds:Transform>';
        $inner = '<Root><Doc ID="a"><V>1</V></Doc></Root>';
        $signedInner = $this->sign($inner, $this->reference('#a', $this->c14nOf($inner, '//Doc'), transforms: $transform));
        $signedInner = str_replace(['<Root>', '</Root>'], ['<Inner>', '</Inner>'], $signedInner);
        $outer = '<Root><Outer ID="o"><Head>1</Head>' . $signedInner . '</Outer></Root>';

        $signed = $this->sign($outer, $this->reference('#o', $this->c14nOf($outer, '//Outer'), transforms: $transform));

        $results = $this->service->validateXml($signed);
        $this->assertCount(2, $results);
        $this->assertTrue($results[0]->isValid());
        $this->assertTrue($results[1]->isValid());

        // A change in the inner document invalidates both signatures.
        $changed = $this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $signed));
        $this->assertFalse($changed[0]->isValid());
        $this->assertFalse($changed[1]->isValid());

        // A change in the outer element only invalidates the outer signature.
        $changed = $this->service->validateXml(str_replace('<Head>1</Head>', '<Head>2</Head>', $signed));
        $this->assertTrue($changed[0]->isValid());
        $this->assertFalse($changed[1]->isValid());
    }

    /**
     * Some systems calculate the digest of the element with the exclusive
     * canonicalization, so the namespaces of its ancestors that it does not use
     * are not in it, even if the reference does not say it.
     */
    public function testDigestOfTheExclusiveCanonicalizationOfTheElementIsAccepted(): void
    {
        $xml = '<Root xmlns:q="urn:q" xmlns:r="urn:r"><Doc ID="a"><V>1</V></Doc></Root>';
        $this->assertNotSame($this->c14nOf($xml, '//Doc'), $this->c14nOf($xml, '//Doc', true));

        $signed = $this->sign($xml, $this->reference('#a', $this->c14nOf($xml, '//Doc', true)));

        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
        $this->assertFalse(
            $this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $signed))[0]->isValid()
        );
    }

    public function testReferencesOfTheSignatureNode(): void
    {
        $xml = '<Root><Doc ID="a"><V>1</V></Doc></Root>';
        $signed = $this->sign(
            $xml,
            $this->reference('', $this->c14nOf($xml), transforms: '<ds:Transform Algorithm="' . self::ENVELOPED . '"></ds:Transform><ds:Transform Algorithm="' . self::C14N . '"></ds:Transform>')
            . $this->reference('#a', $this->c14nOf($xml, '//Doc'), 'sha256', 'http://www.w3.org/2001/04/xmlenc#sha256')
        );
        $signature = (string) preg_replace('#^.*?(<ds:Signature xmlns.*</ds:Signature>).*$#s', '$1', $signed);

        $node = $this->service->createSignatureNode($signature);

        $references = $node->getReferences();
        $this->assertCount(2, $references);
        $this->assertNull($references[0]['uri']);
        $this->assertSame([self::ENVELOPED, self::C14N], $references[0]['transforms']);
        $this->assertSame('#a', $references[1]['uri']);
        $this->assertSame('http://www.w3.org/2001/04/xmlenc#sha256', $references[1]['digestMethod']);
        $this->assertSame([], $references[1]['transforms']);
        $this->assertNotNull($references[1]['digestValue']);
        $this->assertSame('http://www.w3.org/2000/09/xmldsig#rsa-sha1', $node->getSignatureMethod());
        $empty = (new Signature())->setData([]);
        $this->assertSame([], $empty->getReferences());
        $this->assertNull($empty->getSignatureMethod());
    }

    public function testReferencesOfASignatureThatIsNotArray(): void
    {
        $node = (new Signature())->setData(['Signature' => ['SignedInfo' => ['Reference' => ['text', [
            'DigestValue' => 'value',
            'Transforms' => ['Transform' => ['@attributes' => ['Algorithm' => self::XPATH]]],
        ]]]]]);

        $references = $node->getReferences();

        $this->assertCount(1, $references);
        $this->assertSame([self::XPATH], $references[0]['transforms']);
        $this->assertSame('value', $references[0]['digestValue']);
    }

    public function testTextOfElementsWithAttributes(): void
    {
        $node = (new Signature())->setData(['Signature' => [
            'SignatureValue' => ['@attributes' => ['Id' => 'v'], '@value' => 'value'],
            'KeyInfo' => ['X509Data' => ['X509Certificate' => [
                ['@attributes' => ['Id' => 'c1'], '@value' => 'signer'],
                ['@attributes' => ['Id' => 'c2'], '@value' => 'ca'],
            ]]],
        ]]);

        $this->assertSame('value', $node->getSignatureValue());
        $this->assertSame('signer', $node->getX509Certificate());
        $this->assertSame(['ca'], $node->getX509CertificateChain());

        $single = (new Signature())->setData(['Signature' => ['KeyInfo' => ['X509Data' => [
            'X509Certificate' => ['@attributes' => ['Id' => 'c'], '@value' => 'signer'],
        ]]]]);
        $this->assertSame('signer', $single->getX509Certificate());
        $this->assertSame([], $single->getX509CertificateChain());
    }

    public function testSignatureOfTheOfficialUblExampleIsValidated(): void
    {
        $xml = $this->readFixture(__DIR__ . '/../fixtures/ubl_official_enveloped.xml');

        $results = $this->service->validateXml($xml);

        // The `cac:Signature` of UBL is not an electronic signature.
        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid());
        $this->assertNull($results[0]->getError());
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function tamperedUblProvider(): array
    {
        return [
            'data of the document' => ['<cbc:ID>A00095678</cbc:ID>', '<cbc:ID>A00095679</cbc:ID>'],
            'signed properties' => ['<SigningTime>2010-11-26T18:00:00Z</SigningTime>', '<SigningTime>2010-11-27T18:00:00Z</SigningTime>'],
        ];
    }

    #[DataProvider('tamperedUblProvider')]
    public function testTamperedOfficialUblExampleIsNotValid(string $search, string $replace): void
    {
        $xml = $this->readFixture(__DIR__ . '/../fixtures/ubl_official_enveloped.xml');
        $this->assertStringContainsString($search, $xml);

        $results = $this->service->validateXml(str_replace($search, $replace, $xml));

        $this->assertFalse($results[0]->isValid());
    }

    public function testElementNamedSignatureThatIsNotAnElectronicSignatureIsIgnored(): void
    {
        $xml = '<Root xmlns:cac="urn:cac"><cac:Signature><cac:ID>1</cac:ID></cac:Signature></Root>';

        $this->assertSame([], SignatureElements::find($this->xmlDocument($xml)));

        $this->expectException(SignatureException::class);

        $this->service->validateXml($xml);
    }

    public function testSignatureElementsAreFoundByNamespaceOrBySignedInfo(): void
    {
        $xml = '<Root xmlns:o="urn:other">'
            . '<Signature xmlns="' . self::DSIG . '"/>'
            . '<o:Signature><o:SignedInfo/></o:Signature>'
            . '<o:Signature><o:Other/></o:Signature>'
            . '</Root>';

        $elements = SignatureElements::find($this->xmlDocument($xml));

        $this->assertCount(2, $elements);
        $result = $this->service->validateXml($xml);
        $this->assertFalse($result[0]->isValid());
        $this->assertFalse($result[1]->isValid());
    }
}
