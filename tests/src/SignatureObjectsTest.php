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
use Derafu\Signature\Translation\SignatureTranslationResourceProvider;
use Derafu\TestsSignature\Support\ReadsXml;
use Derafu\TestsSignature\Support\UsesXmlsec;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * The `Object` elements of a signature: they are signed, they are referenced by
 * their `Id`, and their digests are made with the signature in its place.
 */
#[CoversClass(Signature::class)]
#[CoversClass(SignatureService::class)]
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
#[CoversClass(SignatureValidationResult::class)]
#[CoversClass(SignatureException::class)]
#[CoversClass(SignatureTranslationResourceProvider::class)]
#[CoversClass(Algorithms::class)]
#[CoversClass(RawSignature::class)]
#[CoversClass(ReferenceData::class)]
#[CoversClass(ReferenceTarget::class)]
#[CoversClass(SignatureElements::class)]
#[CoversClass(SignatureOptions::class)]
final class SignatureObjectsTest extends TestCase
{
    use ReadsXml;
    use UsesXmlsec;

    private const XML = "<Root>\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n</Root>\n";

    private const PROPERTIES = '<p:Properties xmlns:p="urn:properties" Id="props-1"><p:Time>2026-01-01T00:00:00Z</p:Time></p:Properties>';

    protected function setUp(): void
    {
        $this->requireXmlsec();
    }

    /**
     * Gives the digest that a reference of the signature has.
     */
    private function digestOfReference(string $signed, string $uri): string
    {
        return $this->firstElement(
            $signed,
            '//*[local-name()="Reference"][@URI="' . $uri . '"]/*[local-name()="DigestValue"]'
        )->textContent;
    }

    public function testAnObjectIsInTheSignatureAfterItsKeyInfoWithItsAttributes(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'objects' => [[
                'xml' => self::PROPERTIES,
                'id' => 'object-1',
                'mime_type' => 'text/xml',
                'encoding' => 'http://www.w3.org/2000/09/xmldsig#base64',
            ]],
        ]);

        $this->assertMatchesRegularExpression(
            '#</KeyInfo><Object Id="object-1" MimeType="text/xml" Encoding="http://www.w3.org/2000/09/xmldsig\#base64">'
            . preg_quote(self::PROPERTIES, '#') . '</Object></Signature>#',
            $signed
        );
        $results = $this->service->validateXml($signed);
        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    public function testAnObjectOfAPrefixedSignatureHasThePrefix(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'signature_prefix' => 'ds',
            'objects' => [['xml' => self::PROPERTIES, 'id' => 'object-1']],
        ]);

        $this->assertStringContainsString('<ds:Object Id="object-1">' . self::PROPERTIES . '</ds:Object></ds:Signature>', $signed);
    }

    public function testTheContentOfAnObjectThatIsReferencedIsSignedWithTheSignatureInItsPlace(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'references' => [['uri' => '#A'], ['uri' => '#props-1']],
            'objects' => [['xml' => self::PROPERTIES]],
            'signature_prefix' => 'ds',
            'digest_algorithm' => 'sha256',
            'signature_algorithm' => 'rsa-sha256',
        ]);

        // The digest is the one of the element as it is in the signed document.
        $properties = $this->firstElement($signed, '//*[@Id="props-1"]');
        $this->assertSame(
            base64_encode(hash('sha256', $properties->C14N() ?: '', true)),
            $this->digestOfReference($signed, '#props-1')
        );
        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertTrue($this->verifyWithXmlsec($signed, 'ID Doc;Id urn:properties:Properties'));
    }

    public function testTheObjectAndTheDocumentAreSignedTogetherAndEitherChangeIsNotValid(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'references' => [['uri' => ''], ['uri' => '#props-1']],
            'objects' => [['xml' => self::PROPERTIES]],
        ]);

        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
        $this->assertFalse($this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $signed))[0]->isValid());
        $this->assertFalse($this->service->validateXml(str_replace('2026-01-01', '2027-01-01', $signed))[0]->isValid());
    }

    public function testTheObjectItselfCanBeTheReferenceByItsId(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'references' => [['uri' => '#object-1']],
            'objects' => [['xml' => self::PROPERTIES, 'id' => 'object-1']],
            'signature_prefix' => 'ds',
            'digest_algorithm' => 'sha256',
        ]);

        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertFalse($this->service->validateXml(str_replace('2026-01-01', '2027-01-01', $signed))[0]->isValid());
        $this->assertTrue($this->verifyWithXmlsec($signed, 'Id ' . self::DSIG . ':Object'));
    }

    public function testSeveralObjectsAreWrittenInOrder(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'references' => [['uri' => '#o-1'], ['uri' => '#o-2']],
            'objects' => [
                ['xml' => '<a:A xmlns:a="urn:a"/>', 'id' => 'o-1'],
                ['xml' => 'only text', 'id' => 'o-2'],
            ],
        ]);

        $this->assertStringContainsString('<Object Id="o-1"><a:A xmlns:a="urn:a"/></Object><Object Id="o-2">only text</Object>', $signed);
        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    public function testAnObjectThatIsNotReferencedIsPartOfTheSignatureAndTheValidationIgnoresIt(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'objects' => [['xml' => self::PROPERTIES]],
        ]);

        $results = $this->service->validateXml(str_replace('2026-01-01', '2027-01-01', $signed));

        $this->assertTrue($results[0]->isValid());
    }

    public function testASignatureWithAnObjectThatXmlsecSignsIsValidatedByTheLibrary(): void
    {
        $object = '<Object><p:Properties xmlns:p="urn:properties" Id="props-1"><p:Time>now</p:Time></p:Properties></Object>';
        $document = '<Root><Doc ID="A"><V>1</V></Doc>'
            . $this->template('ds', self::SIGNATURES['sha256'], self::C14N, [
                ['#A', self::DIGESTS['sha256'], [[self::C14N, '']]],
                ['#props-1', self::DIGESTS['sha256'], [[self::C14N, '']]],
            ], false, str_replace('<Object>', '<ds:Object>', str_replace('</Object>', '</ds:Object>', $object)))
            . '</Root>';

        $signed = $this->signWithXmlsec($document, 'ID Doc;Id urn:properties:Properties');

        $results = $this->service->validateXml($signed);
        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }
}
