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
use Derafu\TestsSignature\Support\UsesXmlsec;
use Derafu\Xml\Exception\XmlException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The references of a signature and their transforms: several references, the
 * XPath with `here()`, the enveloped signature inside an element, the
 * canonicalizations, and the identifiers of the signature. What the library
 * signs `xmlsec1` verifies, and what `xmlsec1` signs the library validates.
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
final class SignatureTransformsTest extends TestCase
{
    use UsesXmlsec;

    private const UBL = '<?xml version="1.0" encoding="UTF-8"?>' . "\n"
        . '<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"'
        . ' xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"'
        . ' xmlns:ext="urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"'
        . ' xmlns:sig="urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2"'
        . ' xmlns:sac="urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2">'
        . '<ext:UBLExtensions><ext:UBLExtension><ext:ExtensionContent><sig:UBLDocumentSignatures>'
        . '<sac:SignatureInformation><cbc:ID>sig-1</cbc:ID></sac:SignatureInformation>'
        . '<sac:SignatureInformation><cbc:ID>sig-2</cbc:ID></sac:SignatureInformation>'
        . '</sig:UBLDocumentSignatures></ext:ExtensionContent></ext:UBLExtension></ext:UBLExtensions>'
        . '<cbc:ID>INV-1</cbc:ID><cbc:Note>a &amp; b &gt; c</cbc:Note></Invoice>';

    private const UBL_NAMESPACES = [
        'ext' => 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
        'sig' => 'urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2',
        'sac' => 'urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2',
    ];

    private const FLEXIBLE = 'count(ancestor-or-self::sig:UBLDocumentSignatures | here()/ancestor::sig:UBLDocumentSignatures[1]) > count(ancestor-or-self::sig:UBLDocumentSignatures)';

    private const FINAL = 'not(ancestor-or-self::ds:Signature)';

    private const XML = '<Root><Doc ID="A"><V>1</V><!-- a comment --></Doc><Other ID="B"><W>2</W></Other></Root>';

    protected function setUp(): void
    {
        $this->requireXmlsec();
    }

    /**
     * Options of the signature of a UBL document, with the XPath of the profile.
     *
     * @return array<string, mixed>
     */
    private function ublOptions(string $expression, int $slot = 1): array
    {
        return [
            'signature_prefix' => 'ds',
            'signature_location' => ['xpath' => '(//sac:SignatureInformation)[' . $slot . ']', 'namespaces' => self::UBL_NAMESPACES],
            'references' => [[
                'uri' => '',
                'transforms' => [
                    ['type' => 'xpath', 'expression' => $expression, 'namespaces' => self::UBL_NAMESPACES + ['ds' => self::DSIG]],
                    'c14n',
                ],
            ]],
            'digest_algorithm' => 'sha256',
            'signature_algorithm' => 'rsa-sha256',
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function xpathProvider(): array
    {
        return ['flexible' => [self::FLEXIBLE], 'final' => [self::FINAL]];
    }

    #[DataProvider('xpathProvider')]
    public function testADocumentSignedWithAnXPathTransformIsValidForTheLibraryAndXmlsec(string $expression): void
    {
        $signed = $this->service->signXml(self::UBL, $this->certificate, $this->ublOptions($expression));

        $results = $this->service->validateXml($signed);
        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertTrue($this->verifyWithXmlsec($signed));
    }

    #[DataProvider('xpathProvider')]
    public function testTamperedDataOfADocumentWithAnXPathTransformIsNotValid(string $expression): void
    {
        $signed = $this->service->signXml(self::UBL, $this->certificate, $this->ublOptions($expression));

        $results = $this->service->validateXml(str_replace('INV-1', 'INV-2', $signed));

        $this->assertFalse($results[0]->isValid());
        $this->assertFalse($this->verifyWithXmlsec(str_replace('INV-1', 'INV-2', $signed)));
    }

    #[DataProvider('xpathProvider')]
    public function testAnXPathTransformThatXmlsecSignsIsValidatedByTheLibrary(string $expression): void
    {
        $document = str_replace(
            '<sac:SignatureInformation><cbc:ID>sig-1</cbc:ID></sac:SignatureInformation>',
            '<sac:SignatureInformation><cbc:ID>sig-1</cbc:ID>'
            . $this->template('ds', self::SIGNATURES['sha256'], self::C14N, [
                ['', self::DIGESTS['sha256'], [[self::XPATH, $expression], [self::C14N, '']]],
            ])
            . '</sac:SignatureInformation>',
            str_replace('<Invoice ', '<Invoice xmlns:ds="' . self::DSIG . '" ', self::UBL)
        );

        $signed = $this->signWithXmlsec($document, 'ID Nothing');

        $results = $this->service->validateXml($signed);
        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    public function testTheFlexibleXPathAllowsAnotherSignatureAfterwards(): void
    {
        $first = $this->service->signXml(self::UBL, $this->certificate, $this->ublOptions(self::FLEXIBLE, 1));
        $both = $this->service->signXml($first, $this->certificate, $this->ublOptions(self::FLEXIBLE, 2));

        $results = $this->service->validateXml($both);

        $this->assertCount(2, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertTrue($results[1]->isValid(), (string) $results[1]->getError()?->getMessage());
        $this->assertTrue($this->verifyWithXmlsec($both, 'ID Nothing', 1));
        $this->assertTrue($this->verifyWithXmlsec($both, 'ID Nothing', 2));
    }

    public function testTheIdentifiersOfTheSignatureAndOfItsValueAreWritten(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'signature_id' => 'signature-1',
            'signature_value_id' => 'value-1',
        ]);

        $this->assertMatchesRegularExpression('#<Signature xmlns="[^"]+" Id="signature-1">#', $signed);
        $this->assertMatchesRegularExpression('#<SignatureValue Id="value-1">[A-Za-z0-9+/=\s]+</SignatureValue>#', $signed);
        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertTrue($this->verifyWithXmlsec($signed, 'ID Doc'));
    }

    public function testTheIdentifiersOfAPrefixedSignatureAreWritten(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'signature_prefix' => 'ds',
            'signature_id' => 'signature-1',
            'signature_value_id' => 'value-1',
        ]);

        $this->assertStringContainsString('<ds:Signature xmlns:ds="' . self::DSIG . '" Id="signature-1">', $signed);
        $this->assertStringContainsString('<ds:SignatureValue Id="value-1">', $signed);
        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    public function testASignatureThatSignsTheValueOfAnotherOneIsValid(): void
    {
        $first = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'signature_value_id' => 'value-1',
        ]);

        $both = $this->service->signXml($first, $this->certificate, [
            'references' => [['uri' => '#value-1', 'type' => 'urn:countersignature']],
            'signature_prefix' => 'ds',
            'digest_algorithm' => 'sha256',
            'signature_algorithm' => 'rsa-sha256',
        ]);

        $this->assertStringContainsString('Type="urn:countersignature"', $both);
        $results = $this->service->validateXml($both);
        $this->assertCount(2, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertTrue($results[1]->isValid(), (string) $results[1]->getError()?->getMessage());
        $this->assertTrue($this->verifyWithXmlsec($both, 'ID Doc;Id SignatureValue', 2));
    }

    public function testACountersignatureIsNotValidIfTheSignedValueChanges(): void
    {
        $first = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'signature_value_id' => 'value-1',
        ]);
        $both = $this->service->signXml($first, $this->certificate, [
            'references' => [['uri' => '#value-1']],
        ]);

        $changed = (string) preg_replace('#(<SignatureValue Id="value-1">)[A-Za-z0-9]#', '$1A', $both, 1);
        $changed = $changed === $both ? str_replace('<SignatureValue Id="value-1">A', '<SignatureValue Id="value-1">B', $both) : $changed;

        $results = $this->service->validateXml($changed);
        $this->assertFalse($results[1]->isValid());
    }

    public function testSeveralReferencesAreSignedWithTheirOwnDigestAlgorithm(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'references' => [
                ['uri' => '#A', 'digest_algorithm' => 'sha256'],
                ['uri' => '#B', 'digest_algorithm' => 'sha512', 'transforms' => ['exc_c14n']],
            ],
            'signature_prefix' => 'ds',
            'signature_algorithm' => 'rsa-sha256',
        ]);

        $this->assertSame(1, substr_count($signed, 'xmlenc#sha256'));
        $this->assertSame(1, substr_count($signed, 'xmlenc#sha512'));
        $results = $this->service->validateXml($signed);
        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertTrue($this->verifyWithXmlsec($signed, 'ID Doc;ID Other'));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function tamperedReferenceProvider(): array
    {
        return [
            'first reference' => ['<V>1</V>'],
            'second reference' => ['<W>2</W>'],
        ];
    }

    #[DataProvider('tamperedReferenceProvider')]
    public function testTamperedDataOfAnyReferenceIsNotValid(string $data): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'references' => [['uri' => '#A'], ['uri' => '#B']],
        ]);

        $results = $this->service->validateXml(str_replace($data, str_replace(['1', '2'], ['3', '4'], $data), $signed));

        $this->assertFalse($results[0]->isValid());
    }

    public function testSeveralReferencesThatXmlsecSignsAreValidatedByTheLibrary(): void
    {
        $document = '<Root><Doc ID="A"><V>1</V></Doc><Other ID="B"><W>2</W></Other>'
            . $this->template('', self::SIGNATURES['sha256'], self::C14N, [
                ['#A', self::DIGESTS['sha256'], [[self::C14N, '']]],
                ['#B', self::DIGESTS['sha512'], [[self::EXC_C14N, '']]],
            ])
            . '</Root>';

        $signed = $this->signWithXmlsec($document, 'ID Doc;ID Other');

        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    public function testAnElementWithTheEnvelopedSignatureInsideIsSignedAndValidated(): void
    {
        $document = '<Root><Doc ID="A"><V>1</V></Doc></Root>';

        $signed = $this->service->signXml($document, $this->certificate, [
            'references' => [['uri' => '#A', 'transforms' => ['enveloped', 'exc_c14n']]],
            'signature_location' => ['xpath' => '//Doc'],
            'signature_prefix' => 'ds',
            'digest_algorithm' => 'sha256',
            'signature_algorithm' => 'rsa-sha256',
        ]);

        $this->assertStringContainsString('</V><ds:Signature', $signed);
        $results = $this->service->validateXml($signed);
        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertTrue($this->verifyWithXmlsec($signed));
        $this->assertFalse($this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $signed))[0]->isValid());
    }

    public function testAnElementWithTheEnvelopedSignatureInsideThatXmlsecSignsIsValidatedByTheLibrary(): void
    {
        $document = '<Root><Doc ID="A"><V>1</V>'
            . $this->template('', self::SIGNATURES['sha256'], self::C14N, [
                ['#A', self::DIGESTS['sha256'], [[self::ENVELOPED, ''], [self::EXC_C14N, '']]],
            ])
            . '</Doc></Root>';

        $signed = $this->signWithXmlsec($document);

        $results = $this->service->validateXml($signed);
        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    public function testAnElementWithTheEnvelopedSignatureInsideAndSha1IsSignedAndValidated(): void
    {
        $signed = $this->service->signXml('<Root><Doc ID="A"><V>1</V></Doc></Root>', $this->certificate, [
            'references' => [['uri' => '#A', 'transforms' => ['enveloped', 'c14n']]],
            'signature_location' => ['xpath' => '//Doc'],
        ]);

        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
        $this->assertFalse($this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $signed))[0]->isValid());
        $this->assertTrue($this->verifyWithXmlsec($signed));
    }

    public function testAnElementWithTheEnvelopedSignatureInsideAndSha1ThatXmlsecSignsIsValidated(): void
    {
        $document = '<Root><Doc ID="A"><V>1</V>'
            . $this->template('', self::SIGNATURES['sha1'], self::C14N, [
                ['#A', self::DIGESTS['sha1'], [[self::ENVELOPED, ''], [self::C14N, '']]],
            ])
            . '</Doc></Root>';

        $signed = $this->signWithXmlsec($document);

        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    public function testTheCommentsOfAnElementAreNotPartOfWhatIsSigned(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'references' => [['uri' => '#A', 'transforms' => ['exc_c14n']]],
            'signature_prefix' => 'ds',
        ]);

        $changed = str_replace('a comment', 'other', $signed);

        $this->assertTrue($this->service->validateXml($changed)[0]->isValid());
        $this->assertTrue($this->verifyWithXmlsec($changed));
    }

    public function testAReferenceWithoutTransformsIsAnElementWithoutCanonicalization(): void
    {
        $signed = $this->service->signXml('<Root><Doc ID="A"><V>1</V></Doc></Root>', $this->certificate, [
            'references' => [['uri' => '#A', 'transforms' => []]],
        ]);

        $this->assertStringNotContainsString('<Transforms>', $signed);
        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    public function testTheIdOfAReferenceIsWritten(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'references' => [['uri' => '#A', 'id' => 'reference-1']],
        ]);

        $this->assertStringContainsString('<Reference URI="#A" Id="reference-1">', $signed);
        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    public function testAnXPathThatTheValidatorCanNotFindTheSignatureForIsAnError(): void
    {
        $signed = $this->service->signXml(self::UBL, $this->certificate, $this->ublOptions(self::FLEXIBLE));
        $signature = $this->service->createSignatureNode(
            (string) preg_replace('#^.*?(<ds:Signature.*</ds:Signature>).*$#s', '$1', $signed)
        );

        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('with the transforms of the reference was not found');

        $this->service->validateXmlDigestValue(
            '<Invoice xmlns:ds="' . self::DSIG . '"><x/></Invoice>',
            $signature
        );
    }

    public function testAnXPathTransformOfAnElementLeavesOutWhatTheExpressionExcludes(): void
    {
        $document = '<Root><Doc ID="A"><V>1</V><Note>n</Note></Doc></Root>';
        $options = [
            'references' => [[
                'uri' => '#A',
                'transforms' => [['type' => 'xpath', 'expression' => 'not(ancestor-or-self::Note)'], 'c14n'],
            ]],
            'signature_prefix' => 'ds',
            'digest_algorithm' => 'sha256',
            'signature_algorithm' => 'rsa-sha256',
        ];

        $signed = $this->service->signXml($document, $this->certificate, $options);

        // What the expression leaves out can change, what it does not, can not.
        $this->assertTrue($this->service->validateXml(str_replace('>n<', '>other<', $signed))[0]->isValid());
        $this->assertFalse($this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $signed))[0]->isValid());
        $this->assertTrue($this->verifyWithXmlsec($signed));
    }

    public function testTheEnvelopedSignatureAndAnXPathTogetherLeaveOutTheSignatureToo(): void
    {
        $signed = $this->service->signXml('<Root><Doc ID="A"><V>1</V></Doc></Root>', $this->certificate, [
            'references' => [[
                'uri' => '#A',
                'transforms' => ['enveloped', ['type' => 'xpath', 'expression' => 'not(ancestor-or-self::V)'], 'c14n'],
            ]],
            'signature_location' => ['xpath' => '//Doc'],
            'signature_prefix' => 'ds',
            'digest_algorithm' => 'sha256',
            'signature_algorithm' => 'rsa-sha256',
        ]);

        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertTrue($this->verifyWithXmlsec($signed));
    }

    public function testTheEnvelopedSignatureOfAnElementThatDoesNotHaveTheSignatureInsideChangesNothing(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'references' => [['uri' => '#B', 'transforms' => ['enveloped', 'c14n']]],
        ]);

        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertTrue($this->verifyWithXmlsec($signed, 'ID Other'));
    }

    public function testAReferenceToAnElementThatIsNotInTheDocumentCanNotBeSigned(): void
    {
        $this->expectException(XmlException::class);
        $this->expectExceptionMessage('No element with ID "nothing" was found in the XML document.');

        $this->service->signXml(self::XML, $this->certificate, ['references' => [['uri' => '#nothing']]]);
    }

    public function testASignatureWhoseXPathTransformHasNoXPathIsNotValid(): void
    {
        $signed = $this->service->signXml(self::UBL, $this->certificate, $this->ublOptions(self::FLEXIBLE));
        $withoutXPath = (string) preg_replace('#<ds:XPath .*?</ds:XPath>#s', '', $signed);

        $results = $this->service->validateXml($withoutXPath);

        $this->assertFalse($results[0]->isValid());
        $this->assertStringContainsString(
            'with the transforms of the reference was not found',
            (string) $results[0]->getError()?->getMessage()
        );
    }
}
