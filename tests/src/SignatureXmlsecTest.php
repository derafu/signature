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

use Derafu\Signature\Service\SignatureGenerator;
use Derafu\Signature\Service\SignatureService;
use Derafu\Signature\Service\SignatureValidator;
use Derafu\Signature\Signature;
use Derafu\Signature\SignatureValidationResult;
use Derafu\Signature\Support\ReferenceTarget;
use Derafu\Signature\Support\SignatureElements;
use Derafu\TestsSignature\Support\UsesXmlsec;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Documents signed by `xmlsec1`, an implementation of XML Signature that is not
 * this library, validated with the library, and documents signed by the
 * library, verified with `xmlsec1`.
 *
 * The tests are skipped if the `xmlsec1` command is not installed.
 */
#[CoversClass(Signature::class)]
#[CoversClass(SignatureService::class)]
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
#[CoversClass(SignatureValidationResult::class)]
#[CoversClass(ReferenceTarget::class)]
#[CoversClass(SignatureElements::class)]
final class SignatureXmlsecTest extends TestCase
{
    use UsesXmlsec;

    protected function setUp(): void
    {
        $this->requireXmlsec();
    }

    /**
     * Documents where the signature goes, with different namespaces, encodings
     * and identifier attributes. `%SIG%` is the place of the signature.
     *
     * @return array<string, string>
     */
    private static function documents(): array
    {
        $body = "<Root%NS%>\n  <Doc %ID%=\"A\">\n    <V>1</V>\n    <Glosa>Óptica Ñuñoa</Glosa>\n  </Doc>\n  %SIG%\n</Root>\n";
        $make = static fn (string $namespaces = '', string $id = 'ID', string $declaration = ''): string => $declaration
            . str_replace(['%NS%', '%ID%'], [$namespaces, $id], $body);
        $xsi = ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"';

        return [
            'compact' => '<Root><Doc ID="A"><V>1</V></Doc>%SIG%</Root>',
            'pretty' => $make(),
            'default namespace' => $make(' xmlns="http://example.com/x"'),
            'several namespaces' => $make(' xmlns="http://example.com/x"' . $xsi . ' xmlns:ds="' . self::DSIG . '"'),
            'embedded' => "<Env xmlns:ds=\"" . self::DSIG . "\" xmlns:q=\"urn:q\">\n  <Root xmlns=\"http://example.com/x\"" . $xsi . ">\n    <Doc ID=\"A\">\n      <V>1</V>\n    </Doc>\n    %SIG%\n  </Root>\n</Env>\n",
            'iso-8859-1' => (string) mb_convert_encoding($make('', 'ID', "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n"), 'ISO-8859-1', 'UTF-8'),
            'utf-8' => $make('', 'ID', "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"),
            'id attribute' => $make('', 'Id'),
        ];
    }

    /**
     * Gives the elements and the attributes that identify them of a document.
     */
    private static function idsOf(string $document): string
    {
        return $document === 'id attribute' ? 'Id Doc' : 'ID Doc';
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public static function xmlsecCaseProvider(): array
    {
        $cases = [];

        foreach (['sha1', 'sha256', 'sha384', 'sha512'] as $hash) {
            $cases['algorithm ' . $hash] = ['pretty', '', self::SIGNATURES[$hash], self::C14N, [['#A', self::DIGESTS[$hash], []]]];
        }

        foreach (array_keys(self::documents()) as $document) {
            foreach (['', 'ds'] as $prefix) {
                $name = $document . ', prefix ' . ($prefix !== '' ? $prefix : 'none');
                $cases[$name . ', element'] = [$document, $prefix, self::SIGNATURES['sha256'], self::C14N, [
                    ['#A', self::DIGESTS['sha256'], [[self::ENVELOPED, ''], [self::C14N, '']]],
                ]];
                $cases[$name . ', whole document'] = [$document, $prefix, self::SIGNATURES['sha256'], self::C14N, [
                    ['', self::DIGESTS['sha256'], [[self::ENVELOPED, '']]],
                ]];
            }
        }

        // The reference of the library: only the canonicalization.
        foreach (['', 'ds'] as $prefix) {
            $cases['canonicalization only, prefix ' . ($prefix !== '' ? $prefix : 'none')] = ['pretty', $prefix, self::SIGNATURES['sha1'], self::C14N, [
                ['#A', self::DIGESTS['sha1'], [[self::C14N, '']]],
            ]];
        }
        $cases['KeyValue in the KeyInfo'] = ['pretty', '', self::SIGNATURES['sha1'], self::C14N, [
            ['#A', self::DIGESTS['sha1'], [[self::C14N, '']]],
        ], true];
        $cases['exclusive canonicalization'] = ['several namespaces', 'ds', self::SIGNATURES['sha256'], self::EXC_C14N, [
            ['#A', self::DIGESTS['sha256'], [[self::EXC_C14N, '']]],
        ]];
        $cases['canonicalization with comments'] = ['pretty', '', self::SIGNATURES['sha256'], self::C14N, [
            ['#A', self::DIGESTS['sha256'], [[self::C14N . '#WithComments', '']]],
        ]];
        $cases['two references'] = ['pretty', '', self::SIGNATURES['sha256'], self::C14N, [
            ['#A', self::DIGESTS['sha256'], []],
            ['', self::DIGESTS['sha1'], [[self::ENVELOPED, '']]],
        ]];
        $cases['XPath transform over the whole document'] = ['pretty', 'ds', self::SIGNATURES['sha256'], self::C14N, [
            ['', self::DIGESTS['sha256'], [[self::XPATH, 'not(ancestor-or-self::ds:Signature)']]],
        ]];
        $cases['XPath transform with here()'] = ['pretty', 'ds', self::SIGNATURES['sha256'], self::C14N, [
            ['', self::DIGESTS['sha256'], [[self::XPATH, 'count(ancestor-or-self::ds:Signature | here()/ancestor::ds:Signature[1]) &gt; count(ancestor-or-self::ds:Signature)']]],
        ]];

        // The structure of the signatures of UBL (XAdES): the signed properties
        // are in an `Object` of the signature, with an `Id`, and the signature
        // has two references.
        $properties = '<%q%Object><QualifyingProperties><SignedProperties Id="props"><SigningTime>2020-01-01T00:00:00Z</SigningTime></SignedProperties></QualifyingProperties></%q%Object>';
        foreach (['', 'ds'] as $prefix) {
            $cases['signed properties in an Object, prefix ' . ($prefix !== '' ? $prefix : 'none')] = ['pretty', $prefix, self::SIGNATURES['sha256'], self::C14N, [
                ['#A', self::DIGESTS['sha256'], [[self::ENVELOPED, ''], [self::C14N, '']]],
                ['#props', self::DIGESTS['sha256'], []],
            ], true, $properties, 'ID Doc;Id SignedProperties'];
        }

        return $cases;
    }

    /**
     * @param list<array{string, string, list<array{string, string}>}> $references
     */
    #[DataProvider('xmlsecCaseProvider')]
    public function testDocumentSignedByXmlsecIsValidated(
        string $document,
        string $prefix,
        string $signatureMethod,
        string $canonicalization,
        array $references,
        bool $keyValue = false,
        string $object = '',
        ?string $ids = null
    ): void {
        $template = str_replace(
            '%q%',
            $prefix !== '' ? $prefix . ':' : '',
            $this->template($prefix, $signatureMethod, $canonicalization, $references, $keyValue, $object)
        );
        $signed = $this->signWithXmlsec(
            str_replace('%SIG%', $template, self::documents()[$document]),
            $ids ?? self::idsOf($document)
        );

        $results = $this->service->validateXml($signed);

        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
        $this->assertFalse(
            $this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $signed))[0]->isValid()
        );
    }

    public function testXPathTransformThatLeavesOutTheDataIsNotAffectedByItsChange(): void
    {
        $template = $this->template('ds', self::SIGNATURES['sha256'], self::C14N, [
            ['#A', self::DIGESTS['sha256'], [[self::XPATH, 'not(ancestor-or-self::V)']]],
        ]);
        $signed = $this->signWithXmlsec(str_replace('%SIG%', $template, self::documents()['pretty']));

        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
        $this->assertTrue(
            $this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $signed))[0]->isValid()
        );
    }

    /**
     * Gives a document without the place of the signature.
     */
    private function unsigned(string $document): string
    {
        return (string) preg_replace('/\s*%SIG%/', '', $document);
    }

    /**
     * @return array<string, array{string, string|null, string|null}>
     */
    public static function libraryCaseProvider(): array
    {
        $cases = [];

        foreach (array_keys(self::documents()) as $document) {
            foreach ([null, 'ds', 'dsig'] as $prefix) {
                foreach (['A', null] as $reference) {
                    $name = $document
                        . ', prefix ' . ($prefix ?? 'none')
                        . ', ' . ($reference === null ? 'whole document' : 'element');
                    $cases[$name] = [$document, $prefix, $reference];
                }
            }
        }

        return $cases;
    }

    #[DataProvider('libraryCaseProvider')]
    public function testDocumentSignedByTheLibraryIsVerifiedByXmlsec(
        string $document,
        ?string $prefix,
        ?string $reference
    ): void {
        $signed = $this->service->signXml(
            $this->unsigned(self::documents()[$document]),
            $this->certificate,
            $reference,
            signaturePrefix: $prefix
        );
        $ids = self::idsOf($document);

        $this->assertTrue($this->verifyWithXmlsec($signed, $ids));
        $this->assertFalse(
            $this->verifyWithXmlsec(str_replace('<V>1</V>', '<V>2</V>', $signed), $ids)
        );
        // And the library validates it.
        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
    }

    public function testDocumentSignedByTheLibraryWithTheCertificateChainIsVerifiedByXmlsec(): void
    {
        $signed = $this->service->signXml(
            $this->unsigned(self::documents()['pretty']),
            $this->certificate,
            'A',
            includeCertificateChain: true
        );

        $this->assertGreaterThan(1, substr_count($signed, '<X509Certificate>'));
        $this->assertTrue($this->verifyWithXmlsec($signed));
    }

    public function testDocumentWithSeveralSignaturesIsVerifiedByXmlsec(): void
    {
        $first = $this->service->signXml(
            $this->unsigned(self::documents()['pretty']),
            $this->certificate,
            'A',
            signaturePrefix: 'ds'
        );
        $both = $this->service->signXml($first, $this->certificate, 'A');

        $this->assertTrue($this->verifyWithXmlsec($both, 'ID Doc', 1));
        $this->assertTrue($this->verifyWithXmlsec($both, 'ID Doc', 2));
        $this->assertCount(2, $this->service->validateXml($both));
    }

    public function testDocumentSignedByXmlsecAndSignedAgainByTheLibraryIsVerifiedByXmlsec(): void
    {
        $template = $this->template('', self::SIGNATURES['sha256'], self::C14N, [
            ['#A', self::DIGESTS['sha256'], [[self::C14N, '']]],
        ]);
        $byXmlsec = $this->signWithXmlsec(str_replace('%SIG%', $template, self::documents()['pretty']));

        $both = $this->service->signXml($byXmlsec, $this->certificate, 'A', signaturePrefix: 'ds');

        $this->assertTrue($this->verifyWithXmlsec($both, 'ID Doc', 1));
        $this->assertTrue($this->verifyWithXmlsec($both, 'ID Doc', 2));
        $this->assertCount(2, $this->service->validateXml($both));
    }
}
