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
use Derafu\Signature\Support\Algorithms;
use Derafu\Signature\Support\RawSignature;
use Derafu\Signature\Support\ReferenceData;
use Derafu\Signature\Support\ReferenceTarget;
use Derafu\Signature\Support\SignatureElements;
use Derafu\Signature\Support\SignatureOptions;
use Derafu\TestsSignature\Support\UsesXmlsec;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * Envelopes that contain documents that were signed before putting them in the
 * envelope, and are signed as a whole: the structure of the electronic
 * documents that are sent to a tax authority in a package, where the signature
 * of the package covers elements that have signatures of their own.
 *
 * The documents are signed by the library and by `xmlsec1`, and validated by
 * both. Those that use `xmlsec1` are skipped if the command is not installed.
 *
 * The signature of each document is made alone, with the namespace of the
 * document, and then the document is put in an envelope that declares the same
 * namespace and, in some cases, other one more (`xsi`). `xmlsec1` verifies the
 * signature of a document in the envelope when the envelope does not add
 * namespaces to it. When it does, the document has other canonical form than
 * the one that was signed, so `xmlsec1` rejects its signature, and the library
 * does not: it validates it as the signature of a document that was embedded.
 */
#[CoversClass(Signature::class)]
#[CoversClass(SignatureService::class)]
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
#[CoversClass(SignatureValidationResult::class)]
#[CoversClass(ReferenceTarget::class)]
#[CoversClass(SignatureElements::class)]
#[UsesClass(Algorithms::class)]
#[UsesClass(RawSignature::class)]
#[UsesClass(ReferenceData::class)]
#[UsesClass(SignatureOptions::class)]
final class SignatureEnvelopeTest extends TestCase
{
    use UsesXmlsec;

    private const NAMESPACE = 'http://www.example.com/documents';

    private const XSI = ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"';

    private const IDS = 'ID Data;ID Set';

    protected function setUp(): void
    {
        $this->createService();
    }

    /**
     * Combinations of the encoding, the prefix of the signatures, if the
     * envelope adds the `xsi` namespace and the number of documents.
     *
     * @return array<string, array{string, string|null, bool, int}>
     */
    public static function envelopeProvider(): array
    {
        $cases = [];
        foreach (['ISO-8859-1', 'UTF-8'] as $encoding) {
            foreach ([null, 'ds'] as $prefix) {
                foreach ([false, true] as $xsi) {
                    foreach ([1, 2] as $documents) {
                        $cases[$encoding
                            . ', prefix ' . ($prefix ?? 'none')
                            . ($xsi ? ', with xsi' : ', without xsi')
                            . ', ' . $documents . ($documents === 1 ? ' document' : ' documents')] = [$encoding, $prefix, $xsi, $documents];
                    }
                }
            }
        }

        return $cases;
    }

    /**
     * Gives the text of a document, in the encoding.
     */
    private function text(int $number, string $encoding): string
    {
        $text = 'Óptica Ñuñoa ' . $number;

        return $encoding === 'UTF-8' ? $text : (string) mb_convert_encoding($text, $encoding, 'UTF-8');
    }

    /**
     * Gives a document to sign, alone, with its namespace.
     */
    private function document(int $number, string $encoding, string $place = ''): string
    {
        return '<?xml version="1.0" encoding="' . $encoding . "\"?>\n"
            . '<Document xmlns="' . self::NAMESPACE . "\" version=\"1.0\">\n"
            . '  <Data ID="D' . $number . "\">\n"
            . '    <Description>' . $this->text($number, $encoding) . "</Description>\n"
            . "  </Data>\n"
            . $place
            . "</Document>\n";
    }

    /**
     * Gives the envelope with the documents that were already signed. The
     * signature of the envelope goes in `%SIG%`.
     *
     * @param list<string> $documents
     */
    private function envelope(array $documents, string $encoding, bool $xsi, string $place = ''): string
    {
        $body = '';
        foreach ($documents as $document) {
            $body .= (string) preg_replace('/^<\?xml[^>]*\?>\s*/', '', $document);
        }

        return '<?xml version="1.0" encoding="' . $encoding . "\"?>\n"
            . '<Envelope xmlns="' . self::NAMESPACE . '"' . ($xsi ? self::XSI : '') . " version=\"1.0\">\n"
            . "<Set ID=\"Set\">\n"
            . "<Header version=\"1.0\"><Sender>76192083-9</Sender></Header>\n"
            . $body
            . "</Set>\n"
            . $place
            . "</Envelope>\n";
    }

    /**
     * Gives a package signed by the library: each document and the envelope.
     */
    private function signedByTheLibrary(string $encoding, ?string $prefix, bool $xsi, int $documents): string
    {
        $signed = [];
        for ($number = 1; $number <= $documents; $number++) {
            $signed[] = $this->service->signXml(
                $this->document($number, $encoding),
                $this->certificate,
                [
                    'reference' => 'D' . $number,
                    'signature_prefix' => $prefix,
                ]
            );
        }

        return $this->service->signXml(
            $this->envelope($signed, $encoding, $xsi),
            $this->certificate,
            [
                'reference' => 'Set',
                'signature_prefix' => $prefix,
            ]
        );
    }

    /**
     * Gives a package signed by `xmlsec1`: each document and the envelope.
     */
    private function signedByXmlsec(string $encoding, ?string $prefix, bool $xsi, int $documents): string
    {
        $signed = [];
        for ($number = 1; $number <= $documents; $number++) {
            $signed[] = $this->signDocumentWithXmlsec($number, $encoding, $prefix);
        }

        return $this->signEnvelopeWithXmlsec($this->envelope($signed, $encoding, $xsi, '%SIG%'), $prefix);
    }

    private function signDocumentWithXmlsec(int $number, string $encoding, ?string $prefix): string
    {
        $template = $this->template($prefix ?? '', self::SIGNATURES['sha1'], self::C14N, [
            ['#D' . $number, self::DIGESTS['sha1'], [[self::C14N, '']]],
        ], true);

        return $this->signWithXmlsec(
            str_replace('%SIG%', $template, $this->document($number, $encoding, "  %SIG%\n")),
            'ID Data'
        );
    }

    private function signEnvelopeWithXmlsec(string $envelope, ?string $prefix): string
    {
        $template = $this->template($prefix ?? '', self::SIGNATURES['sha1'], self::C14N, [
            ['#Set', self::DIGESTS['sha1'], [[self::C14N, '']]],
        ], true);

        return $this->signWithXmlsec(
            str_replace('%SIG%', $template, $envelope),
            'ID Data;ID Set',
            "/*/*[local-name()='Signature']"
        );
    }

    /**
     * Gives if each signature of a package is valid, in the order of the
     * document: the signatures of the documents and the one of the envelope.
     *
     * @return list<bool>
     */
    private function validity(string $package): array
    {
        return array_values(array_map(
            static fn (SignatureValidationResult $result): bool => $result->isValid(),
            $this->service->validateXml($package)
        ));
    }

    /**
     * Checks the signatures of a package, and that a change in a part of it
     * invalidates the signatures that cover that part.
     */
    private function assertPackageIsValidated(string $package, string $encoding, int $documents): void
    {
        $this->assertSame(array_fill(0, $documents + 1, true), $this->validity($package));

        // A change in the first document invalidates its signature and the one
        // of the envelope, that covers it. The other documents stay valid.
        $text = $this->text(1, $encoding);
        $changed = str_replace($text, $text . ' changed', $package);
        $expected = array_fill(0, $documents + 1, true);
        $expected[0] = false;
        $expected[$documents] = false;
        $this->assertSame($expected, $this->validity($changed));

        // A change in the header of the envelope only invalidates its own
        // signature.
        $expected = array_fill(0, $documents + 1, true);
        $expected[$documents] = false;
        $this->assertSame(
            $expected,
            $this->validity(str_replace('<Sender>76192083-9', '<Sender>76192083-0', $package))
        );
    }

    #[DataProvider('envelopeProvider')]
    public function testPackageSignedByTheLibraryIsValidated(string $encoding, ?string $prefix, bool $xsi, int $documents): void
    {
        $package = $this->signedByTheLibrary($encoding, $prefix, $xsi, $documents);

        $this->assertPackageIsValidated($package, $encoding, $documents);
    }

    #[DataProvider('envelopeProvider')]
    public function testPackageSignedByTheLibraryIsVerifiedByXmlsec(string $encoding, ?string $prefix, bool $xsi, int $documents): void
    {
        $this->requireXmlsec();
        $package = $this->signedByTheLibrary($encoding, $prefix, $xsi, $documents);

        // The signature of the envelope is always verified.
        $this->assertTrue($this->verifyWithXmlsec($package, self::IDS, $documents + 1));
        $this->assertFalse($this->verifyWithXmlsec(
            str_replace('<Sender>76192083-9', '<Sender>76192083-0', $package),
            self::IDS,
            $documents + 1
        ));

        // The ones of the documents are verified if the envelope does not add
        // namespaces to them.
        if (!$xsi) {
            for ($number = 1; $number <= $documents; $number++) {
                $this->assertTrue($this->verifyWithXmlsec($package, self::IDS, $number));
            }
        }
    }

    #[DataProvider('envelopeProvider')]
    public function testPackageSignedByXmlsecIsValidated(string $encoding, ?string $prefix, bool $xsi, int $documents): void
    {
        $this->requireXmlsec();
        $package = $this->signedByXmlsec($encoding, $prefix, $xsi, $documents);

        $this->assertPackageIsValidated($package, $encoding, $documents);
    }

    #[DataProvider('envelopeProvider')]
    public function testDocumentsSignedByXmlsecInAnEnvelopeSignedByTheLibraryAreValidated(
        string $encoding,
        ?string $prefix,
        bool $xsi,
        int $documents
    ): void {
        $this->requireXmlsec();
        $signed = [];
        for ($number = 1; $number <= $documents; $number++) {
            $signed[] = $this->signDocumentWithXmlsec($number, $encoding, $prefix);
        }

        $package = $this->service->signXml(
            $this->envelope($signed, $encoding, $xsi),
            $this->certificate,
            [
                'reference' => 'Set',
                'signature_prefix' => $prefix,
            ]
        );

        $this->assertPackageIsValidated($package, $encoding, $documents);
    }

    #[DataProvider('envelopeProvider')]
    public function testDocumentsSignedByTheLibraryInAnEnvelopeSignedByXmlsecAreValidated(
        string $encoding,
        ?string $prefix,
        bool $xsi,
        int $documents
    ): void {
        $this->requireXmlsec();
        $signed = [];
        for ($number = 1; $number <= $documents; $number++) {
            $signed[] = $this->service->signXml(
                $this->document($number, $encoding),
                $this->certificate,
                [
                    'reference' => 'D' . $number,
                    'signature_prefix' => $prefix,
                ]
            );
        }

        $package = $this->signEnvelopeWithXmlsec($this->envelope($signed, $encoding, $xsi, "%SIG%\n"), $prefix);

        $this->assertPackageIsValidated($package, $encoding, $documents);
    }
}
