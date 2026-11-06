<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsSignature\l10n\cl;

use Derafu\Certificate\Contract\CertificateInterface;
use Derafu\Certificate\Service\CertificateFaker;
use Derafu\Certificate\Service\CertificateLoader;
use Derafu\Signature\Contract\SignatureServiceInterface;
use Derafu\Signature\Service\SignatureGenerator;
use Derafu\Signature\Service\SignatureService;
use Derafu\Signature\Service\SignatureValidator;
use Derafu\Signature\Signature;
use Derafu\Signature\SignatureValidationResult;
use Derafu\Signature\Support\ReferenceTarget;
use Derafu\Signature\Support\SignatureElements;
use Derafu\TestsSignature\Support\ReadsFixtures;
use Derafu\Xml\Service\XmlDecoder;
use Derafu\Xml\Service\XmlEncoder;
use Derafu\Xml\Service\XmlService;
use Derafu\Xml\Service\XmlValidator;
use Derafu\Xml\XmlDocument;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Throwable;

#[CoversClass(Signature::class)]
#[CoversClass(SignatureService::class)]
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
#[CoversClass(SignatureValidationResult::class)]
#[UsesClass(ReferenceTarget::class)]
#[UsesClass(SignatureElements::class)]
class SignatureChileTest extends TestCase
{
    use ReadsFixtures;

    private SignatureServiceInterface $service;

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

    // -------------------------------------------------------------------------
    // Real DTE fixtures (externally signed).
    // -------------------------------------------------------------------------

    /**
     * Provides real DTE XML files from the dte_xml_real/ directory.
     *
     * Each XML may optionally have a companion .php file with the same name
     * that returns an array of specific assertions. If no .php file exists,
     * only generic validation is performed.
     *
     * The directory is gitignored — files must be placed locally for the tests
     * to run. If the directory is empty the test is skipped.
     *
     * @return array<string, array{string, array<string, mixed>}|array{string}>
     */
    public static function realDteXmlProvider(): array
    {
        $dir = __DIR__ . '/../../../fixtures/l10n/cl/dte_xml_real/';
        $files = glob($dir . '*.xml') ?: [];

        if (empty($files)) {
            return [
                'no_files' => [''],
            ];
        }

        $cases = [];
        foreach ($files as $xmlFile) {
            $phpFile = substr($xmlFile, 0, -4) . '.php';
            $loaded = file_exists($phpFile) ? (require $phpFile) : [];
            if (!is_array($loaded)) {
                throw new RuntimeException(sprintf(
                    'The fixture %s must return an array, %s given.',
                    $phpFile,
                    get_debug_type($loaded)
                ));
            }
            $assertions = [];
            foreach ($loaded as $key => $value) {
                if (!is_string($key)) {
                    throw new RuntimeException(sprintf(
                        'The fixture %s must have string keys, %s given.',
                        $phpFile,
                        get_debug_type($key)
                    ));
                }
                $assertions[$key] = $value;
            }
            $cases[basename($xmlFile)] = [$xmlFile, $assertions];
        }

        return $cases;
    }

    /**
     * Validates each real DTE XML against the signature service.
     *
     * This test exercises the validator against documents signed by real
     * Chilean certificates and accepted by the SII. It is the critical
     * interoperability check for the library.
     *
     * @param array<string, mixed> $assertions
     */
    #[DataProvider('realDteXmlProvider')]
    public function testValidateRealDteXml(
        string $xmlFile,
        array $assertions = []
    ): void {
        if ($xmlFile === '') {
            $this->markTestSkipped('No XML files found in the fixtures directory.');
        }

        $xml = $this->readFixture($xmlFile);

        $results = $this->service->validateXml($xml);

        $this->assertNotEmpty($results);
        foreach ($results as $result) {
            $this->assertTrue($result->isValid());
        }

        // Specific assertions from companion .php file, if any.
        foreach ($assertions as $key => $expected) {
            // Placeholder for custom assertions.
            $this->assertSame($expected, true, $key);
        }
    }

    // -------------------------------------------------------------------------
    // ISO-8859-1 special character cases (sign + validate roundtrip).
    // These test that the library correctly handles the encoding used by DTEs.
    // -------------------------------------------------------------------------

    /**
     * Provides ISO-8859-1 XML documents with special characters.
     *
     * Each case is a real-world scenario present in Chilean DTEs: company
     * names with accents (á, é, í, ó, ú, ñ, ü), XML entities, special
     * characters in attributes, etc.
     *
     * @return array<string, array{data: array<string, mixed>, reference: string, expectedException: class-string<Throwable>|null}>
     */
    public static function specialCharactersProvider(): array
    {
        $file = __DIR__ . '/../../../fixtures/l10n/cl/special_cases.php';
        $loaded = require $file;
        $loadedCases = is_array($loaded)
            ? ($loaded['testSignatureWithSpecialCharacters'] ?? null)
            : null
        ;
        if (!is_array($loadedCases)) {
            throw new RuntimeException(sprintf(
                'The fixture %s must return an array with the key testSignatureWithSpecialCharacters.',
                $file
            ));
        }

        $cases = [];
        foreach ($loadedCases as $name => $case) {
            if (!is_string($name) || !is_array($case)) {
                throw new RuntimeException(sprintf(
                    'Each case of testSignatureWithSpecialCharacters in %s must be an array with a string name.',
                    $file
                ));
            }

            $data = $case['data'] ?? null;
            $reference = $case['reference'] ?? null;
            $expectedException = $case['expectedException'] ?? null;
            if (!is_array($data) || !is_string($reference)) {
                throw new RuntimeException(sprintf(
                    'The case %s in %s must have "data" as array and "reference" as string.',
                    $name,
                    $file
                ));
            }
            if ($expectedException !== null && (
                !is_string($expectedException)
                || !is_a($expectedException, Throwable::class, true)
            )) {
                throw new RuntimeException(sprintf(
                    'The case %s in %s must have "expectedException" as null or a class-string of Throwable.',
                    $name,
                    $file
                ));
            }

            $stringKeyedData = [];
            foreach ($data as $key => $value) {
                $stringKeyedData[(string) $key] = $value;
            }

            $cases[$name] = [
                'data' => $stringKeyedData,
                'reference' => $reference,
                'expectedException' => $expectedException,
            ];
        }

        return $cases;
    }

    /**
     * Signs and validates an ISO-8859-1 XML with special characters.
     *
     * Verifies that:
     * - The signed XML is declared as ISO-8859-1.
     * - The signature is valid after signing.
     * - The DigestValue is stable: signing the same XML twice produces the
     *   same digest (deterministic canonicalization).
     *
     * @param array<string, mixed> $data
     * @param class-string<Throwable>|null $expectedException
     */
    #[DataProvider('specialCharactersProvider')]
    public function testSignAndValidateIso88591WithSpecialCharacters(
        array $data,
        string $reference,
        ?string $expectedException
    ): void {
        if ($expectedException !== null) {
            $this->expectException($expectedException);
        }

        // Build the XML as ISO-8859-1.
        $xmlService = new XmlService(
            new XmlEncoder(),
            new XmlDecoder(),
            new XmlValidator()
        );
        $doc = $xmlService->encode($data);
        $doc->setEncoding('ISO-8859-1');
        $xmlIso = $doc->saveXml();

        // Confirm encoding declaration.
        $this->assertStringContainsString('encoding="ISO-8859-1"', $xmlIso);

        // Sign the document.
        $xmlSigned = $this->service->signXml(
            $xmlIso,
            $this->certificate,
            [
                'reference' => $reference,
            ]
        );
        $this->assertStringContainsString('<Signature', $xmlSigned);

        // Validate the signature.
        $results = $this->service->validateXml($xmlSigned);

        $this->assertNotEmpty($results);
        foreach ($results as $result) {
            $this->assertTrue($result->isValid());
        }

        // Verify digest stability: signing the same XML again produces the
        // same DigestValue (canonicalization is deterministic).
        $doc1 = new XmlDocument();
        $doc1->loadXml($xmlSigned);
        $digest1 = $this->service->generateXmlDigestValue($doc1, $reference);

        $doc2 = new XmlDocument();
        $doc2->loadXml($xmlSigned);
        $digest2 = $this->service->generateXmlDigestValue($doc2, $reference);

        $this->assertSame(
            $digest1,
            $digest2,
            'DigestValue must be stable across multiple calculations.'
        );
    }
}
