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
use Derafu\TestsSignature\Support\ReadsFixtures;
use Derafu\TestsSignature\Support\UsesXmlsec;
use Derafu\Xml\XmlDocument;
use JsonException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * Signed documents that are kept as they are, to know that the signatures that
 * were valid keep being valid and the ones that are not valid keep not being
 * valid.
 *
 * They are made up documents that have the shapes that were found in real
 * signed documents (the signed element and what it has inside, the namespaces,
 * the encoding, the prefix of the signature, the transforms, the number of
 * signatures), signed by the library before the support of the prefix and of
 * the references of the signatures (`legacy_*`), by `xmlsec1` (`xmlsec_*`) and
 * by hand (the rest).
 *
 * `manifest.json` has, for each document, what it is, which of its signatures
 * are valid, and what happens to them when a part of the document changes.
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
final class SignatureFixturesTest extends TestCase
{
    use ReadsFixtures;
    use UsesXmlsec;

    private const DIRECTORY = __DIR__ . '/../fixtures/signed';

    protected function setUp(): void
    {
        $this->createService();
    }

    /**
     * @return array<string, array{signatures?: list<bool>, exception?: string, changes: list<array{search: string, replace: string, signatures: list<bool>}>}>
     */
    private static function manifest(): array
    {
        $json = file_get_contents(self::DIRECTORY . '/manifest.json');
        if ($json === false) {
            self::fail('The manifest of the fixtures could not be read.');
        }

        try {
            /** @var array<string, array{signatures?: list<bool>, exception?: string, changes: list<array{search: string, replace: string, signatures: list<bool>}>}> */
            return json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            self::fail($e->getMessage());
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function fixtureProvider(): array
    {
        $cases = [];
        foreach (array_keys(self::manifest()) as $file) {
            $cases[$file] = [$file];
        }

        return $cases;
    }

    /**
     * @return array<string, array{string, int}>
     */
    public static function changeProvider(): array
    {
        $cases = [];
        foreach (self::manifest() as $file => $fixture) {
            foreach ($fixture['changes'] as $index => $change) {
                $cases[$file . ': ' . $change['search']] = [$file, $index];
            }
        }

        return $cases;
    }

    /**
     * @return array<string, array{string}>
     */
    public static function signedFixtureProvider(): array
    {
        $cases = [];
        foreach (self::manifest() as $file => $fixture) {
            if (isset($fixture['signatures'])) {
                $cases[$file] = [$file];
            }
        }

        return $cases;
    }

    /**
     * Gives the validity of each signature of a document.
     *
     * @return list<bool>
     */
    private function validity(string $xml): array
    {
        return array_values(array_map(
            static fn (SignatureValidationResult $result): bool => $result->isValid(),
            $this->service->validateXml($xml)
        ));
    }

    public function testEveryFixtureIsInTheManifestAndTheOtherWayAround(): void
    {
        $files = array_map(
            static fn (string $path): string => basename($path),
            glob(self::DIRECTORY . '/*.xml') ?: []
        );
        $inManifest = array_keys(self::manifest());
        sort($files);
        sort($inManifest);

        $this->assertSame($inManifest, $files);
    }

    #[DataProvider('fixtureProvider')]
    public function testSignaturesOfTheFixture(string $file): void
    {
        $fixture = self::manifest()[$file];
        $xml = $this->readFixture(self::DIRECTORY . '/' . $file);

        if (isset($fixture['exception'])) {
            $this->expectException(SignatureException::class);
            $this->expectExceptionMessage($fixture['exception']);
            $this->validity($xml);

            return;
        }

        $this->assertSame($fixture['signatures'] ?? null, $this->validity($xml));
    }

    #[DataProvider('changeProvider')]
    public function testSignaturesOfTheFixtureThatIsChanged(string $file, int $index): void
    {
        $change = self::manifest()[$file]['changes'][$index];
        $xml = $this->readFixture(self::DIRECTORY . '/' . $file);
        $this->assertSame(1, substr_count($xml, $change['search']));

        $changed = str_replace($change['search'], $change['replace'], $xml);

        $this->assertSame($change['signatures'], $this->validity($changed));
    }

    /**
     * The spaces between the elements of a signed document are part of what is
     * signed. A document that is loaded in an `XmlDocument` and saved has to
     * keep them as they are: the signatures keep their validity.
     */
    #[DataProvider('signedFixtureProvider')]
    public function testFixtureLoadedAndSavedByAnXmlDocumentKeepsItsSignatures(string $file): void
    {
        $xml = $this->readFixture(self::DIRECTORY . '/' . $file);
        $document = new XmlDocument();
        $document->loadXml($xml);

        $saved = $document->saveXml();

        $this->assertSame(self::manifest()[$file]['signatures'] ?? null, $this->validity($saved));
    }

    /**
     * The same, validating the `XmlDocument` and not its text.
     */
    #[DataProvider('signedFixtureProvider')]
    public function testSignaturesOfTheFixtureThatIsAnXmlDocument(string $file): void
    {
        $document = new XmlDocument();
        $document->loadXml($this->readFixture(self::DIRECTORY . '/' . $file));

        $results = array_values(array_map(
            static fn (SignatureValidationResult $result): bool => $result->isValid(),
            $this->service->validateXml($document)
        ));

        $this->assertSame(self::manifest()[$file]['signatures'] ?? null, $results);
    }
}
