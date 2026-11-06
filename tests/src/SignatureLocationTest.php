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
use DOMElement;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The place of the signature in the document is the one that the option
 * `signature_location` says; the rest of the document stays as it was.
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
final class SignatureLocationTest extends TestCase
{
    use ReadsXml;
    use UsesXmlsec;

    private const XML = '<Root xmlns="urn:root" xmlns:e="urn:e"><e:Extensions><e:Slot><e:Content/></e:Slot><e:Slot/></e:Extensions><Doc ID="A"><V>1</V></Doc></Root>';

    private const NAMESPACES = ['r' => 'urn:root', 'e' => 'urn:e'];

    protected function setUp(): void
    {
        $this->createService();
    }

    /**
     * Gives the path of the element of the signature in the document, with the
     * names of its ancestors, to know where it is.
     */
    private function pathOfTheSignature(string $signed): string
    {
        $node = $this->firstElement($signed, "//*[local-name()='Signature']");

        $path = [];
        for ($current = $node; $current instanceof DOMElement; $current = $current->parentNode) {
            $position = 1;
            for ($sibling = $current->previousSibling; $sibling !== null; $sibling = $sibling->previousSibling) {
                if ($sibling instanceof DOMElement) {
                    $position++;
                }
            }
            array_unshift($path, $current->localName . '[' . $position . ']');
        }

        return implode('/', $path);
    }

    /**
     * @return array<string, array{string, string, string}>
     */
    public static function positionProvider(): array
    {
        return [
            'last child by default' => ['last_child', '//e:Slot[1]', 'Root[1]/Extensions[1]/Slot[1]/Signature[2]'],
            'first child' => ['first_child', '//e:Slot[1]', 'Root[1]/Extensions[1]/Slot[1]/Signature[1]'],
            'before the element' => ['before', '//e:Slot[1]', 'Root[1]/Extensions[1]/Signature[1]'],
            'after the element' => ['after', '//e:Slot[1]', 'Root[1]/Extensions[1]/Signature[2]'],
            'in an empty element' => ['last_child', '//e:Slot[2]', 'Root[1]/Extensions[1]/Slot[2]/Signature[1]'],
        ];
    }

    #[DataProvider('positionProvider')]
    public function testTheSignatureIsWhereTheLocationSaysAndIsValid(string $position, string $xpath, string $expected): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'signature_location' => ['xpath' => $xpath, 'namespaces' => self::NAMESPACES, 'position' => $position],
        ]);

        $this->assertSame($expected, $this->pathOfTheSignature($signed));
        $results = $this->service->validateXml($signed);
        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    public function testTheLocationWithoutPositionIsTheLastChild(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'signature_location' => ['xpath' => '/r:Root', 'namespaces' => self::NAMESPACES],
        ]);

        $this->assertSame('Root[1]/Signature[3]', $this->pathOfTheSignature($signed));
    }

    public function testTheSignatureOfTheWholeDocumentInAnInnerElementIsValid(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'signature_location' => ['xpath' => '//e:Content', 'namespaces' => self::NAMESPACES],
            'signature_prefix' => 'ds',
            'digest_algorithm' => 'sha256',
        ]);

        $this->assertSame('Root[1]/Extensions[1]/Slot[1]/Content[1]/Signature[1]', $this->pathOfTheSignature($signed));
        $results = $this->service->validateXml($signed);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }

    public function testTheRestOfTheDocumentIsNotChangedByTheLocation(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'reference' => 'A',
            'signature_location' => ['xpath' => '//e:Content', 'namespaces' => self::NAMESPACES],
        ]);

        $this->assertSame(
            '<?xml version="1.0"?>' . "\n"
            . '<Root xmlns="urn:root" xmlns:e="urn:e"><e:Extensions><e:Slot><e:Content></e:Content></e:Slot><e:Slot/></e:Extensions>'
            . '<Doc ID="A"><V>1</V></Doc></Root>' . "\n",
            (string) preg_replace('#<Signature .*</Signature>#s', '', $signed)
        );
    }

    public function testASignatureThatXmlsecVerifiesGoesInAnInnerElement(): void
    {
        $this->requireXmlsec();

        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'signature_location' => ['xpath' => '//e:Content', 'namespaces' => self::NAMESPACES],
            'signature_prefix' => 'ds',
            'digest_algorithm' => 'sha256',
            'signature_algorithm' => 'rsa-sha256',
        ]);

        $this->assertTrue($this->verifyWithXmlsec($signed));
    }

    public function testTheElementThatTheLocationFindsIsOnlyOne(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('selects 2 elements, and it must select one');

        $this->service->signXml(self::XML, $this->certificate, [
            'signature_location' => ['xpath' => '//e:Slot', 'namespaces' => self::NAMESPACES],
        ]);
    }

    public function testALocationThatFindsNothingIsAnError(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('selects 0 elements, and it must select one');

        $this->service->signXml(self::XML, $this->certificate, [
            'signature_location' => ['xpath' => '//e:Nothing', 'namespaces' => self::NAMESPACES],
        ]);
    }

    public function testALocationThatIsNotAnXPathIsAnError(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('of the location of the signature is not valid');

        $this->service->signXml(self::XML, $this->certificate, [
            'signature_location' => ['xpath' => '//[', 'namespaces' => self::NAMESPACES],
        ]);
    }

    public function testAPrefixThatTheDocumentDeclaresInItsRootNeedsNoNamespaces(): void
    {
        $signed = $this->service->signXml(self::XML, $this->certificate, [
            'signature_location' => ['xpath' => '//e:Content'],
        ]);

        $this->assertSame('Root[1]/Extensions[1]/Slot[1]/Content[1]/Signature[1]', $this->pathOfTheSignature($signed));
    }

    public function testAPrefixThatIsNotDeclaredAnywhereIsAnError(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('of the location of the signature is not valid');

        $this->service->signXml(self::XML, $this->certificate, [
            'signature_location' => ['xpath' => '//z:Content'],
        ]);
    }

    #[DataProvider('beforeOrAfterTheRootProvider')]
    public function testTheSignatureIsNotPlacedBesideTheRoot(string $position): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('can not be placed before or after the root element');

        $this->service->signXml(self::XML, $this->certificate, [
            'signature_location' => ['xpath' => '/r:Root', 'namespaces' => self::NAMESPACES, 'position' => $position],
        ]);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function beforeOrAfterTheRootProvider(): array
    {
        return ['before' => ['before'], 'after' => ['after']];
    }

    public function testADocumentWithAnEmptyElementNamedSignatureHasOnlyTheNewSignature(): void
    {
        $xml = '<Root><Signature/><Doc ID="A"/></Root>';

        $signed = $this->service->signXml($xml, $this->certificate, ['reference' => 'A']);

        $this->assertSame(1, substr_count($signed, '<Signature xmlns='));
        $this->assertSame(1, substr_count($signed, '<Signature/>'));
        $results = $this->service->validateXml($signed);
        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isValid(), (string) $results[0]->getError()?->getMessage());
    }
}
