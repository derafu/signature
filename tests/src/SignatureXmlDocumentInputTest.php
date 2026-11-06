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
use Derafu\Xml\Contract\XmlDocumentInterface;
use Derafu\Xml\Service\XmlEncoder;
use Derafu\Xml\XmlDocument;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * The documents that are given as an `XmlDocument`: the document that is signed
 * or validated is the one that the object saves with its own format settings.
 * The format of the XML is not changed, and it is the responsibility of whoever
 * has the object.
 */
#[CoversClass(Signature::class)]
#[CoversClass(SignatureService::class)]
#[CoversClass(SignatureGenerator::class)]
#[CoversClass(SignatureValidator::class)]
#[CoversClass(SignatureValidationResult::class)]
#[CoversClass(ReferenceTarget::class)]
#[CoversClass(SignatureElements::class)]
final class SignatureXmlDocumentInputTest extends TestCase
{
    use UsesXmlsec;

    protected function setUp(): void
    {
        $this->createService();
    }

    private function isValid(XmlDocumentInterface|string $xml): bool
    {
        $results = $this->service->validateXml($xml);

        return $results !== [] && $results[0]->isValid();
    }

    /**
     * Gives the XML of a document without its signature and without the
     * declaration.
     */
    private function withoutSignature(string $xml): string
    {
        return trim((string) preg_replace(
            ['/^<\?xml[^>]*\?>\s*/', '#<Signature\b.*</Signature>#s'],
            '',
            $xml
        ));
    }

    /**
     * The document that the encoder builds is saved with format, because the
     * encoder asks for it. It is signed as it is saved, and the signed XML is
     * valid wherever it is used: in the same object, in another one and in a
     * file.
     */
    public function testDocumentOfTheEncoderIsSignedAsItIsSaved(): void
    {
        $document = (new XmlEncoder())->encode(['Root' => [
            'Set' => ['@attributes' => ['ID' => 'A'], 'Header' => 'Óptica', 'Body' => ['Item' => ['1', '2']]],
        ]]);
        $unsigned = $document->saveXml();
        $this->assertStringContainsString("\n  <Set ID=\"A\">", $unsigned);

        $signed = $this->service->signXml($document, $this->certificate, 'A');

        $this->assertTrue($this->isValid($signed));
        $this->assertSame($this->withoutSignature($unsigned), $this->withoutSignature($signed));

        // The same object loads the signed XML and is used.
        $document->loadXml($signed);
        $this->assertTrue($document->getDomDocument()->formatOutput);
        $this->assertTrue($this->isValid($document->saveXml()));
        $this->assertTrue($this->isValid($document->getXml()));
        $this->assertTrue($this->isValid($document));

        // Another object loads it and saves it.
        $other = new XmlDocument();
        $other->loadXml($signed);
        $this->assertTrue($this->isValid($other->saveXml()));

        // A file.
        $file = tempnam(sys_get_temp_dir(), 'derafu-signature-');
        $this->assertIsString($file);
        file_put_contents($file, $signed);
        $this->assertTrue($this->isValid((string) file_get_contents($file)));
        unlink($file);
    }

    /**
     * A document that was loaded is signed as it was loaded: if it has no
     * spaces between its elements it is not formatted.
     */
    public function testLoadedDocumentIsSignedAsItWasLoaded(): void
    {
        $xml = '<Root><Set ID="A"><Header>1</Header><Body><Item>1</Item></Body></Set></Root>';
        $document = new XmlDocument();
        $document->loadXml($xml);

        $signed = $this->service->signXml($document, $this->certificate, 'A');

        $this->assertTrue($this->isValid($signed));
        $this->assertSame($xml, $this->withoutSignature($signed));
    }

    /**
     * A document that is asked to have format is signed with the format that it
     * saves: it is the one that the user has.
     */
    public function testDocumentThatIsAskedToHaveFormatIsSignedWithIt(): void
    {
        $document = new XmlDocument();
        $document->loadXml('<Root><Set ID="A"><Header>1</Header></Set></Root>');
        $document->setFormatOutput(true);
        $unsigned = $document->saveXml();
        $this->assertStringContainsString("\n  <Set ID=\"A\">", $unsigned);

        $signed = $this->service->signXml($document, $this->certificate, 'A');

        $this->assertTrue($this->isValid($signed));
        $this->assertSame($this->withoutSignature($unsigned), $this->withoutSignature($signed));
    }

    /**
     * A signed document is validated as the object saves it. If the object is
     * asked to have format and the document has no spaces between its elements,
     * what it saves is not what was signed, and the signature is not valid:
     * whoever has the object has to keep the format of the XML.
     */
    public function testSignedDocumentThatIsSavedWithAnotherFormatIsNotValid(): void
    {
        $signed = $this->service->signXml(
            '<Root><Set ID="A"><Header>1</Header></Set></Root>',
            $this->certificate,
            'A'
        );
        $this->assertTrue($this->isValid($signed));

        $document = new XmlDocument();
        $document->loadXml($signed);
        $this->assertTrue($this->isValid($document));

        $document->setFormatOutput(true);

        $this->assertFalse($this->isValid($document));
        $this->assertFalse($this->isValid($document->saveXml()));
    }
}
