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
use Derafu\Signature\Support\Algorithms;
use Derafu\Signature\Support\ReferenceData;
use Derafu\Signature\Support\ReferenceTarget;
use Derafu\Signature\Support\SignatureElements;
use Derafu\Signature\Translation\SignatureTranslationResourceProvider;
use Derafu\Xml\XmlDocument;
use DOMElement;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * The data of a reference, in the cases that a signature has to read the same
 * way that it was made: with and without the enveloped transform, with the
 * transforms of several XPath, with the canonicalizations, and with a signature
 * that is not where the path says.
 */
#[CoversClass(ReferenceData::class)]
#[CoversClass(SignatureElements::class)]
#[UsesClass(ReferenceTarget::class)]
#[UsesClass(Algorithms::class)]
#[UsesClass(SignatureException::class)]
#[UsesClass(SignatureTranslationResourceProvider::class)]
final class ReferenceDataTest extends TestCase
{
    private const DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    private function document(string $xml): XmlDocument
    {
        $doc = new XmlDocument();
        $doc->loadXml($xml);

        return $doc;
    }

    private function element(XmlDocument $doc, string $name): DOMElement
    {
        $element = $doc->getDomDocument()->getElementsByTagNameNS('*', $name)->item(0);
        $this->assertInstanceOf(DOMElement::class, $element);

        return $element;
    }

    /**
     * A document with a signature inside of the element `a`, whose reference
     * has the transforms that are given.
     */
    private function signedDocument(string $transforms = '', string $extra = ''): XmlDocument
    {
        return $this->document(
            '<r xmlns:u="urn:u"><a Id="a"><!-- c --><x>1</x><Signature xmlns="' . self::DSIG . '"><SignedInfo>'
            . '<Reference URI="#a">' . $transforms . '</Reference></SignedInfo></Signature></a>' . $extra . '</r>'
        );
    }

    public function testTheSignatureInsideOfTheElementIsDataUnlessTheTransformsLeaveItOut(): void
    {
        $doc = $this->signedDocument();
        $signature = $this->element($doc, 'Signature');
        $reference = $this->element($doc, 'Reference');

        $withSignature = ReferenceData::canonicalize($doc, $signature, $reference, '#a', [Algorithms::C14N]);
        $without = ReferenceData::canonicalize($doc, $signature, $reference, '#a', [Algorithms::ENVELOPED, Algorithms::C14N]);

        $this->assertStringContainsString('<Signature', $withSignature);
        $this->assertStringNotContainsString('<Signature', $without);
        $this->assertStringContainsString('<x>1</x>', $without);
    }

    public function testTheCanonicalizationIsExclusiveAndKeepsTheCommentsWhenTheAlgorithmsSayIt(): void
    {
        $doc = $this->signedDocument();
        $reference = $this->element($doc, 'Reference');
        $signature = $this->element($doc, 'Signature');
        $canonicalize = fn (string $algorithm): string => ReferenceData::canonicalize(
            $doc,
            $signature,
            $reference,
            '#a',
            [Algorithms::ENVELOPED, $algorithm]
        );

        $inclusive = $canonicalize(Algorithms::C14N);
        $exclusive = $canonicalize(Algorithms::EXC_C14N);
        $withComments = $canonicalize(Algorithms::C14N_WITH_COMMENTS);

        $this->assertSame('<a xmlns:u="urn:u" Id="a"><x>1</x></a>', $inclusive);
        $this->assertSame('<a Id="a"><x>1</x></a>', $exclusive);
        $this->assertSame('<a xmlns:u="urn:u" Id="a"><!-- c --><x>1</x></a>', $withComments);
        $this->assertSame('<a Id="a"><!-- c --><x>1</x></a>', $canonicalize(Algorithms::EXC_C14N_WITH_COMMENTS));
    }

    public function testAnXPathNeedsTheSignatureAndTheTransformsOfTheReference(): void
    {
        $doc = $this->signedDocument(
            '<Transforms><Transform Algorithm="' . Algorithms::XPATH . '"><XPath>true()</XPath></Transform></Transforms>'
        );
        $withoutTransforms = $this->signedDocument();

        $messages = [];
        foreach ([
            [$doc, null, $this->element($doc, 'Reference')],
            [$withoutTransforms, $this->element($withoutTransforms, 'Signature'), $this->element($withoutTransforms, 'Reference')],
        ] as [$document, $signature, $reference]) {
            try {
                ReferenceData::canonicalize($document, $signature, $reference, '#a', [Algorithms::XPATH]);
                $this->fail('It should have failed.');
            } catch (SignatureException $e) {
                $messages[] = $e->getMessage();
            }
        }

        $this->assertSame(
            array_fill(0, 2, 'The signature element with the transforms of the reference was not found in the XML to validate.'),
            $messages
        );
    }

    /**
     * Each XPath has the namespaces that its own element declares.
     */
    public function testTheNamespacesOfEveryXPathAreInThePrefixesOfAllOfThem(): void
    {
        $transforms = '<Transforms>'
            . '<Transform Algorithm="' . Algorithms::XPATH . '"><XPath xmlns:p="urn:p">boolean(//p:one)</XPath></Transform>'
            . '<Transform Algorithm="' . Algorithms::XPATH . '"><XPath xmlns:q="urn:q">boolean(//q:two)</XPath></Transform>'
            . '</Transforms>';
        $doc = $this->signedDocument($transforms, '<p:one xmlns:p="urn:p"/><q:two xmlns:q="urn:q"/>');

        $data = ReferenceData::canonicalize(
            $doc,
            $this->element($doc, 'Signature'),
            $this->element($doc, 'Reference'),
            '',
            [Algorithms::XPATH, Algorithms::XPATH]
        );

        $this->assertStringContainsString('<p:one', $data);
        $this->assertStringContainsString('<q:two', $data);
    }

    /**
     * A signature that is not in the document, like the one of another document,
     * has no element to take out: the data is the document as it is.
     */
    public function testASignatureThatIsNotWhereItsPathSaysIsNotTakenOut(): void
    {
        $doc = $this->document('<r><a Id="a"/></r>');
        $other = $this->document('<r><b/><c/><d/><Signature/></r>');
        $signature = $this->element($other, 'Signature');

        $data = ReferenceData::canonicalize($doc, $signature, null, '', [Algorithms::ENVELOPED]);

        $this->assertSame('<r><a Id="a"></a></r>', $data);
    }

    public function testTheSignaturesThatAreFoundAreTheOnesInsideOfTheRootUnlessTheRootIsOneToo(): void
    {
        $doc = $this->document('<Signature xmlns="' . self::DSIG . '"><Signature/></Signature>');

        $this->assertCount(1, SignatureElements::find($doc));
        $this->assertCount(2, SignatureElements::find($doc, true));
    }
}
