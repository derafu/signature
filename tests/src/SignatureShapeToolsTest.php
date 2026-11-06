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

use Derafu\TestsSignature\Support\ReadsFixtures;
use Derafu\TestsSignature\Support\ShapeCoverage;
use Derafu\TestsSignature\Support\ShapeReport;
use Derafu\TestsSignature\Support\SignatureShape;
use Derafu\TestsSignature\Support\SignedDocumentsLog;
use Derafu\TestsSignature\Support\UsesXmlsec;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * The tools that describe the shapes of the signatures of a set of documents
 * and compare them with the ones that the tests exercise (`tests/tools/`).
 */
#[CoversNothing]
final class SignatureShapeToolsTest extends TestCase
{
    use ReadsFixtures;
    use UsesXmlsec;

    private const FIXTURES = __DIR__ . '/../fixtures';

    private string $log;

    protected function setUp(): void
    {
        $this->createService();
        $this->log = tempnam(sys_get_temp_dir(), 'derafu-signature-shapes-') ?: '';
        $this->assertNotSame('', $this->log);
        putenv(SignedDocumentsLog::ENVIRONMENT_VARIABLE . '=' . $this->log);
    }

    protected function tearDown(): void
    {
        putenv(SignedDocumentsLog::ENVIRONMENT_VARIABLE);
        if (isset($this->log) && is_file($this->log)) {
            unlink($this->log);
        }
    }

    private function fixture(string $name): string
    {
        return $this->readFixture(self::FIXTURES . '/' . $name);
    }

    public function testShapeOfAPackageWithSignaturesInsideTheSignedElement(): void
    {
        $xml = $this->fixture('signed/xmlsec_package.xml');

        $atoms = SignatureShape::atoms($xml);

        $this->assertContains('doc.signatures=3+', $atoms);
        $this->assertContains('sig.depth=nested', $atoms);
        $this->assertContains('sig.depth=child-of-root', $atoms);
        $this->assertContains('ref.target=contains-signature/signature-outside', $atoms);
        $this->assertContains('ref.target=plain/signature-outside', $atoms);
        $this->assertContains('ref.identifier=ID', $atoms);
        $this->assertContains('doc.encoding=UTF-8', $atoms);
        $this->assertCount(3, SignatureShape::describe($xml));
        $this->assertCount(3, SignatureShape::signatureValues($xml));
    }

    public function testShapeOfTheSignaturesOfUbl(): void
    {
        $atoms = SignatureShape::atoms($this->fixture('ubl_official_enveloped.xml'));

        $this->assertContains('sig.prefix=ds', $atoms);
        $this->assertContains('sig.object=Object', $atoms);
        $this->assertContains('sig.references=2', $atoms);
        $this->assertContains('ref.transforms=xpath', $atoms);
        $this->assertContains('ref.kind=whole', $atoms);
        $this->assertContains('ref.identifier=Id', $atoms);
    }

    public function testShapeOfASignatureThatIsIncompleteAndOfADocumentWithoutSignatures(): void
    {
        $incomplete = SignatureShape::atoms($this->fixture('signed/incomplete_signature.xml'));
        $without = SignatureShape::atoms($this->fixture('signed/element_named_signature_that_is_not_a_signature.xml'));

        $this->assertContains('sig.complete=no (no SignedInfo)', $incomplete);
        $this->assertContains('sig.references=0', $incomplete);
        $this->assertContains('doc.signatures=0', $without);
        $this->assertSame([], array_values(array_filter($without, static fn (string $atom): bool => str_starts_with($atom, 'sig.'))));
    }

    public function testShapeOfAnXmlThatCanNotBeReadIsEmpty(): void
    {
        $this->assertSame([], SignatureShape::atoms('this is not xml'));
        $this->assertSame([], SignatureShape::describe('<a>'));
        $this->assertSame([], SignatureShape::signatureValues(''));
    }

    public function testShapeCanBeLimitedToSomeSignatures(): void
    {
        $xml = $this->fixture('signed/xmlsec_package.xml');

        // Only the signature of the envelope, the last one: it is not nested.
        $atoms = SignatureShape::atoms($xml, [2]);

        $this->assertContains('sig.depth=child-of-root', $atoms);
        $this->assertNotContains('sig.depth=nested', $atoms);
        // The characteristics of the document do not depend on that.
        $this->assertContains('doc.signatures=3+', $atoms);
        $this->assertSame([], array_values(array_filter(
            SignatureShape::atoms($xml, []),
            static fn (string $atom): bool => str_starts_with($atom, 'sig.') || str_starts_with($atom, 'ref.')
        )));
    }

    public function testShapeDoesNotHaveTheContentOfTheDocument(): void
    {
        $xml = $this->fixture('signed/legacy_package_without_xsi_utf_8.xml');

        $text = implode("\n", [...SignatureShape::atoms($xml), ...SignatureShape::describe($xml)]);

        foreach (['Óptica', 'Ñuñoa', '76192083', 'D1', 'Set', 'urn:example'] as $content) {
            $this->assertStringNotContainsString($content, $text);
        }
    }

    public function testFilesAreSearchedInDirectoriesAndInTheGivenFiles(): void
    {
        $files = ShapeCoverage::files([self::FIXTURES . '/signed', self::FIXTURES . '/valid_signed.xml', self::FIXTURES . '/does-not-exist']);

        $this->assertContains(self::FIXTURES . '/signed/xmlsec_package.xml', $files);
        $this->assertContains(self::FIXTURES . '/valid_signed.xml', $files);
        $this->assertNotContains(self::FIXTURES . '/signed/manifest.json', $files);
        $this->assertSame($files, array_values(array_unique($files)));
    }

    public function testAtomsOfTheFilesHaveTheNumberOfFilesAndOneExample(): void
    {
        $atoms = ShapeCoverage::atomsOf([
            self::FIXTURES . '/signed/xmlsec_package.xml',
            self::FIXTURES . '/signed/legacy_reference_iso_8859_1.xml',
            self::FIXTURES . '/signed/does-not-exist.xml',
        ]);

        $this->assertSame(1, $atoms['doc.encoding=ISO-8859-1']['count']);
        $this->assertSame(self::FIXTURES . '/signed/legacy_reference_iso_8859_1.xml', $atoms['doc.encoding=ISO-8859-1']['example']);
        $this->assertSame(2, $atoms['doc.format=pretty']['count']);
        $this->assertSame(self::FIXTURES . '/signed/xmlsec_package.xml', $atoms['doc.format=pretty']['example']);
    }

    public function testLogOfTheDocumentsIsOnlyWrittenIfItIsEnabled(): void
    {
        putenv(SignedDocumentsLog::ENVIRONMENT_VARIABLE);
        SignedDocumentsLog::record(SignedDocumentsLog::SIGNED_BY_LIBRARY, '<a/>');
        $this->assertSame('', (string) file_get_contents($this->log));

        putenv(SignedDocumentsLog::ENVIRONMENT_VARIABLE . '=');
        SignedDocumentsLog::record(SignedDocumentsLog::SIGNED_BY_LIBRARY, '<a/>');
        $this->assertSame('', (string) file_get_contents($this->log));

        putenv(SignedDocumentsLog::ENVIRONMENT_VARIABLE . '=' . $this->log);
        SignedDocumentsLog::record(SignedDocumentsLog::SIGNED_BY_LIBRARY, "<a>ñ\n</a>", 'VALUE');
        SignedDocumentsLog::record(SignedDocumentsLog::VALIDATED_BY_LIBRARY, '<b/>');

        $this->assertSame([
            ['kind' => SignedDocumentsLog::SIGNED_BY_LIBRARY, 'signature' => 'VALUE', 'xml' => "<a>ñ\n</a>"],
            ['kind' => SignedDocumentsLog::VALIDATED_BY_LIBRARY, 'signature' => null, 'xml' => '<b/>'],
        ], SignedDocumentsLog::read($this->log));
    }

    public function testDocumentsOfTheTestsAreAssignedToTheWayInWhichTheyWereExercised(): void
    {
        $xml = "<Root>\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n</Root>\n";

        // The library signs and validates.
        $signed = $this->service->signXml($xml, $this->certificate, ['reference' => 'A']);
        $this->assertTrue($this->service->validateXml($signed)[0]->isValid());
        // A document that is not valid is not exercised as valid.
        $this->assertFalse($this->service->validateXml(str_replace('<V>1</V>', '<V>2</V>', $signed))[0]->isValid());
        // A signature that the library did not make: the one of a fixture.
        $fixture = $this->fixture('signed/xmlsec_sha256_prefixed.xml');
        $this->assertTrue($this->service->validateXml($fixture)[0]->isValid());
        // The library signs over it: only the new signature is its own.
        $both = $this->service->signXml($fixture, $this->certificate, ['reference' => 'A', 'signature_prefix' => 'ds']);
        $this->assertCount(2, $this->service->validateXml($both));

        $modes = ShapeCoverage::atomsOfTests($this->log, []);

        $this->assertSame([], $modes[ShapeCoverage::FIXTURES]);
        $this->assertArrayHasKey('sig.prefix=none', $modes[ShapeCoverage::LIBRARY_TO_LIBRARY]);
        $this->assertArrayHasKey('sig.prefix=ds', $modes[ShapeCoverage::LIBRARY_TO_LIBRARY]);
        $this->assertArrayHasKey('sig.method=dsig:rsa-sha1', $modes[ShapeCoverage::LIBRARY_TO_LIBRARY]);
        // The signature of the fixture is SHA256: it is not the library's.
        $this->assertArrayNotHasKey('sig.method=more:rsa-sha256', $modes[ShapeCoverage::LIBRARY_TO_LIBRARY]);
        $this->assertArrayNotHasKey('ref.digest=enc:sha256', $modes[ShapeCoverage::LIBRARY_TO_LIBRARY]);
        $this->assertSame([], $modes[ShapeCoverage::XMLSEC_TO_LIBRARY]);
        $this->assertSame([], $modes[ShapeCoverage::LIBRARY_TO_XMLSEC]);
    }

    public function testDocumentsSignedByXmlsecAndVerifiedByXmlsecAreAssignedToTheirWays(): void
    {
        $this->requireXmlsec();
        $xml = "<Root>\n  <Doc ID=\"A\">\n    <V>1</V>\n  </Doc>\n  %SIG%\n</Root>\n";
        $template = $this->template('', self::SIGNATURES['sha256'], self::C14N, [
            ['#A', self::DIGESTS['sha256'], [[self::C14N, '']]],
        ]);
        $byXmlsec = $this->signWithXmlsec(str_replace('%SIG%', $template, $xml));
        $this->assertTrue($this->service->validateXml($byXmlsec)[0]->isValid());
        $byLibrary = $this->service->signXml(str_replace('%SIG%', '', $xml), $this->certificate, ['reference' => 'A']);
        $this->assertTrue($this->verifyWithXmlsec($byLibrary));
        // A document that xmlsec1 does not verify is not exercised.
        $this->assertFalse($this->verifyWithXmlsec(str_replace('<V>1</V>', '<V>2</V>', $byLibrary)));

        $modes = ShapeCoverage::atomsOfTests($this->log, []);

        $this->assertArrayHasKey('sig.method=more:rsa-sha256', $modes[ShapeCoverage::XMLSEC_TO_LIBRARY]);
        $this->assertArrayHasKey('sig.method=dsig:rsa-sha1', $modes[ShapeCoverage::LIBRARY_TO_XMLSEC]);
        $this->assertArrayNotHasKey('sig.method=more:rsa-sha256', $modes[ShapeCoverage::LIBRARY_TO_XMLSEC]);
    }

    public function testCharacteristicsThatTheTestsDoNotExerciseAreMissing(): void
    {
        $documents = [
            'sig.prefix=ds' => ['count' => 2, 'example' => 'a.xml'],
            'sig.depth=nested' => ['count' => 1, 'example' => 'b.xml'],
            'sig.references=2' => ['count' => 1, 'example' => 'c.xml'],
            'ref.digest=enc:sha256' => ['count' => 1, 'example' => 'd.xml'],
        ];
        $tests = [
            ShapeCoverage::FIXTURES => ['sig.prefix=ds' => true, 'sig.depth=nested' => true, 'sig.references=2' => true],
            ShapeCoverage::LIBRARY_TO_LIBRARY => ['sig.prefix=ds' => true],
            ShapeCoverage::XMLSEC_TO_LIBRARY => ['sig.prefix=ds' => true, 'sig.depth=nested' => true],
            ShapeCoverage::LIBRARY_TO_XMLSEC => ['sig.prefix=ds' => true, 'sig.depth=nested' => true],
        ];

        $missing = ShapeCoverage::missing($documents, $tests);

        // The prefix is exercised in all the ways.
        $this->assertArrayNotHasKey('sig.prefix=ds', $missing);
        $this->assertSame([ShapeCoverage::LIBRARY_TO_LIBRARY], $missing['sig.depth=nested']);
        // Two references and the digest SHA256 are by design only in the
        // fixtures: it is only missing if the fixtures do not have them.
        $this->assertArrayNotHasKey('sig.references=2', $missing);
        $this->assertSame([ShapeCoverage::FIXTURES], $missing['ref.digest=enc:sha256']);
        $this->assertNotNull(ShapeCoverage::reason('sig.references=2'));
        $this->assertNull(ShapeCoverage::reason('sig.prefix=ds'));
    }

    public function testReports(): void
    {
        $shapes = ShapeReport::shapes(ShapeCoverage::files([self::FIXTURES . '/signed']));
        $this->assertStringContainsString('Shapes of signatures:', $shapes);
        $this->assertStringContainsString('prefix=ds', $shapes);
        $this->assertStringContainsString('Without signatures: 1.', $shapes);

        $documents = ['sig.prefix=ds' => ['count' => 2, 'example' => 'a.xml'], 'sig.depth=nested' => ['count' => 1, 'example' => 'b.xml']];
        $all = [ShapeCoverage::FIXTURES => ['sig.prefix=ds' => true, 'sig.depth=nested' => true]];
        $this->assertStringContainsString('missing: library->library', ShapeReport::coverage($documents, $all));
        $this->assertStringContainsString(
            'All the characteristics are exercised',
            ShapeReport::coverage(['doc.format=pretty' => ['count' => 1, 'example' => 'a.xml']], array_fill_keys(ShapeCoverage::MODES, ['doc.format=pretty' => true]))
        );
    }

    public function testCommandsRunWithTheFixturesAndTheirOptions(): void
    {
        $tools = __DIR__ . '/../tools';
        $fixtures = escapeshellarg(self::FIXTURES);
        file_put_contents($this->log, '');

        exec(PHP_BINARY . ' ' . escapeshellarg($tools . '/signature-shapes.php') . ' ' . $fixtures . ' 2>&1', $lines, $status);
        $this->assertSame(0, $status);
        $this->assertStringContainsString('Shapes of signatures:', implode("\n", $lines));

        exec(PHP_BINARY . ' ' . escapeshellarg($tools . '/signature-shapes.php') . ' 2>&1', $lines, $status);
        $this->assertSame(1, $status);

        // The log is empty, so the tests do not exercise anything: with
        // `--strict` it is an error.
        $coverage = PHP_BINARY . ' ' . escapeshellarg($tools . '/signature-coverage.php') . ' --log=' . escapeshellarg($this->log) . ' --fixtures=' . $fixtures;
        exec($coverage . ' ' . $fixtures . ' 2>&1', $lines, $status);
        $this->assertSame(0, $status);
        exec($coverage . ' --strict ' . $fixtures . ' 2>&1', $lines, $status);
        $this->assertSame(1, $status);
        exec(PHP_BINARY . ' ' . escapeshellarg($tools . '/signature-coverage.php') . ' 2>&1', $lines, $status);
        $this->assertSame(1, $status);
    }
}
