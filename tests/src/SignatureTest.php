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

use Derafu\Certificate\Service\CertificateFaker;
use Derafu\Certificate\Service\CertificateLoader;
use Derafu\Signature\Signature;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * The signature node reads its data from the array that represents it. The data
 * can come from an XML that was loaded, so what is not in it is not a problem:
 * it is `null`.
 */
#[CoversClass(Signature::class)]
final class SignatureTest extends TestCase
{
    public function testANewSignatureHasNoValues(): void
    {
        $signature = new Signature();

        $this->assertNull($signature->getReference());
        $this->assertNull($signature->getDigestValue());
        $this->assertNull($signature->getX509Certificate());
        $this->assertSame([], $signature->getX509CertificateChain());
        $this->assertNull($signature->getSignatureValue());
    }

    public function testTheValuesThatAreAssignedAreRead(): void
    {
        $certificate = (new CertificateFaker(new CertificateLoader()))->createFake();

        $signature = (new Signature())->configureSignatureData(
            reference: '#Doc1',
            digestValue: 'digest',
            certificate: $certificate
        )->setSignatureValue('signature');

        $this->assertSame('Doc1', $signature->getReference());
        $this->assertSame('digest', $signature->getDigestValue());
        $this->assertSame($certificate->getCertificate(true), $signature->getX509Certificate());
        $this->assertSame([], $signature->getX509CertificateChain());
        $this->assertSame('signature', $signature->getSignatureValue());
    }

    public function testTheCertificateChainIsTheCertificatesAfterTheFirst(): void
    {
        $certificate = (new CertificateFaker(new CertificateLoader()))->createFake();
        $chain = $certificate->getCertificateChain(true);
        $this->assertNotSame([], $chain);

        $signature = (new Signature())->configureSignatureData(
            digestValue: 'digest',
            certificate: $certificate,
            includeCertificateChain: true
        );

        $this->assertSame($certificate->getCertificate(true), $signature->getX509Certificate());
        $this->assertSame($chain, $signature->getX509CertificateChain());
    }

    public function testWhatIsNotInTheDataIsNullWithoutWarnings(): void
    {
        foreach ([[], ['Signature' => []], ['Signature' => 'text'], ['Signature' => ['KeyInfo' => null]]] as $data) {
            $signature = (new Signature())->setData($data);

            $this->assertNull($signature->getReference());
            $this->assertNull($signature->getDigestValue());
            $this->assertNull($signature->getX509Certificate());
            $this->assertSame([], $signature->getX509CertificateChain());
            $this->assertNull($signature->getSignatureValue());
        }
    }

    public function testTheValuesAreOnlyTextOrNull(): void
    {
        $signature = (new Signature())->setData(['Signature' => [
            'SignatureValue' => ['not', 'text'],
            'SignedInfo' => ['Reference' => ['DigestValue' => 123, '@attributes' => ['URI' => ['no']]]],
            'KeyInfo' => ['X509Data' => ['X509Certificate' => [1, 'chain']]],
        ]]);

        $this->assertNull($signature->getSignatureValue());
        $this->assertNull($signature->getDigestValue());
        $this->assertNull($signature->getReference());
        $this->assertNull($signature->getX509Certificate());
        $this->assertSame(['chain'], $signature->getX509CertificateChain());
    }
}
