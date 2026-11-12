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
use Derafu\Signature\Support\RawSignature;
use Derafu\Signature\Translation\SignatureTranslationResourceProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The DER of a signature of ECDSA and DSA, in every form that its lengths can
 * have: the short form, the long form from 128 bytes, the lengths of several
 * bytes and the forms that DER does not allow.
 */
#[CoversClass(RawSignature::class)]
#[CoversClass(SignatureException::class)]
#[CoversClass(SignatureTranslationResourceProvider::class)]
final class RawSignatureLengthsTest extends TestCase
{
    /**
     * @return array<string, array{string, string}>
     */
    public static function minimalDerProvider(): array
    {
        return [
            'integers that need no padding' => ["\x30\x06\x02\x01\x05\x02\x01\x07", "\x05\x07"],
            'integers of the value 0x80, that need a zero before' => ["\x30\x08\x02\x02\x00\x80\x02\x02\x00\x80", "\x80\x80"],
            'integers with the high bit' => ["\x30\x08\x02\x02\x00\x80\x02\x02\x00\xFF", "\x80\xFF"],
            'integers of the value 0x7F, that need no zero' => ["\x30\x06\x02\x01\x7F\x02\x01\x7F", "\x7F\x7F"],
            'integers of zeros' => ["\x30\x06\x02\x01\x00\x02\x01\x00", "\x00\x00"],
        ];
    }

    #[DataProvider('minimalDerProvider')]
    public function testTheDerThatIsWrittenIsTheMinimalOne(string $der, string $raw): void
    {
        $this->assertSame($der, RawSignature::toDer($raw));
    }

    public function testAnElementOf128BytesUsesTheLongFormOfTheLength(): void
    {
        // Two integers of 62 bytes: each one is an element of 64 bytes.
        $raw = str_repeat("\x01", 124);

        $der = RawSignature::toDer($raw);

        $this->assertSame("\x30\x81\x80", substr($der, 0, 3));
        $this->assertSame($raw, RawSignature::fromDer($der, 62));
    }

    public function testALengthThatNeedsTwoBytesIsWrittenWithTwoBytes(): void
    {
        // Two integers of 150 bytes: the body has 306 bytes (0x0132).
        $raw = str_repeat("\x01", 300);

        $der = RawSignature::toDer($raw);

        $this->assertSame("\x30\x82\x01\x32", substr($der, 0, 4));
        $this->assertSame($raw, RawSignature::fromDer($der, 150));
    }

    public function testALengthOfFourBytesIsRead(): void
    {
        $der = "\x30\x84\x00\x00\x00\x06\x02\x01\x05\x02\x01\x07";

        $this->assertSame("\x05\x07", RawSignature::fromDer($der, 1));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidProvider(): array
    {
        $body = "\x02\x3E" . str_repeat("\x01", 62) . "\x02\x3E" . str_repeat("\x01", 62);

        return [
            'a sequence that is another element, with the rest valid' => ["\x31\x06\x02\x01\x05\x02\x01\x07"],
            'a length of five bytes' => ["\x30\x85\x00\x00\x00\x00\x06\x02\x01\x05\x02\x01\x07"],
            'the byte of the indefinite length, followed by 128 bytes' => ["\x30\x80" . $body],
        ];
    }

    #[DataProvider('invalidProvider')]
    public function testADerThatIsNotValidIsAnErrorEvenIfWhatFollowsIsAPairOfIntegers(string $der): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionMessage('is not a sequence of two integers in DER');

        RawSignature::fromDer($der, 62);
    }
}
