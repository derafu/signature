<?php

declare(strict_types=1);

/**
 * Derafu: Signature - Library for digital signatures.
 *
 * Copyright (c) 2025 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Signature\Support;

use Derafu\Signature\Exception\SignatureException;

/**
 * Converts the signatures of ECDSA and DSA between the two forms that exist.
 *
 * OpenSSL gives and takes them as DER (a sequence of two integers, `r` and
 * `s`), and XML Signature writes them as the raw concatenation `r || s`, each
 * one with the size of the order of the group.
 */
final class RawSignature
{
    /**
     * Converts a signature from DER to `r || s`.
     *
     * @param string $der Signature in DER.
     * @param int $size Size in bytes of each integer.
     * @throws SignatureException If it is not a signature in DER or an integer
     * does not fit in the size.
     */
    public static function fromDer(string $der, int $size): string
    {
        $invalid = new SignatureException('The signature is not a sequence of two integers in DER.');

        $offset = 0;
        if (self::readTag($der, $offset) !== 0x30) {
            throw $invalid;
        }
        $length = self::readLength($der, $offset, $invalid);
        if ($offset + $length !== strlen($der)) {
            throw $invalid;
        }

        $raw = '';
        for ($i = 0; $i < 2; $i++) {
            if (self::readTag($der, $offset) !== 0x02) {
                throw $invalid;
            }
            $integerLength = self::readLength($der, $offset, $invalid);
            if ($integerLength === 0 || $offset + $integerLength > strlen($der)) {
                throw $invalid;
            }
            $integer = ltrim(substr($der, $offset, $integerLength), "\x00");
            $offset += $integerLength;
            if (strlen($integer) > $size) {
                throw $invalid;
            }
            $raw .= str_pad($integer, $size, "\x00", STR_PAD_LEFT);
        }
        if ($offset !== strlen($der)) {
            throw $invalid;
        }

        return $raw;
    }

    /**
     * Converts a signature from `r || s` to DER.
     *
     * @param string $raw Signature as `r || s`, with an even size.
     * @throws SignatureException If the signature is empty or has an odd size.
     */
    public static function toDer(string $raw): string
    {
        $length = strlen($raw);
        if ($length === 0 || $length % 2 !== 0) {
            throw new SignatureException('The signature is not the concatenation of two integers of the same size.');
        }

        $half = intdiv($length, 2);
        $body = self::integer(substr($raw, 0, $half)) . self::integer(substr($raw, $half));

        return "\x30" . self::length(strlen($body)) . $body;
    }

    /**
     * Writes a positive integer in DER.
     */
    private static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '' || ord($bytes[0]) >= 0x80) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . self::length(strlen($bytes)) . $bytes;
    }

    /**
     * Writes the length of a DER element.
     */
    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return pack('C', $length);
        }
        $bytes = ltrim(pack('N', $length), "\x00");

        return pack('C', 0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * Reads the tag of a DER element and moves the offset after it.
     */
    private static function readTag(string $der, int &$offset): int
    {
        $tag = ord($der[$offset] ?? "\xFF");
        $offset++;

        return $tag;
    }

    /**
     * Reads the length of a DER element and moves the offset after it.
     *
     * @throws SignatureException If the length is not valid.
     */
    private static function readLength(string $der, int &$offset, SignatureException $invalid): int
    {
        if ($offset >= strlen($der)) {
            throw $invalid;
        }
        $first = ord($der[$offset]);
        $offset++;
        if ($first < 0x80) {
            return $first;
        }

        $count = $first & 0x7F;
        if ($count === 0 || $count > 4 || $offset + $count > strlen($der)) {
            throw $invalid;
        }
        $length = 0;
        for ($i = 0; $i < $count; $i++) {
            $length = ($length << 8) | ord($der[$offset]);
            $offset++;
        }

        return $length;
    }
}
