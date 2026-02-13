<?php namespace Mercator\Totp2fa\Classes;

use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;

/**
 * Renders an SVG QR code (used on the enrollment screen).
 */
class Qr
{
    public static function svg(string $text, int $size = 220): string
    {
        $renderer = new ImageRenderer(new RendererStyle($size), new SvgImageBackEnd());
        return (new Writer($renderer))->writeString($text);
    }
}
