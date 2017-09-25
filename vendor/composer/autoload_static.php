<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit755bcd64e43c63af6e6408937fdf4503
{
    public static $prefixLengthsPsr4 = array (
        'N' => 
        array (
            'Novutec\\WhoisParser\\' => 20,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Novutec\\WhoisParser\\' => 
        array (
            0 => __DIR__ . '/../..' . '/',
        ),
    );

    public static $classMap = array (
        'Novutec\\DomainParser\\Parser' => __DIR__ . '/..' . '/novutec/domainparser/Parser.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit755bcd64e43c63af6e6408937fdf4503::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit755bcd64e43c63af6e6408937fdf4503::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit755bcd64e43c63af6e6408937fdf4503::$classMap;

        }, null, ClassLoader::class);
    }
}
