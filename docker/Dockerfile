ARG PHP_VERSION=8.3
FROM php:${PHP_VERSION}-cli-alpine

RUN apk add --no-cache \
        git \
        unzip \
        libzip-dev \
        $PHPIZE_DEPS \
    && docker-php-ext-install zip \
    && pecl install pcov \
    && docker-php-ext-enable pcov \
    && apk del $PHPIZE_DEPS

# pcov.directory is PHP_INI_PERDIR, so phpunit.dist.xml cannot set it. Pin it to
# the project root here so `bin/castor lint` covers packages/core/src as well as
# src, matching the ini-values passed in .github/workflows/ci.yaml.
RUN printf 'pcov.directory=.\n' > "$PHP_INI_DIR/conf.d/zz-pcov-directory.ini"

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

WORKDIR /app