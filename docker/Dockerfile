ARG PHP_VERSION=8.3
FROM php:${PHP_VERSION}-cli-alpine

RUN apk add --no-cache \
        git \
        unzip \
        libzip-dev \
        icu-dev \
        $PHPIZE_DEPS \
    && docker-php-ext-install zip bcmath intl \
    && pecl install pcov \
    && docker-php-ext-enable pcov \
    && apk del $PHPIZE_DEPS

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

WORKDIR /app