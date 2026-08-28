FROM php:8.4-apache

RUN apt-get update \
    && apt-get install -y libonig-dev \
    && docker-php-ext-install pdo pdo_mysql mbstring \
    && rm -rf /var/lib/apt/lists/*

COPY php.ini /usr/local/etc/php/conf.d/uploads.ini
    
COPY . /var/www/html/

RUN chown -R www-data:www-data /var/www/html