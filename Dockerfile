ARG ALPINE_VERSION=3.16
FROM alpine:${ALPINE_VERSION}
LABEL Maintainer="Tim de Pater <code@trafex.nl>"
LABEL Description="Lightweight container with Nginx 1.22 & PHP 8.1 based on Alpine Linux."
# Setup document root
WORKDIR /var/www/html

ARG COMPOSER_SETUP_SHA384="e21205b207c3ff031906575712edab6f13eb0b361f2085f1f1237b7126d785e826a450292b6cfd1d64d92e6563bbde02"

# Install packages and remove default server definition
RUN apk add --no-cache \
  curl \
  nginx \
  php81 \
  php81-ctype \
  php81-curl \
  php81-dom \
  php81-fpm \
  php81-gd \
  php81-intl \
  php81-mbstring \
  php81-mysqli \
  php81-opcache \
  php81-openssl \
  php81-phar \
  php81-session \
  php81-xml \
  php81-xmlreader \
  php81-zlib \
  php81-redis \
  php81-tokenizer \
  php81-fileinfo \
  php81-zip \
  php81-pdo \
  php81-pdo_mysql \
  php81-pdo_pgsql \
  php81-exif \
  php81-pecl-xdebug \
  supervisor

# Create symlink so programs depending on `php` still function
RUN ln -s /usr/bin/php81 /usr/bin/php

RUN php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" && \
  php -r "if (hash_file('sha384', 'composer-setup.php') === '${COMPOSER_SETUP_SHA384}') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;"  && \
    php composer-setup.php && \
    php -r "unlink('composer-setup.php');" && \
    mv composer.phar /usr/local/bin/composer

# Configure nginx
COPY config/nginx.conf /etc/nginx/nginx.conf

# Configure PHP-FPM
COPY config/fpm-pool.conf /etc/php81/php-fpm.d/www.conf
COPY config/php.ini /etc/php81/conf.d/custom.ini

# Configure supervisord
COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Make sure files/folders needed by the processes are accessable when they run under the nobody user
RUN chown -R nobody.nobody /var/www/html /run /var/lib/nginx /var/log/nginx

# Switch to use a non-root user from here on
USER nobody

# Add application
COPY --chown=nobody src/ /var/www/html/

# Expose the port nginx is reachable on
EXPOSE 8080

# Let supervisord start nginx & php-fpm
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

# Configure a healthcheck to validate that everything is up&running
HEALTHCHECK --timeout=10s CMD curl --silent --fail http://127.0.0.1:8080/fpm-ping
