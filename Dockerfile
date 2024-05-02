# Use an official PHP image with Apache as the base image.
FROM php:8.3-apache


# Install system dependencies.
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    zip \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Enable Apache modules required for Laravel.
RUN a2enmod rewrite


# Set the Apache document root
ENV APACHE_DOCUMENT_ROOT /var/www/html/public
ENV COMPOSER_ALLOW_SUPERUSER 1

# Update the default Apache site configuration
# COPY apache-config.conf /etc/apache2/sites-available/000-default.conf

# Install PHP extensions.
RUN docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) gd pdo pdo_mysql

# Install Composer globally.
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Create a directory for your Laravel application.
WORKDIR /var/www/html

RUN echo "=============================="
RUN echo $APACHE_DOCUMENT_ROOT
RUN pwd && ls
RUN echo "=============================="

# # Copy the Laravel application files into the container.
# COPY /Users/snowball/Documents/on-the-go-tours/DOCKERTEST/Conteiners/keyapi/apikey .

# Install Laravel dependencies using Composer.
# RUN composer install --no-interaction --optimize-autoloader

# # RUN Laravel migrate.
# RUN php artisan migrate

# Set permissions for Laravel.
# RUN chown -R www-data:www-data storage bootstrap/cache

# Expose port 80 for Apache.
EXPOSE 82

# Start Apache web server.
CMD ["apache2-foreground"]

# You can add any additional configurations or commands required for Laravel 10 here.
