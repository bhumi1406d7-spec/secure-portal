FROM php:8.2-apache

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Install mysqli extension
RUN docker-php-ext-install mysqli

# Copy all project files
COPY . /var/www/html/

# Set permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# Apache config to allow .htaccess
RUN echo '<Directory /var/www/html>\n\
    AllowOverride All\n\
    Require all granted\n\
</Directory>' > /etc/apache2/conf-available/project.conf \
    && a2enconf project

EXPOSE 80
