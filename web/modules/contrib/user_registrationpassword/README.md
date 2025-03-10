# User registration password

User Registration Password let's users register with a password
on the registration form when 'Require email verification when
a visitor creates an account' is enabled on the configuration page.

By default, users can create accounts directly on the registration form, set
their password and be immediately logged in, or they can create their account,
wait for a verification email, and then create their password.

With this module, users are able to create their account along with their
password and simply activate their account when receiving the verification
email by clicking on the activation link provided via this email.

User Registration Password transforms the checkbox on the
`admin/config/people/accounts` page into a radio list with 3 options.

The first 2 are default Drupal behavior:

:o: Do not require a verification email, and let users set their password on
   the registration form.

:o: Require a verification email, but wait for the approval email to let users
   set their password.

The newly added option is:

:x: Require a verification email, but let users set their password directly on
   the registration form.

The first 2 disable User Registration Password, only the 3rd option activates
the behavior implemented by this module.


## Contents of this file

- Installation
- Configuration
- Email templates
- Token
- Multilingual sites
- Known issues
- De-installation
- Upgrade notes


## Installation

Installation is like any other module, just place the files in the modules
directory and enable the module on the 'Extend' page.


## Configuration

The module sets the correct configuration settings on install, including the
correct account activation email template. But if you want to change something,
these steps describe how to configure the module in more detail.

On the `admin/config/people/accounts` page make sure you have selected:

Who can register accounts?

:o: Administrators only

:x: Visitors

:o: Visitors, but administrator approval is required

Then select 'Require a verification email, but let users set their password
directly on the registration form.' at:

Require email verification when a visitor creates an account

:o: Do not require a verification email, and let users
  set their password on the
  registration form.

:o: Require a verification email, but wait for the approval email to let users
   set their password.

:x: Require a verification email, but let users set their password directly
   on the registration form.

The module is now configured and ready for use. This is also the only way to
configure it correctly. This module will also not work if you do not have
'Visitors' selected at 'Who can register accounts?' on the same page.


## Email templates

Regarding email templates:

You do not have to alter any email templates, User Registration Password
overrides the default 'Account activation' email template during installation.
So there is no need to change anything anymore on a fresh installation.

If you have previously modified the account activation email template before
you installed this module and discovered that it overrides the default Account
activation email template, no worries! The installer saves your changes to the
template to a temporally variable and revives them when you uninstall User
Registration Password. Your modifications are revived and you can now copy
paste them to a text file and re-install User Registration Password again and
make the changes to the 'account activation' email template based on your
previous version.


## Token

The token provided by this module:

`[user:registrationpassword-url]`

Place this token in your registration email template (the installer tries to do
this during install, if that fails you have to manually add it).

Also see the token widget on the admin account form for all available tokens.


## Multilingual sites

All variables (including email) are all translatable via the core user
configuration translation page at `admin/config/people/accounts/translate` or
via the general translate configuration page.

Ones configured correctly, users will receive an email in their default
language, setting available on user's edit page. It does not matter what the
site language is, this setting will be leading and supercede the site's default
language. So it is logical and correct that if you have an German based site
with, let's say German and English languages enabled, and German is also the
site's default language, still when users have English as their default browser
language, they will receive an English email.


## Known issues

None yet that we didn't solve.

If you run into problems, like access denied or other (possibly) cache-related
issues, or if you have enabled the module via drush, remember to clear
the site cache via the admin/config/development/performance page.

If this does not help, first try on IRC if anyone can help you, if you still
are not able to get it to work, open a new issue with a descent title and
description of the problem here: [issue queue](https://drupal.org/node/add/project-issue/user_registrationpassword)


## De-Installation

If you want to disable the module temporally, just select the first or second
option on the the `admin/config/people/accounts` page at:

Require email verification when a visitor creates an account

1. Do not require a verification email, and let users
   set their password on the registration form.
1. Require a verification email, but wait for the
   approval email to let users set their password.
1. Require a verification email, but let users set
   their password directly on the
   registration form.

This disables the User Registration Password functionality without
uninstalling it.

If you want to remove the module uninstall it as you do for any other module
via the `admin/modules page`.


## Upgrade notes

Variables should work, named constants changed, so if you implement these you
might want to revisit this code.
