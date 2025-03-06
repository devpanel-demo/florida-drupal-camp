To run the recipe run.

ddev drush site-install --existing-config
ddev ssh
php core/scripts/drupal recipe recipes/fldc25 -vvv
ddev drush cr
ddev drush --uid=4 uli

Notes: Some changes were made to accommodate for said commands.

1. Such as --existing config requires a change from standard to minimal profile on the core—extensions file.
2. One of the views had its config altered since there are no taxonomies when it loads they get added after and hence it does not save that preference.
3. Emails were modified to @demo address.