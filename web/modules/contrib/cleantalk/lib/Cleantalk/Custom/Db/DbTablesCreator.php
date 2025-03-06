<?php

namespace Cleantalk\Custom\Db;

use Cleantalk\Common\Db\Schema;
use Cleantalk\Common\Mloader\Mloader;

class DbTablesCreator extends \Cleantalk\Common\Db\DbTablesCreator
{
    /**
     * Create all plugin tables from Schema
     */
    public function createAllTables($prefix = '')
    {
      /** @var Schema $schema_class */
      $schema_class = Mloader::get('Db\Schema');

      $db_schema = $schema_class::getStructureSchemas();

      foreach ($db_schema as $table_key => $table_schema) {
        $schema = \Drupal::database()->schema();
        try {
          $schema->createTable($table_key, $table_schema);
        } catch (\Drupal\Core\Database\SchemaObjectExistsException $e) {
          // The table is already exists
          continue;
        }
      }
    }

    /**
     * Create Table by table name
     */
    public function createTable($table_name)
    {
      /** @var Schema $schema_class */
      $schema_class = Mloader::get('Db\Schema');

      $db_schema = $schema_class::getStructureSchemas();

      $schema = \Drupal::database()->schema();
      try {
        $schema->createTable($table_name, $db_schema[str_replace('_temp', '', $table_name)]);
      } catch (\Drupal\Core\Database\SchemaObjectExistsException $e) {
        // The table is already exists
      }
    }
}
