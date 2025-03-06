<?php

namespace Cleantalk\Custom\Db;

class Db extends \Cleantalk\Common\Db\Db
{
    private $db_result;
    public $result;

    /**
     * Alternative constructor.
     * Initilize Database object and write it to property.
     * Set tables prefix.
     */
    protected function init()
    {
        if (method_exists(\Drupal::service('database'), 'tablePrefix')) {
          $this->prefix = \Drupal::service('database')->tablePrefix();
        } else {
          $this->prefix = \Drupal::service('database')->getPrefix();
        }
    }

    /**
     * Safely replace place holders
     *
     * @param string $query
     * @param array  $vars
     *
     * @return $this
     */
    public function prepareAndExecute($query, $vars = array())
    {
        $query = str_replace('%s', '?', $query);
        $this->db_result = \Drupal::service('database')->query($query, $vars);
        return $this->db_result;
    }

    /**
     * Run any raw request
     *
     * @param $query
     *
     * @return bool|int Raw result
     */
    public function execute($query, $returnAffected = false)
    {
        if ( $returnAffected ) {
          $this->db_result = \Drupal::service('database')->query($query, [], ['return' => 2]);
        } else {
          $this->db_result = \Drupal::service('database')->query($query);
        }

        return $this->db_result;
    }

    /**
     * Fetchs first column from query.
     * May receive raw or prepared query.
     *
     * @param bool $query
     * @param bool $response_type
     *
     * @return array|object|void|null
     */
    public function fetch( $query = false, $response_type = false )
    {
      if (!$query) {
        $query = $this->getQuery();
      }
      $this->result = \Drupal::service('database')->query($query)->fetchAssoc();

      return $this->result;
    }

    /**
     * Fetchs all result from query.
     * May receive raw or prepared query.
     *
     * @param bool $query
     * @param bool $response_type
     *
     * @return array|object|null
     */
    public function fetchAll( $query = false, $response_type = false )
    {

        $this->db_result = \Drupal::service('database')->query($query);
        $this->result = array();

        while ($row = $this->db_result->fetchAssoc()){
            $this->result[] = $row;
        }
        return $this->result;
    }

    public function getAffectedRows() {
        if ( is_int($this->db_result) ) {
            return $this->db_result;
        }
    }

    public function sfwGetFromBlacklist($table_name, $needles, $current_ip_v4)
    {
      $db = \Drupal::database();
      if ( $db->getProvider() === 'pgsql' ) {
        return "SELECT
				network, mask, status, source
				FROM " . $table_name . "
				WHERE network IN (" . implode(',', $needles) . ")
				AND	network = " . $current_ip_v4 . " & mask
				ORDER BY status DESC LIMIT 1";
      }
      return parent::sfwGetFromBlacklist($table_name, $needles, $current_ip_v4);
    }

    public function acGetFromBlacklist($table, $ip, $sign)
    {
      $db = \Drupal::database();
      if ( $db->getProvider() === 'pgsql' ) {
        return "SELECT ip"
          . " FROM " . $table
          . " WHERE ip = '$ip'"
          . " AND ua = '$sign';";
      }
      return parent::acGetFromBlacklist($table, $ip, $sign);
    }

  public function afGetFromBlacklist($table, $ip, $time)
  {
    return "SELECT SUM(entries) as total_count"
      . ' FROM ' . $table
      . " WHERE ip = '$ip' AND interval_start > '$time';";
  }

  public function resetAutoIncrement($table_name)
  {
    $db = \Drupal::database();
    if ( $db->getProvider() === 'pgsql' ) {
      return $this->execute("TRUNCATE TABLE $table_name RESTART IDENTITY"); // Drop AUTO INCREMENT
    }
    parent::resetAutoIncrement($table_name);
  }

  public function isTableExists($table_name)
  {
    $db = \Drupal::database();
    if ( $db->getProvider() === 'pgsql' ) {
      $sql = "SELECT EXISTS (SELECT FROM pg_tables WHERE  tablename = '$table_name')";
      return (bool)$this->execute($sql);
    }
    return parent::isTableExists($table_name);
  }

  public function renameTable($old_name, $new_name)
  {
    $db = \Drupal::database();
    if ( $db->getProvider() === 'pgsql' ) {
      $db->schema()->renameTable($old_name, $new_name);
      return true;
    }
    return parent::renameTable($old_name, $new_name);
  }

  public function getUpdateLogQuery($table, $module_name, $status, $ip, $source)
  {
    $db = \Drupal::database();
    if ( $db->getProvider() === 'pgsql' ) {
      $id   = md5($ip . $module_name);
      $time = time();
      $blocked_entries = strpos($status, 'DENY') !== false ? 1 : 0;
      return "INSERT INTO $table
        (id, ip, status, all_entries, blocked_entries, entries_timestamp, ua_name, source, network, first_url, last_url)
        VALUES ('$id', '$ip', '$status', 1, $blocked_entries, $time, %s, '$source', %s, %s, %s)
        ON CONFLICT (id) DO UPDATE
            SET status = '$status',
                source = '$source',
                all_entries = EXCLUDED.all_entries + 1,
                blocked_entries = EXCLUDED.blocked_entries" . (strpos($status, 'DENY') !== false ? ' + 1' : '') . ",
                entries_timestamp = '" . $time . "',
                ua_name = %s,
                network = %s,
                last_url = %s";
    }
    return parent::getUpdateLogQuery($table, $module_name, $status, $ip, $source);
  }
  public function getUpdateAcLogQuery($table, $id, $current_ip, $sign, $interval_time)
  {
    $db = \Drupal::database();
    if ( $db->getProvider() === 'pgsql' ) {
      return "INSERT INTO " . $table . "
				(id, ip, ua, entries, interval_start)
				VALUES ('$id', '$current_ip', '$sign', 1, $interval_time)
				ON CONFLICT (id) DO UPDATE
          SET ip = EXCLUDED.ip,
              entries = EXCLUDED.entries + 1,
              interval_start = $interval_time;";
    }
    return parent::getUpdateAcLogQuery($table, $id, $current_ip, $sign, $interval_time);
  }

  public function getCLearAcQuery($table, $interval_start, $sign)
  {
    $db = \Drupal::database();
    if ( $db->getProvider() === 'pgsql' ) {
      return "DELETE
				FROM " . $table . "
				WHERE interval_start < ". $interval_start ."
				AND ua = '$sign';";
    }
    return parent::getCLearAcQuery($table, $interval_start, $sign);
  }

  public function altCookiesStoreQuery($table)
  {
    $db = \Drupal::database();
    if ( $db->getProvider() === 'pgsql' ) {
      return "INSERT INTO {$table}
        (id, name, value, last_update)
        VALUES (:id, :name, :value, :last_update)
        ON CONFLICT (id, name) DO UPDATE
          SET value = :value,
              last_update = :last_update";
    }
    return parent::altCookiesStoreQuery($table);
  }

  public function altCookiesClearQuery($table)
  {
    $db = \Drupal::database();
    if ( $db->getProvider() === 'pgsql' ) {
      $time_interval = time() - APBCT_SESSION__LIVE_TIME;
      return "DELETE
          FROM {$table}
          WHERE last_update < TO_TIMESTAMP(" . $time_interval . ");"
        ;
    }
    return parent::altCookiesClearQuery($table);
  }
}
