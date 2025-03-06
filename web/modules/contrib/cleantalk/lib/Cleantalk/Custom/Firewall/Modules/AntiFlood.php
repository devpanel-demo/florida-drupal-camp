<?php

namespace Cleantalk\Custom\Firewall\Modules;

use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Common\Firewall\FirewallModule;
use Cleantalk\Common\Variables\Server;
use Drupal\cleantalk\CleantalkFuncs;

class AntiFlood extends FirewallModule
{

    public $module_name = 'ANTIFLOOD';

    /**
     * @var mixed|null
     */
    private $db__table__logs;

    /**
     * @var mixed|null
     */
    private $db__table__ac_logs;

    /**
     * @var string|null
     */
    private $db__table__ac_ua_bl;

    /**
     * @var mixed|null
     */
    private $view_limit;
    private $store_interval  = 60;
    private $chance_to_clean = 20;

    /**
     * @var string
     */
  private $sign;

  private $db__table__sfw;

  /**
     * @throws \Exception
     */
    public function __construct($log_table, $params = array())
    {
        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db = $db_class::getInstance();
        $this->db = $db;

        foreach ($params as $param_name => $param) {
            if ( in_array($param_name, array_keys(get_class_vars(__CLASS__))) ) {
                $this->$param_name = isset($this->$param_name) ? $param : false;
            } else {
                throw new \Exception('trying to set value for undeclared attribute ' . $param_name . ' in class ' . __CLASS__);
            }
        }

        $this->db__table__logs    = $db->prefix . $log_table ?: null;
        $this->db__table__ac_logs = $params['db__table__ac_logs'] ? $db->prefix . $params['db__table__ac_logs'] : null;
        $this->db__table__ac_ua_bl = defined('APBCT_TBL_AC_UA_BL') ? $db->prefix . APBCT_TBL_AC_UA_BL : null;
        $this->db__table__sfw = $params['db__table__sfw'] ? $db->prefix . $params['db__table__sfw'] : null;
        $this->sign = md5(Server::get('HTTP_USER_AGENT') . Server::get('HTTPS') . Server::get('HTTP_HOST'));
        $this->view_limit = isset($params['view_limit']) ? $params['view_limit'] : null;
    }

    public function check()
    {
        $results = array();

        $this->clearTable();

        $time = time() - $this->store_interval;

        foreach( $this->ip_array as $current_ip ) {

            // UA check
            $ua_bl_results = $this->db->fetchAll(
                "SELECT * FROM " . $this->db__table__ac_ua_bl . " ORDER BY ua_status DESC;"
            );

            if(! empty($ua_bl_results) ) {

                foreach( $ua_bl_results as $ua_bl_result ){

                    if(! empty($ua_bl_result['ua_template']) && preg_match("%". str_replace('"', '', $ua_bl_result['ua_template']) ."%i", Server::get('HTTP_USER_AGENT')) ) {

                        if($ua_bl_result['ua_status'] == 1 ) {
                            // Whitelisted
                            $results[] = array('ip' => $current_ip, 'is_personal' => false, 'status' => 'PASS_ANTIFLOOD_UA',);
                            return $results;
                        }

                    }

                }

            }

            // Passed
            if(CleantalkFuncs::apbct_getcookie('apbct_antiflood_passed') === md5($current_ip . $this->api_key) ) {

                if(! headers_sent() ) {
                    CleantalkFuncs::apbct_setcookie('apbct_antiflood_passed', '0');
                }

                // Do logging an one passed request
                $this->updateLog($current_ip, 'PASS_ANTIFLOOD');

                $results[] = array( 'ip' => $current_ip, 'is_personal' => false, 'status' => 'PASS_ANTIFLOOD', );

                return $results;
            }

            // @todo Rename ip column to sign. Use IP + UserAgent for it.

            $query = $this->db->afGetFromBlacklist($this->db__table__ac_logs, $current_ip, $time);
            $result = $this->db->fetch($query);

            if(! empty($result) && isset($result['total_count']) && $result['total_count'] >= $this->view_limit ) {
                  $results[] = array( 'ip' => $current_ip, 'is_personal' => false, 'status' => 'DENY_ANTIFLOOD', );
            }
        }

        if(! empty($results) ) {
            // Do block page
            return $results;
        } else{
            $this->updateAcLog();
        }

        return $results;
    }

    public function actionsForDenied($result)
    {
        // TODO: Implement actionsForDenied() method.
    }

    public function actionsForPassed($result)
    {
        // TODO: Implement actionsForPassed() method.
    }

    public function clearTable()
    {
        if(rand(0, 100) < $this->chance_to_clean ) {
            /** @var \Cleantalk\Common\Helper\Helper $helper_class */
            $helper_class = Mloader::get('Helper');
            $interval_start = $helper_class::timeGetIntervalStart($this->store_interval);
            $query = $this->db->getCLearAcQuery($this->db__table__ac_logs, $interval_start, $this->sign);
            $this->db->execute($query);
        }
    }

    /**
     * Add entry to SFW log.
     * Writes to database.
     *
     * @param string $ip
     * @param $status
     */
    public function updateLog( $ip, $status, $network = null, $source = null )
    {
        if(!$source) {
          $source = 0;
        }
        if(!$network) {
          $network = 'NULL';
        }

        $query = $this->db->getUpdateLogQuery($this->db__table__logs, $this->module_name, $status, $ip, $source);

        $vars = array(
          Server::get('HTTP_USER_AGENT'),
          $network,
          substr(Server::get('HTTP_HOST') . Server::get('REQUEST_URI'), 0, 100),
          substr(Server::get('HTTP_HOST') . Server::get('REQUEST_URI'), 0, 100),

          Server::get('HTTP_USER_AGENT'),
          $network,
          substr(Server::get('HTTP_HOST') . Server::get('REQUEST_URI'), 0, 100),
        );

        $this->db->prepareAndExecute($query, $vars);
    }

    /**
     * Update ac logs table
     */
    public function updateAcLog()
    {
        /** @var \Cleantalk\Common\Helper\Helper $helper_class */
        $helper_class = Mloader::get('Helper');
        $interval_time = $helper_class::timeGetIntervalStart($this->store_interval);

        foreach( $this->ip_array as $current_ip ){
            $id = md5($current_ip . $this->sign . $interval_time);
            $query = $this->db->getUpdateAcLogQuery($this->db__table__ac_logs, $id, $current_ip, $this->sign, $interval_time);
            $this->db->execute($query);
        }
    }

    public function diePage( $result )
    {

        parent::diePage($result);

        /** @var \Cleantalk\Common\RemoteCalls\Remotecalls $remote_calls_class */
        $remote_calls_class = Mloader::get('RemoteCalls');

        // File exists?
        if(file_exists(__DIR__ . '/die_page_antiflood.html') ) {

            $die_page = file_get_contents(__DIR__ . '/die_page_antiflood.html');

            $net_count = $this->db->fetch('SELECT COUNT(*) as net_count FROM ' . $this->db__table__sfw)['net_count'];

            // Translation
            $replaces = array(
            '{SFW_DIE_NOTICE_IP}'              => 'Anti-Flood is activated for your IP',
            '{SFW_DIE_MAKE_SURE_JS_ENABLED}'   => 'To continue working with the web site, please make sure that you have enabled JavaScript.',
            '{SFW_DIE_YOU_WILL_BE_REDIRECTED}' => sprintf('You will be automatically redirected to the requested page after %d seconds.', 30),
            '{CLEANTALK_TITLE}'                => 'Antispam by CleanTalk',
            '{REMOTE_ADDRESS}'                 => $result['ip'],
            '{REQUEST_URI}'                    => Server::get('REQUEST_URI'),
            '{SERVICE_ID}'                     => $net_count,
            '{HOST}'                           => $remote_calls_class::getSiteUrl(),
            '{GENERATED}'                      => '<p>The page was generated at&nbsp;' . date('D, d M Y H:i:s') . "</p>",
            '{COOKIE_ANTIFLOOD_PASSED}'        => md5($result['ip'] . $this->api_key),
            '{USE_ALT_COOKIES}'                => \Drupal::config('cleantalk.settings')->get('cleantalk_alternative_cookies_session') ? 1 : 0
            );

            foreach( $replaces as $place_holder => $replace ){
                $die_page = str_replace($place_holder, $replace, $die_page);
            }

            die($die_page);

        }

        die("IP BLACKLISTED. Blocked by AntiFlood " . $result['ip']);

    }

}
