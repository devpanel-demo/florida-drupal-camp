<?php

namespace Cleantalk\Custom\Firewall\Modules;

use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Common\Firewall\FirewallModule;
use Cleantalk\Common\Variables\Server;
use Drupal\cleantalk\CleantalkFuncs;

class AntiCrawler extends FirewallModule
{

    /**
     * Public module name
     *
     * @var string
     */
    public $module_name = 'ANTICRAWLER';

    /**
     * Signature - User-Agent + Protocol
     *
     * @var string
     */
    private $sign;

    private $store_interval = 60;

    /**
     * @var false|string
     */
    private $antibot_cookie_value;

    /**
     * @var string
     */
    private $ua_bl_table_name;

    /**
     * @var string|null
     */
    private $db__table__ac_logs;

    /**
     * @var string|null
     */
    private $db__table__sfw_logs;

    private $db__table__sfw;

    public function __construct($data_table = 'cleantalk_ac_logs', $params = [])
    {
        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db = $db_class::getInstance();
        $this->db = $db;

        $this->ua_bl_table_name = $db->prefix . $data_table;
        $this->db__table__ac_logs = $params['db__table__ac_logs'] ? $db->prefix . $params['db__table__ac_logs'] : null;
        $this->db__table__sfw_logs = $params['db__table__sfw_logs'] ? $db->prefix . $params['db__table__sfw_logs'] : null;
        $this->db__table__sfw = $params['db__table__sfw'] ? $db->prefix . $params['db__table__sfw'] : null;
        $this->sign = md5(Server::get('HTTP_USER_AGENT') . Server::get('HTTPS') . Server::get('HTTP_HOST'));
        $this->antibot_cookie_value = CleantalkFuncs::create_ac_cookie_value();
    }

    /**
     * Use this method to execute main logic of the module.
     *
     * @return array  Array of the check results
     */
    public function check()
    {
        $results = array();

        foreach( $this->ip_array as $current_ip ) {

            // Skip by cookie
            if(CleantalkFuncs::apbct_getcookie('apbct_antibot') == $this->antibot_cookie_value ) {
                if(CleantalkFuncs::apbct_getcookie('apbct_anticrawler_passed') == 1 ) {
                    if(! headers_sent() ) {
                        CleantalkFuncs::apbct_setcookie('apbct_anticrawler_passed', '0');
                    }
                }

                $results[] = array( 'ip' => $current_ip, 'is_personal' => false, 'status' => 'PASS_ANTICRAWLER', );

                return $results;
            }

            // Skip by 301 response code
            if($this->isRedirected() ) {
                $results[] = array( 'ip' => $current_ip, 'is_personal' => false, 'status' => 'PASS_ANTICRAWLER', );
                return $results;
            }

            // UA check
            $ua_bl_results = $this->db->fetchAll(
                "SELECT * FROM " . $this->ua_bl_table_name . " ORDER BY ua_status DESC;"
            );

            if(! empty($ua_bl_results) ) {

                  $is_blocked = false;

                foreach( $ua_bl_results as $ua_bl_result ) {

                    if(! empty($ua_bl_result['ua_template']) && preg_match("%". str_replace('"', '', $ua_bl_result['ua_template']) ."%i", Server::get('HTTP_USER_AGENT')) ) {

                        if($ua_bl_result['ua_status'] == 1 ) {
                            // Whitelisted
                            $results[] = array('ip' => $current_ip, 'is_personal' => false, 'status' => 'PASS_ANTICRAWLER_UA',);
                            return $results;
                        } else {
                            // Blacklisted
                            $results[] = array('ip' => $current_ip, 'is_personal' => false, 'status' => 'DENY_ANTICRAWLER_UA',);
                            $is_blocked = true;
                            break;
                        }
                    }
                }

                if(! $is_blocked ) {
                    $results[] = array('ip' => $current_ip, 'is_personal' => false, 'status' => 'PASS_ANTICRAWLER_UA',);
                }
            }
        }

        // Common check
        foreach( $this->ip_array as $current_ip ) {

            // IP check
            $query = $this->db->acGetFromBlacklist($this->db__table__ac_logs, $current_ip, $this->sign);
            $result = $this->db->fetch($query);

            if(isset($result['ip']) ) {
                if(CleantalkFuncs::apbct_getcookie('apbct_antibot') !== $this->antibot_cookie_value ) {
                    $results[] = array( 'ip' => $current_ip, 'is_personal' => false, 'status' => 'DENY_ANTICRAWLER', );
                }else{
                    if(CleantalkFuncs::apbct_getcookie('apbct_anticrawler_passed') === '1' ) {
                        if(! headers_sent() ) {
                            CleantalkFuncs::apbct_setcookie('apbct_anticrawler_passed', '0');
                        }

                        // Do logging an one passed request
                        $this->updateLog($current_ip, 'PASS_ANTICRAWLER');

                        $results[] = array( 'ip' => $current_ip, 'is_personal' => false, 'status' => 'PASS_ANTICRAWLER', );

                        return $results;
                    }
                }

            }else{

                if(! CleantalkFuncs::apbct_getcookie('apbct_antibot') ) {
                    $this->updateAcLog();
                }
            }
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

    private function isRedirected()
    {
        $is_redirect = false;
        if(Server::get('HTTP_REFERER') !== '' && Server::get('HTTP_HOST') !== '' && $this->isCloudflare() ) {
            $parse_referer = parse_url(Server::get('HTTP_REFERER'));
            if($parse_referer && isset($parse_referer['host']) ) {
                $is_redirect = Server::get('HTTP_HOST') !== $parse_referer['host'];
            }
        }
        return http_response_code() === 301 || http_response_code() === 302 || $is_redirect;
    }

    private function isCloudflare()
    {
        return Server::get('HTTP_CF_RAY') && Server::get('HTTP_CF_CONNECTING_IP') && Server::get('HTTP_CF_REQUEST_ID');
    }

    /**
     * Add entry to SFW log.
     * Writes to database.
     *
     * @param string $ip
     * @param string $status
     * @param string $network
     * @param int $source
     */
    public function updateLog( $ip, $status, $network = null, $source = null )
    {
        if(!$source) {
          $source = 0;
        }
        if(!$network) {
          $network = 'NULL';
        }

        $query = $this->db->getUpdateLogQuery($this->db__table__sfw_logs, $this->module_name, $status, $ip, $source);

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

    /**
     * @inheritdoc
     */
    public function diePage( $result )
    {
        parent::diePage($result);

        /** @var \Cleantalk\Common\RemoteCalls\Remotecalls $remote_calls_class */
        $remote_calls_class = Mloader::get('RemoteCalls');

        // File exists?
        if(file_exists(__DIR__ . "/die_page_anticrawler.html")) {

            $die_page = file_get_contents(__DIR__ . "/die_page_anticrawler.html");

            $net_count = $this->db->fetch('SELECT COUNT(*) as net_count FROM ' . $this->db__table__sfw)['net_count'];

            // Translation
            $replaces = array(
            '{SFW_DIE_NOTICE_IP}'              => 'Anti-Crawler Protection is activated for your IP ',
            '{SFW_DIE_MAKE_SURE_JS_ENABLED}'   => 'To continue working with the web site, please make sure that you have enabled JavaScript.',
            '{SFW_DIE_YOU_WILL_BE_REDIRECTED}' => 'You will be automatically redirected to the requested page after 3 seconds.<br>' . 'Don\'t close this page. Please, wait for 3 seconds to pass to the page.',
            '{CLEANTALK_TITLE}'                => 'Antispam by CleanTalk',
            '{REMOTE_ADDRESS}'                 => $result['ip'],
            '{SERVICE_ID}'                     => $net_count,
            '{HOST}'                           => $remote_calls_class::getSiteUrl(),
            '{COOKIE_ANTICRAWLER}'             => $this->antibot_cookie_value,
            '{COOKIE_ANTICRAWLER_PASSED}'      => '1',
            '{GENERATED}'                      => '<p>The page was generated at&nbsp;' . date('D, d M Y H:i:s') . "</p>",
            '{USE_ALT_COOKIES}'                => \Drupal::config('cleantalk.settings')->get('cleantalk_alternative_cookies_session') ? 1 : 0,
            );

            foreach( $replaces as $place_holder => $replace ){
                $die_page = str_replace($place_holder, $replace, $die_page);
            }

            if(isset($_GET['debug']) ) {
                $debug = '<h1>Headers</h1>'
                . str_replace("\n", "<br>", print_r(\apache_request_headers(), true))
                . '<h1>$_SERVER</h1>'
                . str_replace("\n", "<br>", print_r($_SERVER, true))
                . '<h1>IPS</h1>'
                . str_replace("\n", "<br>", print_r($this->ip_array, true));
            }else{
                $debug = '';
            }
            $die_page = str_replace("{DEBUG}", $debug, $die_page);

            die($die_page);
        }

        die("IP BLACKLISTED. Blocked by AntiCrawler " . $result['ip']);
    }

}
