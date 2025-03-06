<?php

namespace Drupal\cleantalk\Form;

use Cleantalk\Common\Firewall\Firewall;
use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Common\Queue\Queue;
use Cleantalk\Common\Variables\Post;
use Cleantalk\Common\Variables\Server;
use Cleantalk\Custom\Antispam\Cleantalk;
use Cleantalk\Custom\Antispam\CleantalkRequest;
use Drupal\cleantalk\Service\CleantalkDebug;
use Drupal\Component\Render\FormattableMarkup;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

use Cleantalk\Common\Api\Api as CleantalkAPI;
use Cleantalk\Custom\Helper\Helper as CleantalkHelper;
use Drupal\cleantalk\CleantalkFuncs;

class CleantalkSettingsForm extends ConfigFormBase
{
    /**
     * {@inheritdoc}
     */

    public function getFormId()
    {

        return 'cleantalk_settings_form';

    }

    /**
     * {@inheritdoc}
     */

    public function submitForm(array &$form, FormStateInterface $form_state)
    {

        $config = $this->config('cleantalk.settings');

        $config_values = $form_state->getValues();

        foreach ( $config_values as $key => $value ) {

            if ( strpos($key, 'cleantalk') !== false ) {

                $config->set($key, $value);

            }

        }

        $config->save();

        if ( method_exists($this, '_submitForm') ) {

            $this->_submitForm($form, $form_state);

        }

        parent::submitForm($form, $form_state);

    }

    /**
     * {@inheritdoc}
     */

    public function validateForm(array &$form, FormStateInterface $form_state)
    {

        $key_is_valid = CleantalkHelper::isApikeyCorrect(trim($form_state->getValue('cleantalk_authkey') ?: ''));

        if ( $this->handleServeButtons() ) {
            return;
        }

        if ( $key_is_valid ) {

            $ct_request = new CleantalkRequest(array(
                // General
                'auth_key' => $form_state->getValue('cleantalk_authkey'),
                // Additional
                'feedback' => '0:' . CLEANTALK_USER_AGENT,
            ));
            $ct = new Cleantalk();
            $ct->server_url     = CLEANTALK_MODERATE_URL;
            $ct->sendFeedback($ct_request);

            $path_to_cms = preg_replace('/http[s]?:\/\//', '', $GLOBALS['base_url'], 1);
            $account_status = CleantalkAPI::methodNoticePaidTill($form_state->getValue('cleantalk_authkey'), $path_to_cms);

            $validation_has_error = $this->getKeyValidationError($account_status);

            if (false === $validation_has_error) {

                if ( $form_state->getValue('cleantalk_sfw') === 1 ) {
                    CleantalkFuncs::apbct_sfw_update($form_state->getValue('cleantalk_authkey'));
                    CleantalkFuncs::apbct_sfw_send_logs($form_state->getValue('cleantalk_authkey'));
                }

            } else {

              $form_state->setErrorByName(
                '',
                $this->t($validation_has_error));
            }

            \Drupal::state()->set('cleantalk_api_show_notice', (empty($account_status['error']) && isset($account_status['show_notice'])) ? $account_status['show_notice'] : 0);
            \Drupal::state()->set('cleantalk_api_renew', (empty($account_status['error']) && isset($account_status['renew'])) ? $account_status['renew'] : 0);
            \Drupal::state()->set('cleantalk_api_trial', (empty($account_status['error']) && isset($account_status['trial'])) ? $account_status['trial'] : 0);
            \Drupal::state()->set('cleantalk_api_user_token', (empty($account_status['error']) && isset($account_status['user_token'])) ? $account_status['user_token'] : '');
            \Drupal::state()->set('cleantalk_api_spam_count', (empty($account_status['error']) && isset($account_status['spam_count'])) ? $account_status['spam_count'] : 0);
            \Drupal::state()->set('cleantalk_api_moderate_ip', (empty($account_status['error']) && isset($account_status['moderate_ip'])) ? $account_status['moderate_ip'] : 0);
            \Drupal::state()->set('cleantalk_api_moderate', (empty($account_status['error']) && isset($account_status['moderate'])) ? $account_status['moderate'] : 0);
            \Drupal::state()->set('cleantalk_api_show_review', (empty($account_status['error']) && isset($account_status['show_review'])) ? $account_status['show_review'] : 0);
            \Drupal::state()->set('cleantalk_api_service_id', (empty($account_status['error']) && isset($account_status['service_id'])) ? $account_status['service_id'] : 0);
            \Drupal::state()->set('cleantalk_api_license_trial', (empty($account_status['error']) && isset($account_status['license_trial'])) ? $account_status['license_trial'] : 0);
            \Drupal::state()->set('cleantalk_api_account_name_ob', (empty($account_status['error']) && isset($account_status['account_name_ob'])) ? $account_status['account_name_ob'] : '');
            \Drupal::state()->set('cleantalk_api_ip_license', (empty($account_status['error']) && isset($account_status['ip_license'])) ? $account_status['ip_license'] : 0);
            \Drupal::state()->set('cleantalk_show_renew_banner', (\Drupal::state()->get('cleantalk_api_show_notice') && \Drupal::state()->get('cleantalk_api_trial')) ? 1 : 0);

        }

        // Turns off alternative cookies setting if cookies are disabled
        if ( 0 == $form_state->getValue('cleantalk_set_cookies') ) {
            $form_state->setValue('cleantalk_alternative_cookies_session', 0);
        }

        // Turns off capturing buffer if external forms protection is disabled
        if ( 0 == $form_state->getValue('cleantalk_check_external') ) {
            $form_state->setValue('cleantalk_check_external__capture_buffer', 0);
        }

        // Validating the URL exclusion string
        if ( $form_state->getValue('cleantalk_url_regexp') || $form_state->getValue('cleantalk_fields_regexp') ) {
            $this->validateFormRegexpExclusions($form_state);
        }

    }

  /**
   * Validate notice_paid_till result to extract validation errors.
   *
   * @param $account_status
   *
   * @return false|string False if no errors found, the error text otherwise.
   */
  private function getKeyValidationError($account_status)
    {
      $error = false;
      $error_prefix = 'Key validation error: ';
      $error_contact_link = 'Please, contact us via support@cleantalk.org';

      if (!empty($account_status['error'])) {
        if ($account_status['error'] === 'CURL_NOT_INSTALLED') {
          $error = $error_prefix . 'cUrl extension is disabled in the PHP config. Please, enable cURL to use CleanTalk services.';
        } else {
          $error = $error_prefix . 'unexpected API error ['
            . isset($account_status['error']) ? (string)($account_status['error']) : 'unknown error'
            . '] '
            . $error_contact_link;
        }
      } else {
        if ($account_status['valid'] == 0) {
          $error = $error_prefix . 'key is not valid or is expired.';
        }
      }

      return $error;
    }

    protected function validateFormRegexpExclusions(&$form_state)
    {
        if ( !empty ($form_state) ) {

            $exclusion_sources = array(
                'cleantalk_fields_regexp' => array(
                    'display_name' => 'Fields exclusions',
                    'settings_path' => 'cleantalk_fields_exclusions'
                ),
                'cleantalk_url_regexp' => array(
                    'display_name' => 'URL exclusions',
                    'settings_path' => 'cleantalk_url_exclusions'
                )
            );

            foreach ( $exclusion_sources as $source => $params ) {
                if ( $form_state->getValue($source) ) {
                    $errors = array();
                    $exclusions = $form_state->getValue($params['settings_path']) ?: array();

                    if ( !empty($exclusions) ) {
                        $exclusions = explode(',', $exclusions);
                        foreach ( $exclusions as $exclusion ) {
                            $sanitized_exclusion = trim($exclusion);
                            if ( !empty($sanitized_exclusion) && !self::apbct_is_regexp($sanitized_exclusion) ) {
                                $errors[] = $sanitized_exclusion;
                            }
                        }
                        if ( !empty($errors) ) {
                            // Remove the variable (setting) from BD if is not valid
                            $config = \Drupal::service('config.factory')->getEditable('cleantalk.settings');
                            $config->set($params['settings_path'], '')->save();
                            // And trigger an error
                            $form_state->setErrorByName(
                                $params['settings_path'],
                                $this->t($params['display_name'] . ' regexp is not valid: ') . implode(', ', $errors));
                        }
                    }
                }
            }
        }
    }

    /**
     * {@inheritdoc}
     */

    protected function getEditableConfigNames()
    {

        return ['cleantalk.settings'];

    }

    public function buildForm(array $form, \Drupal\Core\Form\FormStateInterface $form_state)
    {

        // EU Cookie Compliance cookie banner

        if ( \Drupal::service('module_handler')->moduleExists('eu_cookie_compliance') ) {
            $allowed_cookies = array('ct_check_js', 'ct_timezone', 'ct_pointer_data', 'ct_fkp_timestamp', 'ct_ps_timestamp', 'apbct_timestamp', 'apbct_cookies_test');
            $cooke_module_option = \Drupal::config('eu_cookie_compliance.settings')->get('allowed_cookies');
            $show_banner = false;
            foreach ( $allowed_cookies as $cookie ) {
                if ( strpos($cooke_module_option, $cookie) === false ) {
                    $show_banner = true;
                }
            }
            if ( $show_banner ) {
                \Drupal::messenger()->addMessage(t("EU Cookie Compliance module is enabled. Please, add an exclusion for <a href = 'https://cleantalk.org/help/install-drupal9#attention' target='_blank'>these</a> cookies."), 'warning', false);
            }
        }

        //Renew banner

        if ( \Drupal::state()->get('cleantalk_show_renew_banner') ) {

            $link = (\Drupal::state()->get('cleantalk_api_trial')) ? 'https://cleantalk.org/my/bill/recharge?utm_source=banner&utm_medium=wp-backend&utm_campaign=Drupal%20backend%20trial&user_token=' : 'https://cleantalk.org/my/bill/recharge?utm_source=banner&utm_medium=wp-backend&utm_campaign=Drupal%20backend%20renew&user_token=';

            \Drupal::messenger()->addMessage(t("Cleantalk module trial period ends, please upgrade to <a href='" . $link . \Drupal::state()->get('cleantalk_api_user_token') . "' target='_blank'><b>premium version</b></a> ."), 'warning', false);

        }

        if ( \Drupal::state()->get('cleantalk_api_account_name_ob') ) {

            $key_description = $this->t('Account at cleantalk.org is <b>' . \Drupal::state()->get('cleantalk_api_account_name_ob') . '</b>');

        } elseif ( \Drupal::state()->get('cleantalk_api_moderate_ip') == 1 ) {

            $key_description = $this->t('The anti-spam service is paid by your hosting provider. License #<b>' . \Drupal::state()->get('cleantalk_api_ip_license') . '</b>');

        } else {

            $key_description = $this->t('Click <a target="_blank" href="https://cleantalk.org/register?platform=drupal">here</a> to get access key.');
        }

        $fw_stats = Firewall::getFwStats();
        if ( !empty($fw_stats->errors) ) {
            foreach ( $fw_stats->errors as $error ) {
                $msg = $this->t('CleanTalk SFW update error: ')
                    . $error
                    . $this->t('. Please, save settings to run new SFW update and wait for an hour.');
                \Drupal::messenger()->addMessage($msg, 'warning');
            }
        }

        $form['cleantalk_authkey'] = [
            '#type' => 'textfield',
            '#title' => $this->t('Access key'),
            '#size' => 20,
            '#maxlength' => 20,
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_authkey') ?: '',
            '#description' => $key_description,
            '#value_callback' => [static::class, 'apiKeyTrim']
        ];

        $form['cleantalk_comments'] = array(
            '#type' => 'fieldset',
            '#title' => $this->t('Comments'),
        );

        $form['cleantalk_comments']['cleantalk_check_comments'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Check comments'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_check_comments'),
            '#description' => $this->t('Enabling this option will allow you to check all comments on your website.'),
        );

        $form['cleantalk_comments']['cleantalk_check_comments_automod'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Enable automoderation'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_check_comments_automod'),
            '#description' => $this->t('Automatically put suspicious comments which may not be 100% spam to manual approvement and block obvious spam comments.') .
                '<br /><span class="admin-missing">' .
                $this->t('Note: If disabled, all suspicious comments will be automatically blocked!') .
                '</span>',
            '#states' => array(
                // Only show this field when the value when checking comments is enabled
                'disabled' => array(
                    ':input[name="cleantalk_check_comments"]' => array('checked' => false),
                ),
            ),
        );

        $form['cleantalk_comments']['cleantalk_check_comments_min_approved'] = array(
            '#type' => 'number',
            '#title' => $this->t('Minimum approved comments per registered user'),
            '#min' => 1,
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_check_comments_min_approved'),
            '#description' => $this->t('Moderate messages of guests and registered users who have approved messages less than this value.'),
            '#states' => array(
                // Only show this field when the value when checking comments is enabled
                'disabled' => array(
                    ':input[name="cleantalk_check_comments"]' => array('checked' => false),
                ),
            ),
        );

        $form['cleantalk_search'] = array(
            '#type' => 'fieldset',
            '#title' => $this->t('Search'),
        );

        $form['cleantalk_search']['cleantalk_check_search_form'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Check search form'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_check_search_form'),
            '#description' => $this->t('Enabling this option will allow you to check search form on your website.'),
        );

        $form['cleantalk_search']['cleantalk_search_noindex'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Add noindex for search form'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_search_noindex'),
            '#description' => $this->t('Add html meta-tag robots-noindex to search form.'),
        );

        $form['cleantalk_exclusions'] = array(
            '#type' => 'fieldset',
            '#title' => $this->t('Exclusions'),
        );

        // Container URL_EXCLUSIONS
        $form['cleantalk_exclusions']['cleantalk_url_exclusions_fieldset'] = array(
            '#type' => 'fieldset',
            '#title' => $this->t('URL exclusions'),
            '#description' => $this->t('Exclude urls from spam check. List them separated by commas.'),
        );
        $form['cleantalk_exclusions']['cleantalk_url_exclusions_fieldset']['cleantalk_url_exclusions_container_inline'] = array(
            '#type' => 'container',
            '#attributes' => array(
                'class' => array(
                    'container-inline'
                ),
            ),
        );
        $form['cleantalk_exclusions']['cleantalk_url_exclusions_fieldset']['cleantalk_url_exclusions_container_inline']['cleantalk_url_exclusions'] = array(
            '#type' => 'textfield',
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_url_exclusions'),
        );
        $form['cleantalk_exclusions']['cleantalk_url_exclusions_fieldset']['cleantalk_url_exclusions_container_inline']['cleantalk_url_regexp'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Regular expression'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_url_regexp'),
        );

        // Container FIELDS_EXCLUSIONS
        $form['cleantalk_exclusions']['cleantalk_fields_exclusions_fieldset'] = array(
            '#type' => 'fieldset',
            '#title' => $this->t('Fields exclusions'),
            '#description' => $this->t('Add the "name" attribute value of the field you want to be excluded. For example if the <"name="test"> then add <b>test</b>.'),
        );
        $form['cleantalk_exclusions']['cleantalk_fields_exclusions_fieldset']['cleantalk_fields_exclusions_container_inline'] = array(
            '#type' => 'container',
            '#attributes' => array(
                'class' => array(
                    'container-inline'
                ),
            ),
        );
        $form['cleantalk_exclusions']['cleantalk_fields_exclusions_fieldset']['cleantalk_fields_exclusions_container_inline']['cleantalk_fields_exclusions'] = array(
            '#type' => 'textfield',
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_fields_exclusions'),
        );
        $form['cleantalk_exclusions']['cleantalk_fields_exclusions_fieldset']['cleantalk_fields_exclusions_container_inline']['cleantalk_fields_regexp'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Regular expression'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_fields_regexp'),
        );


        // Container ROLES_EXCLUSIONS
        $form['cleantalk_exclusions']['cleantalk_roles_exclusions_fieldset'] = array(
            '#type' => 'fieldset',
            '#title' => $this->t('Roles checking'),
            '#description' => $this->t('Roles which bypass spam test. You can select multiple roles.'),
        );
        $form['cleantalk_exclusions']['cleantalk_roles_exclusions_fieldset']['cleantalk_roles_exclusions_container_inline'] = array(
            '#type' => 'container',
            '#attributes' => array(
                'class' => array(
                    'container-inline'
                ),
            ),
        );
        $form['cleantalk_exclusions']['cleantalk_roles_exclusions_fieldset']['cleantalk_roles_exclusions_container_inline']['cleantalk_roles_exclusions'] = array(
            '#type' => 'select',
            '#options' => CleantalkFuncs::cleantalk_get_user_roles(),
            '#multiple' => true,
            '#default_value' => CleantalkFuncs::cleantalk_get_user_roles_default(),
        );

        $form['cleantalk_check_register'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Check registrations'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_check_register'),
            '#description' => $this->t('Enabling this option will allow you to check all registrations on your website.'),
        );

        $form['cleantalk_check_webforms'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Check webforms'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_check_webforms'),
            '#description' => $this->t('Enabling this option will allow you to check all webforms on your website.'),
        );

        $form['cleantalk_check_contact_forms'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Check contact forms'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_check_contact_forms'),
            '#description' => $this->t('Enabling this option will allow you to check all contact forms on your website.'),
        );

        $form['cleantalk_check_forum_topics'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Check forum topics'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_check_forum_topics'),
            '#description' => $this->t('Enabling this option will allow you to check all forum topics on your website.'),
        );

        $form['cleantalk_check_added_content'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Check added content'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_check_added_content'),
            '#description' => $this->t('Enabling this option will allow you to check all added content (pages, articles, etc) by non-admin users on your website.'),
        );

        $form['cleantalk_check_ccf'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Check custom forms'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_check_ccf'),
            '#description' => $this->t('Enabling this option will allow you to check all forms on your website.') .
                '<br /><span class="admin-missing">' .
                $this->t('Note: May cause conflicts!') .
                '</span>',
        );

        $form['cleantalk_check_external'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Check external forms'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_check_external'),
            '#description' => $this->t('Turn this option on to protect forms on your website that send data to third-part servers (like MailChimp).'),
        );

        $form['cleantalk_check_external__capture_buffer'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Capture buffer'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_check_external__capture_buffer'),
            '#description' => $this->t('This setting gives you more sophisticated and strengthened protection for external forms.'),
            '#states' => array(
                // Only show this field when the value when checking comments is enabled
                'invisible' => array(
                    ':input[name="cleantalk_check_external"]' => array('checked' => false),
                ),
            ),
        );

        $form['cleantalk_set_cookies'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Set cookies'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_set_cookies'),
            '#description' => $this->t('Turn this option off to deny plugin generates any cookies on website front-end. This option is helpful if you use Varnish. But most of contact forms will not be protected if the option is turned off!') . '<br /><span class="admin-disabled">' .
                $this->t('Note: We strongly recommend you to enable this otherwise it could cause false positives spam detection.') .
                '</span>',
        );

        $form['cleantalk_alternative_cookies_session'] = array(
            '#type' => 'checkbox',
            '#title' => $this->t('Use alternative mechanism for cookies'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_alternative_cookies_session'),
            '#description' => $this->t('Doesn\'t use cookie or PHP sessions. Collect data for all types of bots.'),
            '#states' => array(
                // Only show this field when the value when checking comments is enabled
                'invisible' => array(
                    ':input[name="cleantalk_set_cookies"]' => array('checked' => false),
                ),
            ),
        );

        $form['cleantalk_sfw'] = [
            '#type' => 'checkbox',
            '#title' => $this->t('SpamFireWall'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_sfw'),
            '#description' => $this->t('This option allows to filter spam bots before they access website. Also reduces CPU usage on hosting server and accelerates pages load time.'),
        ];

        $form['cleantalk_sfw_ac'] = [
            '#type' => 'checkbox',
            '#title' => $this->t('Anti-Crawler'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_sfw_ac'),
            '#description' => $this->t(
                'Plugin shows SpamFireWall stop page for any bot, except allowed bots (Google, Yahoo and etc).
                                        Anti-Crawler includes blocking bots by the User-Agent. Use Personal lists in the Dashboard to filter specific User-Agents.'
            ),
            '#states' => array(
                // Only show this field when SFW is enabled
                'invisible' => array(
                    ':input[name="cleantalk_sfw"]' => array('checked' => false),
                ),
            ),
        ];

        /**
         * Antiflood settings
         * ==================
         */
        $form['cleantalk_sfw_antiflood'] = [
            '#type' => 'checkbox',
            '#title' => $this->t('Anti-Flood'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_sfw_antiflood'),
            '#description' => $this->t('Shows the SpamFireWall page for bots trying to crawl your site. Look at the page limit setting below.'),
            '#states' => array(
                // Only show this field when SFW is enabled
                'invisible' => array(
                    ':input[name="cleantalk_sfw"]' => array('checked' => false),
                ),
            ),
        ];

        $form['cleantalk_sfw_antiflood_limit'] = array(
            '#type' => 'number',
            '#title' => $this->t('Anti-Flood Page Views Limit'),
            '#min' => 20,
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_sfw_antiflood_limit'),
            '#description' => $this->t('Count of page view per 1 minute before plugin shows SpamFireWall page. SpamFireWall page active for 30 second after that valid visitor (with JavaScript) passes the page to the demanded page of the site.'),
            '#states' => array(
                // Only show this field when the value Anti-flood is enabled
                'invisible' => array(
                    ':input[name="cleantalk_sfw_antiflood"]' => array('checked' => false),
                ),
            ),
        );

        $form['cleantalk_bot_detector'] = array(
          '#type' => 'checkbox',
          '#title' => $this->t('Use CleanTalk JavaScript library'),
          '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_bot_detector'),
          '#description' => $this->t('This option includes CleanTalk external JavaScript library to getting visitors info data. You should flush the pages cache to make the changes work.'),
        );

        $form['cleantalk_link'] = [
            '#type' => 'checkbox',
            '#title' => $this->t('Tell others about CleanTalk'),
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_link'),
            '#description' => $this->t('Checking this box places a small link under the comment form that lets others know what anti-spam tool protects your site.'),
        ];

        $do_debug = 1;
        $config = \Drupal::service('config.factory')->getEditable('cleantalk.settings');

        if (!empty($_POST) && Post::get('form_id') === 'cleantalk_settings_form') {
            if (Post::get('cleantalk_debug_enabled') === '1') {
                CleantalkDebug::collectData();
            } else {
                $do_debug = 0;
                CleantalkDebug::clearDebugData();
            }
            $config->set('cleantalk_debug_enabled', $do_debug);
        } else {
            $do_debug = \Drupal::config('cleantalk.settings')->get('cleantalk_debug_enabled');
        }

        $form = $this->addDebugLayoutToForm($form, $do_debug);

        $form = $this->addServeCronLayoutToForm($form);

        /**
         * Salt
         */
        $form['cleantalk_salt'] = [
            '#type' => 'hidden',
            '#default_value' => \Drupal::config('cleantalk.settings')->get('cleantalk_salt') ?: str_pad((string)rand(0, getrandmax()), 6, '0') . str_pad((string)rand(0, getrandmax()), 6, '0'),
        ];

        return parent::buildForm($form, $form_state);

    }

    /**
     * Is this valid regexp
     *
     * @param  $regexp
     * @return bool
     */
    private static function apbct_is_regexp($regexp)
    {

        return @preg_match('#' . $regexp . '#', null) !== false;

    }

    public static function apiKeyTrim(array &$element, $input, FormStateInterface $form_state)
    {
        if ( $input === false ) {
            return $element['#default_value'] ?? [];
        }
        $valid_input = trim($input);
        $form_state->setValue('cleantalk_authkey', $valid_input);
        return $valid_input;
    }

    /**
     * Add debug settings and debug message layout to the form.
     * @param $form
     * @param $do_debug
     * @return mixed
     */
    private function addDebugLayoutToForm(&$form, $do_debug)
    {
        // Control if we need to collect debug
        $form['cleantalk_debug_enabled'] = [
            '#type' => 'checkbox',
            '#title' => $this->t('Collect debug data'),
            '#default_value' => $do_debug,
            '#description' => $this->t('Check this if you want to get the debug data. Data will be printed on this page after save.'),
        ];

        //=

        // Container. Show/hide all debug controls only if cleantalk_debug_enabled enabled.
        $form['debug_settings'] = array(
            '#type' => 'container',
            '#states' => array(
                'invisible' => array(
                    ':input[name="cleantalk_debug_enabled"]' => array('checked' => FALSE),
                ),
            ),
        );

        //= =

        // Fieldset visualisation
        $form['debug_settings']['debug_settings_container'] = array(
            '#type' => 'fieldset',
            '#states' => array(
                'invisible' => array(
                    ':input[name="cleantalk_debug_enabled"]' => array('checked' => FALSE),
                ),
            ),
        );

        //= = =

        // Control if we need to show debug
        $form['debug_settings']['debug_settings_container']['cleantalk_show_debug_checkbox'] = [
            '#type' => 'checkbox',
            '#title' => $this->t('Show debug info.'),
            '#default_value' => $do_debug,
            '#description' => $this->t('Show or hide the debug area.'),
        ];

        // Container. Show/hide debug area only if cleantalk_debug_enabled enabled.
        $form['debug_settings']['debug_settings_container']['debug_area_container'] = array(
            '#type' => 'container',
            '#states' => array(
                'invisible' => array(
                    ':input[name="cleantalk_show_debug_checkbox"]' => array('checked' => FALSE),
                ),
            ),
        );

        //Collect JSON debug data from settings.
        $debug_data_json = !empty(CleantalkDebug::getDebugJSON())
            ? CleantalkDebug::getDebugJSON()
            : '';

        //Markup data to make it readable.
        $markup = '<pre id="cleantalk_debug_pretty" style="font-size: small; color: gray"> ';
        $markup .= !empty($debug_data_json)
            ? htmlspecialchars($debug_data_json)
            : $this->t('No debug collected yet. Save configuration to run logging.');
        $markup .= '</pre>';
        $markup = new FormattableMarkup($markup, []);

        //Show debug area
        $form['debug_settings']['debug_settings_container']['debug_area_container']['cleantalk_debug_json_output'] = [
            '#type' => 'markup',
            '#prefix' => '<div id="cleantalk_debug_json_output" style="border: solid 1px lightgray">',
            '#markup' => $markup,
            '#suffix' => '</div>',
            '#weight' => 1,
        ];

        // show button
        if ( !empty($debug_data_json) ) {
            $form['debug_settings']['debug_settings_container']['debug_area_container']['cleantalk_debug_json_output']['cleantalk_debug_save_button'] = [
                '#type' => 'button',
                '#value' => 'Save to file',
                '#name' => 'cleantalk_debug_save_button'
            ];
        }

        return $form;
    }

    /**
     * Add serve cron buttons for local test to the form.
     * @param $form
     * @return mixed
     */
    private function addServeCronLayoutToForm(&$form)
    {
        if ( in_array(Server::getDomain(), array('loc')) ) {
            $form['serve_run_cron_sfw_update'] = [
                '#type' => 'button',
                '#value' => 'run cron task - sfw update in 120 sec',
                '#name' => 'cleantalk_serve_run_cron_sfw_update'
            ];
            $form['serve_run_cron_sfw_send_logs'] = [
                '#type' => 'button',
                '#value' => 'run cron task - send sfw logs in 120 sec',
                '#name' => 'cleantalk_serve_run_cron_sfw_send_logs'
            ];
        }

        return $form;
    }

    /**
     * @return bool
     */
    private function handleServeButtons()
    {
        if ( empty($_POST) ) {
            return false;
        }

        if ( Post::get('form_id') !== 'cleantalk_settings_form' ) {
            return false;
        }

        if ( Post::get('cleantalk_debug_save_button')) {
            CleantalkDebug::saveJSONToFile();
            return true;
        }

        if (Post::get('cleantalk_serve_run_cron_sfw_update')) {
            /** @var \Cleantalk\Common\Cron\Cron $cron_class */
            $cron_class = Mloader::get('Cron');
            $cron_class = new $cron_class;
            $cron_class->serveCronActions('sfw_update', time() + 120);
            return true;
        }

        if (Post::get('cleantalk_serve_run_cron_sfw_send_logs')) {
            /** @var \Cleantalk\Common\Cron\Cron $cron_class */
            $cron_class = Mloader::get('Cron');
            $cron_class = new $cron_class;
            $cron_class->serveCronActions('sfw_send_logs', time() + 120);
            return true;
        }

        return false;
    }
}
