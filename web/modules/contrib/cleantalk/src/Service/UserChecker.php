<?php

namespace Drupal\cleantalk\Service;

use Cleantalk\Common\Api\Api as CleantalkAPI;

class UserChecker
{
    /**
     * Auth key
     */
    private $authkey;

    /**
     * Users
     */
    private $users;

    /**
     * Offset
     */
    private $offset;

    /**
     * Limit
     */
    private $limit;

    /**
     * Constructor
     */
    public function __construct($offset = 0, $limit = 100)
    {
        $this->authkey = trim(\Drupal::config('cleantalk.settings')->get('cleantalk_authkey') ?: '');

        if (!$this->authkey) {
            return array(
                'error' => 'invalid_apy_key',
                'error_message' => 'Invalid apikey'
            );
        }

        $this->offset = $offset;
        $this->limit = $limit;

        $user_data = new UserData();
        $this->users = $user_data->getUsersFromFieldData($this->offset, $limit);

        if (!$this->users) {
            return array(
                'error' => 'no_users_found',
                'error_message' => 'No users found'
            );
        }

        return true;
    }

    public function checkUsers()
    {
        // collecting user emails
        $user_emails = array();
        foreach ($this->users as $user) {
            if ($user->mail) {
                $user_emails[] = $user->mail;
            }
        }

        // Send query to API
        $result = CleantalkAPI::methodSpamCheckCms($this->authkey, $user_emails);

        if (isset($result['error_message'])) {
            return array(
                'error' => 'error_api',
                'error_message' => $result['error_message']
            );
        }

        // collecting spammer emails
        $spammers_emails = array();
        foreach ($result as $key => $value) {
            if (isset($value['appears']) && $value['appears'] == '1') {
                $spammers_emails[] = $key;
            }
        }

        $spammers = array();
        if ($spammers_emails) {
            foreach ($this->users as $user) {
                if (in_array($user->mail, $spammers_emails)) {
                    $spammers[] = array(
                        $user->uid,
                        'cleantalk',
                        'spammer',
                        '1'
                    );
                }
            }
        }

        if ($spammers) {
            $user_data = new UserData();
            $user_data->insertSpammers($spammers);
        }

        $result = array(
            'success' => 'ok',
            'count_spammers' => count($spammers),
            'last_query' => 0
        );

        if (count($this->users) < $this->limit || count($this->users) === 0) {
            $result['last_query'] = 1;
        }

        return $result;
    }

    public function checkExcludeWithArticlesUsers()
    {
        $only_ids = array();
        $node_data = new NodeData();
        $users_with_articles = $node_data->getUserIdsWithArticles($this->users);

        if ($users_with_articles) {
            foreach ($users_with_articles as $user_id) {
                $only_ids[] = $user_id->uid;
            }

            foreach ($this->users as $key => $user) {
                if (in_array($user->uid, $only_ids)) {
                    unset($this->users[$key]);
                }
            }
        }

        return $this->checkUsers();
    }

}
