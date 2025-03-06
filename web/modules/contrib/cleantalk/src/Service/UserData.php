<?php
/**
 * Class for work with user.data storage
 */
namespace Drupal\cleantalk\Service;

class UserData
{
    public function deleteAll()
    {
        $user_data = \Drupal::service('user.data');
        $user_data->delete('cleantalk', null, 'spammer');
    }
    
    /**
     * Select users from users_field_data with limit and offset
     */
    public function getUsersFromFieldData($offset = 0, $limit = 100)
    {
        $users = \Drupal::database()
            ->select('users_field_data', 'n')
            ->fields('n', ['uid', 'mail'])
            ->orderBy('uid')
            ->range($offset, $limit)
            ->execute()
            ->fetchAll();

        if (!$users) {
            return array();
        }
        
        return $users;
    }

    /**
     * Insert spammers to users_data
     * 
     * @param array $spammers
     */
    public function insertSpammers($spammers)
    {
        $query = \Drupal::database()->insert('users_data');
        $query->fields(
            array(
                'uid',
                'module',
                'name',
                'value'
            )
        );
        foreach ($spammers as $spammer) {
            $query->values($spammer);
        }
        $query->execute();
    }
    
    /**
     * Total users
     */
    public function totalUsers()
    {
        return \Drupal::database()
            ->select('users_field_data', 'n')
            ->countQuery()
            ->execute()
            ->fetchField();
    }

    /**
     * Total spammers
     */
    public function totalSpammers()
    {
        return \Drupal::database()
            ->select('users_data', 'n')
            ->condition('n.module', 'cleantalk')
            ->condition('n.name', 'spammer')
            ->condition('n.value', 1)
            ->countQuery()
            ->execute()
            ->fetchField();
    }

    /**
     * Get spammers
     */
    public function getSpammers($current_page = 0, $num_per_page = 20)
    {
        $offset = 0;
        
        if ($current_page > 1) {
            $offset = ($current_page - 1) * $num_per_page;
        }

        $query = \Drupal::database()
            ->select('users_field_data', 'n');
        $query->innerJoin('users_data', 'u', 'n.uid = u.uid');
        return $query->fields('n')
            ->condition('u.module', 'cleantalk')
            ->condition('u.name', 'spammer')
            ->condition('u.value', 1)
            ->orderBy('n.uid')
            ->range($offset, $num_per_page)
            ->execute()
            ->fetchAll();
    }

    /**
     * @return mixed
     */
    public function getAllSpammers()
    {
        $query = \Drupal::database()
            ->select('users_field_data', 'n');
        $query->innerJoin('users_data', 'u', 'n.uid = u.uid');
        
        return $query->fields('n')
            ->condition('u.module', 'cleantalk')
            ->condition('u.name', 'spammer')
            ->condition('u.value', 1)
            ->execute()
            ->fetchAll();
    }
}