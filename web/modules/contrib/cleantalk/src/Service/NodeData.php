<?php

namespace Drupal\cleantalk\Service;

class NodeData
{
  
    public function getUserIdsWithArticles($users)
    {
        // collecting user emails
        $user_ids = array();
        foreach ($users as $user) {
            if ($user->uid) {
                $user_ids[] = $user->uid;
            }
        }

        return \Drupal::database()
            ->select('node_field_data', 'n')
            ->fields('n', ['uid'])
            ->condition('n.type', 'article')
            ->condition('n.status', '1')
            ->condition('n.uid', $user_ids, 'IN')
            ->execute()
            ->fetchAll();
    }
}