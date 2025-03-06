<?php

namespace Drupal\cleantalk\Controller;

use Cleantalk\Custom\Helper\Helper as CleantalkHelper;
use Drupal\cleantalk\CleantalkFuncs;
use Laminas\Diactoros\Response\JsonResponse;

class ExternalFormsController
{

    public function check()
    {
        $result = array();
    
        if(!empty($_POST)) {
            $ct_temp_msg_data = CleantalkHelper::get_fields_any($_POST);
            $spam_check = array();
            $spam_check['type'] = 'custom_contact_form';
            $spam_check['sender_email'] = $ct_temp_msg_data['email']    ?: '';
            $spam_check['sender_nickname'] = $ct_temp_msg_data['nickname'] ?: '';
            $spam_check['message_title'] = $ct_temp_msg_data['subject']  ?: '';
            $spam_check['message_body'] = $ct_temp_msg_data['message']  ? implode("\n", $ct_temp_msg_data['message'])  : '';

            if ($spam_check['sender_email'] != '' || $spam_check['message_title'] != '' || $spam_check['message_body'] != '') {
                $result = CleantalkFuncs::_cleantalk_check_spam($spam_check);
            }
        }    

        return new JsonResponse($result);
    }
}
