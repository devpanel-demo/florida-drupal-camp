<?php

namespace Drupal\cleantalk\Controller;

use Drupal\cleantalk\CleantalkFuncs;
use Symfony\Component\HttpFoundation\Request;

class SetAltCookiesController
{

    public function setCookies(Request $request)
    {
        $content = $request->getContent();
        $content = json_decode($content, true);

        if(!empty($content) && is_array($content)) {
            foreach ($content as $cookie) {
                CleantalkFuncs::apbct_setcookie($cookie['name'], $cookie['value']);
            }
        }

        die;
    }
}
