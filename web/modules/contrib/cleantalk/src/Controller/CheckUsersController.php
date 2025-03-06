<?php

namespace Drupal\cleantalk\Controller;

use Drupal\cleantalk\Service\UserChecker;
use Drupal\cleantalk\Service\UserData;
use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Entity\EntityStorageException;
use Drupal\Core\Url;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

class CheckUsersController extends ControllerBase
{
    const COUNT_USERS_IN_TEST = 100;
    
    /**
     * Return data for view
     * 
     * @return array
     */
    public function view(Request $request)
    {
        $user_data = new UserData();
        $total_users = $user_data->totalUsers();
        $total_spammers = $user_data->totalSpammers();

        $num_per_page = 20;
        $current_page = \Drupal::request()->get('page');
        $spammersOnPage = $user_data->getSpammers($current_page, $num_per_page);
        
        // pagination
        $count_pages = 0;
        if ($total_spammers > $num_per_page) {
            $count_pages = ceil($total_spammers / $num_per_page);
        }
        
        return [
            '#theme' => 'cleantalk_check_users',
            '#attached' => array(
                'library' => array(
                    'cleantalk/apbct-admin-styles',
                    'cleantalk/apbct-admin-scripts',
                ),
            ),
            '#template_data' => [
                'total_users' => $total_users,
                'total_spammers' => $total_spammers,
                'spammers' => $spammersOnPage,
                'count_pages' => $count_pages
            ]
        ];
    }

    /**
     * Clear users for new checking
     *
     * @return JsonResponse
     */
    public function clear()
    {
        $user_data = new UserData();
        $user_data->deleteAll();

        return new JsonResponse(['success'=>'ok']);
    }

    /**
     * Check users for spam
     *
     * @param Request $request
     * 
     * @return JsonResponse
     */
    public function check(Request $request)
    {
        $offset = $request->cookies->get('apbct_start_users_interval') ?: 0;
        $limit = self::COUNT_USERS_IN_TEST;
        $exclude_with_articles = $request->get('exclude_with_articles');
        
        $user_checker = new UserChecker($offset, $limit);

        if ($exclude_with_articles === 'true') {
            $result = $user_checker->checkExcludeWithArticlesUsers();
        } else {
            $result = $user_checker->checkUsers();
        }

        return new JsonResponse($result);
    }

    /**
     * Delete user
     *
     * @param  Request $request
     * @return RedirectResponse
     * @throws EntityStorageException
     */
    public function delete(Request $request)
    {
        $user_id = $request->get('user_id');
        $user = \Drupal\user\Entity\User::load($user_id);
        $user->delete();
        
        $redirect_url = Url::fromRoute('cleantalk.check_users')->toString();

        return new RedirectResponse($redirect_url);
    }

    /**
     * Delete selected users
     *
     * @throws EntityStorageException
     */
    public function deleteSelected(Request $request)
    {
        $users_id = \Drupal\Component\Serialization\Json::decode($request->getContent());
        
        foreach ($users_id as $user_id) {
            $user = \Drupal\user\Entity\User::load($user_id);
            $user->delete();
        }

        return new JsonResponse(['success'=>'ok']);
    }

    /**
     * Delete all spammers users
     *
     * @throws EntityStorageException
     */
    public function deleteAll()
    {
        $user_data = new UserData();
        $spammers = $user_data->getAllSpammers();

        foreach ($spammers as $user) {
            $user = \Drupal\user\Entity\User::load($user->uid);
            $user->delete();
        }

        return new JsonResponse(['success'=>'ok']);
    }
}