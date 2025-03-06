(function ($, Drupal) {

    /**
     * Check if exclude-user-with-articles cookie is set and set a new checkbox statement
     */
    let cookie = getCookie('apbct_exclude_uwa')
    if (undefined !== cookie && ['1', '0'].indexOf(cookie) > -1 ) {
        let new_checkbox_state = cookie === '1';
        $('#exclude-user-with-articles').prop('checked', new_checkbox_state);
    } else {
        var ctSecure = location.protocol === "https:" ? "; secure" : "";
        document.cookie = 'apbct_exclude_uwa=none; path=/; max-age=-1; expires=0; samesite=lax' + ctSecure;
    }

    /**
     * Set new cookie to remember exclude-user-with-articles statement
     */
    let secure = location.protocol === 'https' ? 'secure;' : ''
    $('#exclude-user-with-articles').change(
        function () {
            let checkbox_state = $('#exclude-user-with-articles').is(':checked');
            let state = checkbox_state ? '1' : '0';
            document.cookie = 'apbct_exclude_uwa' + "=" + state + ";" +
            " path=/;" +
            " max-age=" + 60 * 60 * 24 * 90 + ";SameSite=Strict;"
            + secure;
        }
    );

    /**
     * Clear spam users before checking
     */
    if (document.getElementById('apbct-start-check-users') != null) {
        document.getElementById('apbct-start-check-users').onclick = function () {
            $.ajax(
                {
                    url: '/admin/config/cleantalk/cleantalk_check_users_clear',
                    type: 'post',
                    error: function (jqXHR, textStatus, errorThrown) {
                        alert(textStatus);
                    },
                    success: function (response) {
                        if (response.success !== undefined && response.success === 'ok') {
                            let ctSecure = location.protocol === "https:" ? "; secure" : "";
                            document.cookie = 'apbct_start_users_interval' + "=" + 0 + "; path=/; expires=0; samesite=lax" + ctSecure;
                            $('#apbct-total-spammers').text(0);
                            $('#apbct-spammers-table').empty();
                            $('#apbct-spammers-pagination').empty();
                            $('.apbct-start-panel .lds-ripple').css('visibility', 'visible');
                            $('#apbct-start-check-users').prop('disabled', true);
                            startCheckingUsers();
                        }
                    }
                }
            );
        }
    }

    /**
     * Checking users
     */
    function startCheckingUsers()
    {
        $.ajax(
            {
                url: '/admin/config/cleantalk/cleantalk_check_users_check',
                type: 'post',
                data: {
                    'exclude_with_articles' : $('#exclude-user-with-articles').prop('checked')
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    alert(textStatus);
                },
                success: function (response) {
                    if (response.success !== undefined && response.success === 'ok') {
                        let countSpammers = Number($('#apbct-total-spammers').text()) + response.count_spammers;
                        $('#apbct-total-spammers').text(countSpammers);

                        if (response.last_query === 1) {
                              $('.apbct-start-panel .lds-ripple').css('visibility', 'hidden');
                              $('#apbct-start-check-users').prop('disabled', false);
                              document.location.reload();
                        } else {
                            let offset = Number(getCookie('apbct_start_users_interval')) + 100,
                              ctSecure = location.protocol === "https:" ? "; secure" : "";
                            document.cookie = 'apbct_start_users_interval' + "=" + offset + "; path=/; expires=0; samesite=lax" + ctSecure;
                            startCheckingUsers();
                        }
                    }

                    if (response.error !== undefined) {
                        $(".apbct__header").prepend(
                            '<div role="contentinfo" class="messages messages--error">\n' +
                            '<div role="alert">\n' +
                            '<h2 class="visually-hidden">Error type: ' + response.error + '</h2>\n' +
                            '<p>' + response.error_message + '</p>' +
                            '</div>\n' +
                            '</div>'
                        );
                    }
                }
            }
        );
    }

    /**
     * Select all users to delete
     */
    $('.apbct-selected-all-user-to-delete').change(
        function () {
            $('.apbct-selected-user-to-delete').prop('checked', $(this).is(':checked'));
        }
    );

    /**
     * Delete selected users
     */
    if (document.getElementById('apbct-delete-selected-users') != null) {
        document.getElementById('apbct-delete-selected-users').onclick = function () {
            var selectedUsers = $('.apbct-selected-user-to-delete:checked');

            if (selectedUsers.length === 0) {
                alert('Select the users to delete');
                return;
            }

            var selectedUsersID = [].map.call(
                selectedUsers, function (obj) {
                    return obj.value;
                }
            );

            if (! confirm('Are you sure?')) {
                return
            }

            $.ajax(
                {
                    url: '/admin/config/cleantalk/cleantalk_delete_selected_users',
                    type: 'post',
                    data: JSON.stringify(selectedUsersID),
                    error: function (jqXHR, textStatus, errorThrown) {
                        alert(textStatus);
                    },
                    success: function (response) {
                        if (response.success !== undefined && response.success === 'ok') {
                            document.location.reload();
                        }
                    }
                }
            );
        }
    }


    /**
     * Delete all spam users
     */
    if (document.getElementById('apbct-delete-all-users') != null) {
        document.getElementById('apbct-delete-all-users').onclick = function () {
            if (! confirm('Are you sure?')) {
                return
            }

            $.ajax(
                {
                    url: '/admin/config/cleantalk/cleantalk_delete_all_users',
                    type: 'post',
                    error: function (jqXHR, textStatus, errorThrown) {
                        alert(textStatus);
                    },
                    success: function (response) {
                        if (response.success !== undefined && response.success === 'ok') {
                            document.location.reload();
                        }
                    }
                }
            );
        }
    }

    /**
     * Get cookie by name
     *
     * @param   name
     * @returns {string|undefined}
     */
    function getCookie(name)
    {
        let matches = document.cookie.match(
            new RegExp(
                "(?:^|; )" + name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, '\\$1') + "=([^;]*)"
            )
        );
        return matches ? decodeURIComponent(matches[1]) : undefined;
    }

})(jQuery, Drupal);
