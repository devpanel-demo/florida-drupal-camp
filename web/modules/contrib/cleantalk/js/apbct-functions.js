function ctSetCookie(cookies)
{

  let useCookies, useAltCookies

  if ('undefined' !== typeof ct_use_cookies) {
    useCookies = ct_use_cookies;
  } else {
    useCookies = false;
  }

  if ('undefined' !== typeof ct_use_alt_cookies) {
    useAltCookies = ct_use_alt_cookies;
  } else {
    useAltCookies = false
  }

  if (useCookies) {
    if (useAltCookies && useAltCookies === 1) {
      let xhr = new XMLHttpRequest();

      let json = JSON.stringify(cookies);

      xhr.open("POST", '/admin/config/cleantalk/set_alt_cookies')
      xhr.setRequestHeader('Content-type', 'application/json; charset=utf-8');

      xhr.send(json);
    } else {
      cookies.forEach(
        function (e) {
          let ctSecure = location.protocol === "https:" ? "; secure" : "";
          document.cookie = e.name + "=" + encodeURIComponent(e.value) + "; path=/; expires=0; samesite=lax" + ctSecure;
        }
      )
    }
  }
}
