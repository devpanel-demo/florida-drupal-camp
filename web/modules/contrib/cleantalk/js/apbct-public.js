var d = new Date(),
    ctTimeMs = new Date().getTime(),
    ctMouseEventTimerFlag = true, //Reading interval flag
    ctMouseData = "[",
    ctMouseDataCounter = 0,
    ctScrollCollected = false,
    ctEventTokenInterval = null;

ctSetCookie(
    [
    {
        'name' : 'ct_check_js',
        'value' : ct_check_js_val
    },
    {
        'name' : 'ct_ps_timestamp',
        'value' : Math.floor(new Date().getTime()/1000)
    },
    {
        'name' : 'ct_fkp_timestamp',
        'value' : '0'
    },
    {
        'name' : 'ct_pointer_data',
        'value' : '0'
    },
    {
        'name' : 'ct_timezone',
        'value' : d.getTimezoneOffset()/60*(-1)
    },
    {
        'name' : 'apbct_antibot',
        'value' : drupal_ac_antibot_cookie_value
    },
    {
        'name' : 'ct_has_scrolled',
        'value' : false
    }
    ]
);

//Reading interval

var ctMouseReadInterval = setInterval(
    function () {
        ctMouseEventTimerFlag = true;
    }, 150
);

//Writting interval

var ctMouseWriteDataInterval = setInterval(
    function () {
        if(typeof ct_use_alt_cookies !== "undefined" && ct_use_alt_cookies === 1) {
            return;
        }
        var ctMouseDataToSend = ctMouseData.slice(0,-1).concat("]");
        ctSetCookie(
            [
            {
                'name' : 'ct_pointer_data',
                'value' : ctMouseDataToSend
            }
            ]
        );
    }, 1200
);

//Stop observing function

function ctMouseStopData()
{
    if(typeof window.addEventListener == "function") {
        window.removeEventListener("mousemove", ctFunctionMouseMove);
    } else {
        window.detachEvent("onmousemove", ctFunctionMouseMove);
    }
    clearInterval(ctMouseReadInterval);
    clearInterval(ctMouseWriteDataInterval);
}

//Logging mouse position each 300 ms

var ctFunctionMouseMove = function output(event)
{
    if (ctMouseEventTimerFlag == true) {
        var mouseDate = new Date();
        ctMouseData += "[" + Math.round(event.pageY) + "," + Math.round(event.pageX) + "," + Math.round(mouseDate.getTime() - ctTimeMs) + "],";
        ctMouseDataCounter++;
        ctMouseEventTimerFlag = false;
        if(ctMouseDataCounter >= 100) {
            ctMouseStopData();
        }
    }
};

/**
 * Set scrolling cookie
 */
function ctSetHasScrolled()
{
    if(! ctScrollCollected ) {
        ctSetCookie(
            [
            {
                'name' : 'ct_has_scrolled',
                'value' : true
            }
            ]
        );
        ctScrollCollected = true;
    }
}

//Stop key listening function

function ctKeyStopStopListening()
{
    if (typeof window.addEventListener == "function") {
        window.removeEventListener("mousedown", ctFunctionFirstKey);
        window.removeEventListener("keydown", ctFunctionFirstKey);
    }
    else {
        window.detachEvent("mousedown", ctFunctionFirstKey);
        window.detachEvent("keydown", ctFunctionFirstKey);
    }
}

//Writing first key press timestamp

var ctFunctionFirstKey = function output(event)
{
    var KeyTimestamp = Math.floor(new Date().getTime()/1000);
    ctSetCookie(
        [
        {
            'name' : 'ct_fkp_timestamp',
            'value' : KeyTimestamp
        }
        ]
    );
    ctKeyStopStopListening();
};

if (typeof window.addEventListener == "function") {
    window.addEventListener("mousemove", ctFunctionMouseMove);
    window.addEventListener("mousedown", ctFunctionFirstKey);
    window.addEventListener("keydown", ctFunctionFirstKey);
    window.addEventListener("scroll", ctSetHasScrolled);
}
else {
    window.attachEvent("onmousemove", ctFunctionMouseMove);
    window.attachEvent("mousedown", ctFunctionFirstKey);
    window.attachEvent("keydown", ctFunctionFirstKey);
    window.attachEvent("scroll", ctSetHasScrolled);
}

function apbct_collect_visible_fields( form )
{

    // Get only fields
    var inputs = [],
        inputs_visible = '',
        inputs_visible_count = 0,
        inputs_invisible = '',
        inputs_invisible_count = 0,
        inputs_with_duplicate_names = [];

    for(var key in form.elements){
        if(!isNaN(+key)) {
            inputs[key] = form.elements[key];
        }
    }

    // Filter fields
    inputs = inputs.filter(
        function (elem) {

            // Filter already added fields
            if(inputs_with_duplicate_names.indexOf(elem.getAttribute('name')) !== -1 ) {
                return false;
            }
            // Filter inputs with same names for type == radio
            if(-1 !== ['radio', 'checkbox'].indexOf(elem.getAttribute("type"))) {
                inputs_with_duplicate_names.push(elem.getAttribute('name'));
                return false;
            }
            return true;
        }
    );

    // Visible fields
    inputs.forEach(
        function (elem, i, elements) {
            // Unnecessary fields
            if(elem.getAttribute("type")         === "submit"  // type == submit
                || elem.getAttribute('name')         === null
                || elem.getAttribute('name')         === 'ct_checkjs'
            ) {
                return;
            }
            // Invisible fields
            if(getComputedStyle(elem).display    === "none"    // hidden
                || getComputedStyle(elem).visibility === "hidden"  // hidden
                || getComputedStyle(elem).opacity    === "0"       // hidden
                || elem.getAttribute("type")         === "hidden" // type == hidden
            ) {
                if(elem.classList.contains("wp-editor-area") ) {
                    inputs_visible += " " + elem.getAttribute("name");
                    inputs_visible_count++;
                } else {
                    inputs_invisible += " " + elem.getAttribute("name");
                    inputs_invisible_count++;
                }
            }
            // Visible fields
            else {
                inputs_visible += " " + elem.getAttribute("name");
                inputs_visible_count++;
            }

        }
    );

    inputs_invisible = inputs_invisible.trim();
    inputs_visible = inputs_visible.trim();

    return {
        visible_fields : inputs_visible,
        visible_fields_count : inputs_visible_count,
        invisible_fields : inputs_invisible,
        invisible_fields_count : inputs_invisible_count,
    }

}

function apbct_visible_fields_set_cookie( visible_fields_collection )
{
    var collection = typeof visible_fields_collection === 'object' && visible_fields_collection !== null ?  visible_fields_collection : {};

    ctSetCookie(
        [
        {
            'name' : 'apbct_visible_fields',
            'value' : JSON.stringify(collection)
        }
        ]
    )
}

// Event token handler class. Get token and save it to the alternative sessions.

class EventTokenHandler {

  constructor(use_alt_cookies_option) {
    this.token = null;
    this.lsSavedFlagName = 'event_token_saved_to_alt_sessions';
    this.lsEVentTokenName = 'bot_detector_event_token';
    this.intervalValue = 1500;
    this.init(use_alt_cookies_option);
  }

  init(use_alt_cookies_option){
    if ('undefined' !== typeof use_alt_cookies_option && use_alt_cookies_option) {
      this.setNotSavedFlag();
      this.startListenTokenLS();
    }
  }


  setSavedFlag()
  {
    localStorage.setItem(this.lsSavedFlagName, '1');
  }

  setNotSavedFlag()
  {
    localStorage.setItem(this.lsSavedFlagName, '0');
  }

  isSaved()
  {
    let event_token_saved = localStorage.getItem(this.lsSavedFlagName);
    return event_token_saved !== null && event_token_saved !== undefined && event_token_saved === '1';
  }

  getEventToken()
  {
    let event_token = localStorage.getItem(this.lsEVentTokenName);
    try {
      event_token = event_token !== null ? JSON.parse(event_token) : false;
    } catch (e) {
      return false;
    }
    event_token = event_token.hasOwnProperty('value') ? event_token.value : false;
    if (typeof event_token === 'string' && event_token.length === 64) {
      return event_token;
    }
    return false;
  }

  setEventTokenCookie()
  {
    if (typeof this.token === 'string' && this.token.length === 64) {
      ctSetCookie(
        [
          {
            'name': 'apbct_event_token',
            'value': this.token
          }
        ]
      )
    }
  }

  stopListenTokenLS()
  {
    clearInterval(this.intervalID);
  }

  startListenTokenLS()
  {
    this.intervalID = setInterval( this.intervalRun, this.intervalValue, this)
  }

  intervalRun(handler)
  {
    if ( !handler.isSaved() ) {
      handler.token = handler.getEventToken();
      if ( handler.token  ) {
        handler.setEventTokenCookie();
        handler.setSavedFlag();
        handler.stopListenTokenLS();
      }
    }
  }
}

//Collect event token
new EventTokenHandler(ct_use_alt_cookies);
