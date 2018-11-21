/* 
 * (c) 2017 TRIAL.
 * Created on 16/06/2017, 22:56:53.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

window.T = (function (T) {
  
  T.Navigation = {};

  T.Navigation.scroll = function (options) {
      var y = { initial: window.pageYOffset, distance: 0 },
          x = { initial: window.pageXOffset, distance: 0 };
      if (!options.hasOwnProperty('x')) {
        options.x = x.initial;
      }
      if (options.x !== x.initial) {
        if (options.x < x.initial) {
          x.distance = -(x.initial - options.x);
        } else {
          x.distance = options.x - x.initial;
        }
      }
      if (!options.hasOwnProperty('y')) {
        options.y = y.initial;
      }
      if (options.y !== y.initial) {
        if (options.y < y.initial) {
          y.distance = -(y.initial - options.y);
        } else {
          y.distance = options.y - y.initial;
        }
      }
      if (y.distance !== 0 || x.distance !== 0) {
        T.load('design', function () {
          T.Animation.start({
            duration: options.duration || 300,
            delta: function (p) {
              return T.Animation.Easing.easeInOutQuart(p);
            },
            step: function (delta) {
              window.scrollTo(x.initial + (x.distance * delta), y.initial + (y.distance * delta));
            }
          });
        });
      }
  };
  
  T.Navigation.next = function (options) {
    try {
      options.next.style.position = 'absolute';
      options.next.style.display = '';
      options.next.style.top = options.top + 'px';
      options.next.style.left = '100%';
      if (options.onstart)
        options.onstart(options);
      T.load('design', function () {
        T.Animation.start({
          duration: 200,
          delta: function (p) {
            return T.Animation.Easing.easeInOutQuart(p);
          },
          step: function (delta) {
            try {
              var perc = 100 * delta;
              options.current.style.left = '-' + perc + '%';
              options.next.style.left = (100 - perc) + '%';
            } catch (e) {
              console.error(e);
            }
          }
        });
        setTimeout(function () {
          options.next.style.position = '';
          options.next.style.top = 0;
          if (options.onfinish) {
            options.onfinish(options);
          }
        }, 201);
      });
    } catch (e) {
      console.error(e);
    }
  };
  
  T.Navigation.previous = function (options) {
    try {
      options.previous.style.position = 'absolute';
      options.previous.style.display = '';
      options.previous.style.top = options.top + 'px';
      options.previous.style.left = '-100%';
      if (options.onstart)
        options.onstart(options);
      T.load('design', function () {
        T.Animation.start({
          duration: 200,
          delta: function (p) {
            return T.Animation.Easing.easeInOutQuart(p);
          },
          step: function (delta) {
            try {
              var perc = 100 * delta;
              options.previous.style.left = '-' + (100 - perc) + '%';
              options.current.style.left = perc + '%';
            } catch (e) {
              console.error(e);
            }
          }
        });
        setTimeout(function () {
          options.previous.style.position = '';
          options.previous.style.top = 0;
          if (options.onfinish) {
            options.onfinish(options);
          }
        }, 201);
      });
    } catch (e) {
      console.error(e);
    }
  };

  T.Navigation.noRefresh = function (options) {
    
    var api = {};

    options.into = options.into || 'ajax-content';
    options.jsClass = options.jsClass || 'ajax-script';
    options.cssClass = options.cssClass || 'ajax-style';

    api.load = (function (api) {

      function loadStyles(html) {
        var styles = {
          current : [],
          loaded  : html.getElementsByClassName(options.cssClass)
        };
        for (var i = 0, t = document.styleSheets.length; i < t; i++)
          styles.current.push(document.styleSheets[i].href);
        var d = document.getElementsByClassName(options.cssClass);
        for (i = 0, t = d.length; i < t; i++)
          try {
            document.head.removeChild(d[i]);
          } catch (e) {}
        for (i = 0, t = styles.loaded.length; i < t; i++) {
          if (styles.current.indexOf(styles.loaded[i].href) === -1) {
            if (styles.loaded[i] instanceof HTMLStyleElement) {
              var style = document.createElement('style');
              style.innerHTML = styles.loaded[i].innerHTML;
            } else {
              var style = document.createElement('link');
              style.rel = 'stylesheet';
              style.type = 'text/css';
              style.href = styles.loaded[i].href;
            }
            style.classList.add(options.cssClass);
            document.head.appendChild(style);
          }
        }
      }

      function loadScripts(html) {
          var scripts = {
            current : [],
            loaded  : html.getElementsByClassName(options.jsClass)
          };
          for (var i = 0, t = document.scripts.length; i < t; i++) {
              if (!document.scripts[i])
                  continue;
              if (document.scripts[i].classList.contains(options.jsClass)) {
                  try {
                    document.body.removeChild(document.scripts[i]);
                  } catch (e) {}
                  continue;
              }
              if (document.scripts[i].src !== undefined && document.scripts[i].src !== null && document.scripts[i].src !== '')
                  scripts.current.push(document.scripts[i].src);
          }
        for (var i = 0, t = scripts.loaded.length; i < t; i++) {
          if (scripts.current.indexOf(scripts.loaded[i].src) === -1) {
            var s = document.createElement('script');
            if (scripts.loaded[i].src) {
              s.src = scripts.loaded[i].src;
            }
            s.innerHTML = scripts.loaded[i].innerHTML;
            s.classList.add(options.jsClass);
            document.body.appendChild(s);
          }
        }
      }

      function loadPage(html, update, url) {
        try {
          var str_html =   html instanceof HTMLDocument 
                         ? html.documentElement.outerHTML 
                         : html,
              content = {
                current : document.getElementById(options.into),
                loaded  : html.getElementById(options.into)
              };
          content.current.className = content.loaded.className;
          document.documentElement.className = html.documentElement.className;
          loadStyles(html);
          content.current.innerHTML = content.loaded.innerHTML;
          document.title = html.title;
          loadScripts(html);
          if (update) {
            var data = {
              title : document.title,
              url   : location.href,
              page  : str_html
            };
            if (options.onsave)
              options.onsave(data);
            T.History.add(data, html.title, url);
            api.currentState = data;
          }
          if (options.onloaded) {
            var custom = options;
            custom.page = html;
            options.onloaded(custom);
          }
        } catch (e) {
          console.error(e);
          if (options.onerror)
            options.onerror(e);
          if (options.onloaded) {
            var custom = options;
            custom.error = e;
            options.onloaded(custom);
          }
        }
      }

      return function (q) {
        if (typeof q.url === 'undefined') {
          if (q.e.state && q.e.state.page) {
            loadPage(new DOMParser().parseFromString(q.e.state.page, 'text/html'));
          }
        } else {
          T.load('utils', function () {
            T.Utils.ajax({
              event: q.e,
              url: q.url,
              method: 'GET',
              response: 'document',
              onloadend: function (e) {
                loadPage(e.target.response, true, q.url);
              }
            });
          });
        }
      };

    })(api);

    var prestate = {
      title : document.title,
      url   : location.href,
      page  : document.documentElement.outerHTML
    };

    if (options.onsave) {

      options.onsave(prestate, true);

    }

    T.load('history', function () {

        T.History.replace(prestate);

        window.addEventListener('popstate', function (e) {

            if (typeof options.onnavigate === 'undefined' ||
               (typeof options.onnavigate === 'function' && options.onnavigate.call(api, e))) {

              api.load({e: e});

            }

            api.currentState = e.state;

        });

    });

    return api;
    
  };
    
  return T;
  
})(window.T || {});
    
window.dispatchEvent(new CustomEvent('T.Navigation.loaded'));