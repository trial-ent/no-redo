/* 
 * (c) 2017 TRIAL.
 * Created on 18/06/2017, 20:59:23.
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

(function (T) {
  
  function missing(x) {
    if (!T.Utils && !T.style)
      T.load("utils", x);
    else
      x();
  }

  T.elements.custom(T.elements.TRL_LOADING, {
    prototype: Object.create(HTMLDivElement.prototype, {
      createdCallback: {
        value: function () {
          this.updateStyle();
        }
      },
      attributeChangedCallback: {
        value: function () {
          this.updateStyle();
        }
      },
      attachedCallback: {
        value: function () {
          this.updateStyle();
        }
      },
      color: {
        set: function (color) {
          this.setAttribute("trl-color", color || "#24c742");
        },
        get: function () {
          return this.getAttribute("trl-color") || "#24c742";
        }
      },
      size: {
        set: function (size) {
          this.setAttribute("trl-size", size || "100%");
        },
        get: function () {
          return this.getAttribute("trl-size") || "100%";
        }
      },
      duration: {
        set: function (duration) {
          this.setAttribute("trl-duration", duration || "8s");
        },
        get: function () {
          return this.getAttribute("trl-duration") || "8s";
        }
      },
      updateStyle: {
        value: function () {
          var that = this, color = this.color, size = this.size, duration = this.duration, 
          css_changes = {
            Styles: {
              "[loading] | [loading] [triangle][up][left] | [loading] [triangle][up][right][mid-top] | [loading] [triangle][up][right][mid-bottom] | [loading] [triangle][down][left] | [loading] [triangle][down][right]": {
                  animationDuration: duration
              },
              "[loading]": {
                  width: size,
                  height: size
              },
              "[triangle-color]": {
                  fill: color
              }
            }
          };
          missing(function () {
            if (!that.stylesheet)
              for (var i in document.styleSheets)
                if (document.styleSheets[i].href && document.styleSheets[i].href.indexOf("trl-loading.css") !== -1) {
                  that.stylesheet = document.styleSheets[i];
                  break;
                }
            T(that.stylesheet).style(css_changes);
          });
        }
      },
      isLoading: {
        value: function () {
          return this.children.length > 0;
        }  
      },
      start: {
        value: function () {
          var loading = document.createElement("section"),
              up_left = document.createElement("div"),
              down_left = document.createElement("div"),
              down_right = document.createElement("div"),
              container_right = document.createElement("div"),
              up_right_mid_bottom = document.createElement("div"),
              up_right_mid_top = document.createElement("div"),
              shape_number = 0;

          loading.setAttribute("loading", "");

          up_left.setAttribute("triangle", "");
          up_left.setAttribute("up", "");
          up_left.setAttribute("left", "");
          up_left.innerHTML = svg("M50 0 L50 50 L0 50 L0 50 Z");

          down_left.setAttribute("triangle", "");
          down_left.setAttribute("down", "");
          down_left.setAttribute("left", "");
          down_left.innerHTML = svg("M0 0 L50 0 L50 0 L50 50 Z");

          down_right.setAttribute("triangle", "");
          down_right.setAttribute("down", "");
          down_right.setAttribute("right", "");
          down_right.innerHTML = svg("M0 0 L0 50 L50 0 L50 0 Z");

          container_right.setAttribute("container-triangles", "");

          up_right_mid_top.setAttribute("triangle", "");
          up_right_mid_top.setAttribute("up", "");
          up_right_mid_top.setAttribute("right", "");
          up_right_mid_top.setAttribute("mid-top", "");
          up_right_mid_top.innerHTML = svg("M50 50 L0 50 L50 0 L50 0 Z");

          up_right_mid_bottom.setAttribute("triangle", "");
          up_right_mid_bottom.setAttribute("up", "");
          up_right_mid_bottom.setAttribute("right", "");
          up_right_mid_bottom.setAttribute("mid-bottom", "");
          up_right_mid_bottom.innerHTML = svg("M0 0 L50 0 L50 0 L0 50 Z");

          container_right.appendChild(up_right_mid_top);
          container_right.appendChild(up_right_mid_bottom);

          loading.appendChild(up_left);
          loading.appendChild(container_right);
          loading.appendChild(down_left);
          loading.appendChild(down_right);

          this.appendChild(loading);

          function svg(path) {
            var id = "f" + (shape_number++);
            return '<svg viewBox="0 0 50 50" style="width: 100%; height: 100%">' +
                '<defs>' +
                  '<filter id="' + id + '" x="0" y="0" width="100%" height="100%">' +
                    '<feOffset result="offOut" in="SourceAlpha" dx="0" dy="0" />' +
                    '<feGaussianBlur result="blurOut" in="offOut" stdDeviation="1" />' +
                    '<feBlend in="SourceGraphic" in2="blurOut" mode="normal" />' +
                  '</filter>' +
                '</defs>' +
                '<path triangle-color d="' + path + '" filter="url(#' + id + ')" />' +
                'Sorry, your browser does not support inline SVG.' +
            '</svg>';
          }

          return loading;
        }
      },
      stop: {
        value: function () {
          while (this.firstChild)
              this.removeChild(this.firstChild);
        }
      }
    })
  }, 'TRIAL.Loading');

  window.dispatchEvent(new CustomEvent("T.elements.TRIAL.Loading.loaded"));
    
})(window.T);