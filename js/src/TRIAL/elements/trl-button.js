/* 
 * (c) 2017 TRIAL.
 * Created on 18/06/2017, 21:00:42.
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
/*
 * moved all from T.php to trl-button.js on 18/06/2017, 21:00:52
 * 
 * 05/12/2016, 21:30:18 => added document.registerElement() code
 * 
 * 14/12/2016, 18:03:40 => added this.already_setup, createdCallback(), attachedCallback()
 * 
 * 12/01/2018, 01:38:21 => updated document.registerElement() code to newer window.T.elements.custom() code
 */
(function (window) {
    window.T.elements.custom(window.T.elements.TRL_BUTTON, {
        prototype: Object.create(HTMLAnchorElement.prototype, {
            createdCallback: {
                value: function () {
                    if (this.innerHTML) {
                        this.setup();
                    }
                }
            },
            attachedCallback: {
                value: function () {
                    this.setup();
                }
            },
            setup: {
                value: function () {
                    var div = document.createElement("div");
                    this.original_innerHTML = this.innerHTML;
                    div.innerHTML = this.original_innerHTML;
                    this.innerHTML = null;
                    this.appendChild(div);
                }
            }
        }),
        extends: "a"
    }, window.T.elements.TRIAL.Button);
})(window);