/* 
 * (c) 2017 TRIAL.
 * Created on 16/06/2017, 23:07:37.
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

window.T = ( ( T ) => {
  
    T.History = {

        add( state, title, url ) {
            if ( history.pushState ) {
                history.pushState( state, title, url );
                document.title = title;
            } else {
                location.assign( url );
            }
        },

        replace( state, title, url ) {
            try {
                history.replaceState( state, title || null, url || null );
            } catch (e) {}
        }

    };

    return T;
  
} )( window.T || {} );
    
window.dispatchEvent( new CustomEvent( 'T.History.loaded' ) );
