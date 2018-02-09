/*  =========================================================================
    fty_alert_actions - Actor performing actions on alert (sending notifications)

    Copyright (C) 2014 - 2017 Eaton                                        
                                                                           
    This program is free software; you can redistribute it and/or modify   
    it under the terms of the GNU General Public License as published by   
    the Free Software Foundation; either version 2 of the License, or      
    (at your option) any later version.                                    
                                                                           
    This program is distributed in the hope that it will be useful,        
    but WITHOUT ANY WARRANTY; without even the implied warranty of         
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          
    GNU General Public License for more details.                           
                                                                           
    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.            
    =========================================================================
*/

#ifndef FTY_ALERT_ACTIONS_H_INCLUDED
#define FTY_ALERT_ACTIONS_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

//  @interface
//  Create a new fty_alert_actions
FTY_ALERT_ENGINE_EXPORT fty_alert_actions_t *
    fty_alert_actions_new (void);

//  Destroy the fty_alert_actions
FTY_ALERT_ENGINE_EXPORT void
    fty_alert_actions_destroy (fty_alert_actions_t **self_p);

//  Main actor function for actions module
FTY_ALERT_ENGINE_EXPORT void
fty_alert_actions (zsock_t *pipe, void* args);

//  Self test of this class
FTY_ALERT_ENGINE_EXPORT void
    fty_alert_actions_test (bool verbose);

//  @end

#ifdef __cplusplus
}
#endif

#endif
