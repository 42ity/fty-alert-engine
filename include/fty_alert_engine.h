/*  =========================================================================
    fty-alert-engine - 42ity service evaluating rules written in Lua and producing alerts

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

#ifndef FTY_ALERT_ENGINE_H_H_INCLUDED
#define FTY_ALERT_ENGINE_H_H_INCLUDED

//  Include the project library file
#include "fty_alert_engine_library.h"

//  Add your own public definitions here, if you need them

// path to the directory, where rules are stored. Attention: without last slash!
#define PATH "/var/lib/bios/alert_agent"

// path to the directory where templates are stored. Attention: without last slash!
// (changed from /usr/share/bios/fty-autoconfig/)
#define TEMPLATES "/usr/share/fty/fty-alert-engine"

#endif
