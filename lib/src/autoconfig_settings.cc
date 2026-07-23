/*  =========================================================================
    autoconfig_settings

    Copyright (C) 2014 - 2020 Eaton

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

#include "autoconfig_settings.h"
#include <fty_log.h>
#include <algorithm>
#include <vector>
#include <string>

void AutoconfigSettings::setVoltageStandard(const std::string& value_)
{
    static const std::vector<std::string> VALUES{ "EUROPE", "USA", "AUSTRALIA", "EUROPE_208" };

    std::string value{value_};
    std::transform(value.begin(), value.end(), value.begin(), ::toupper);

    const auto& it = std::find(VALUES.begin(), VALUES.end(), value);
    if (it != VALUES.end()) { // apply
        _voltageStandard = *it;
    }
    else {
        log_error("Failed to set Voltage standard (value: %s)", value.c_str());
    }
}
