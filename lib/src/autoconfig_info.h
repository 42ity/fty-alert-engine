/*  =========================================================================
    autoconfig_info

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

#pragma once

#include <fty_proto.h>
#include <map>
#include <vector>
#include <string>

struct AutoConfigurationInfo
{
    std::string type;
    std::string subtype;
    std::string update_ts;
    uint64_t date{0}; // *must* be 0
    bool configured{false}; // *must* be false

    std::map<std::string, std::string> attributes; // ext. attributes <key, value>
    std::vector<std::string> locations; // inames (dc, room, ...)

    // not initialized?
    bool empty() const;

    // ext. attribute accessor
    std::string getAttr(const std::string& attrName, const std::string& defValue = "") const;

    // dbg, dump with/without filter on ext. attributes
    std::string dump(const std::vector<std::string>& attrFilter) const;
    std::string dump() const { return dump({}); }

    // compare w/ fty_proto object
    bool operator == (fty_proto_t* proto) const;
};
