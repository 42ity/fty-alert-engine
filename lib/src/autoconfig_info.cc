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

#include "autoconfig_info.h"
#include "misc/utils.h"
#include <sstream>

// not initialized?
bool AutoConfigurationInfo::empty() const
{
    return type.empty();
}

// ext. attribute accessor
std::string AutoConfigurationInfo::getAttr(const std::string& attrName, const std::string& defValue) const
{
    const auto& it = attributes.find(attrName);
    return (it != attributes.end()) ? it->second : defValue;
}

// dbg, dump with filter on ext. attributes
std::string AutoConfigurationInfo::dump(const std::vector<std::string>& attrFilter) const
{
    if (empty()) { return "<empty>"; } // not initialized

    std::ostringstream oss;
    oss << type << "(" << subtype << ")/" << operation;

    for (const auto& it : attributes) {
        const std::string key{it.first};
        const std::string value{it.second};

        if (!attrFilter.empty()) {
            bool found{false};
            for (const auto& attr : attrFilter) {
                if (key.find(attr) != std::string::npos)
                    { found = true; break; }
            }
            if (!found) { continue; }
        }

        oss << "," << key << "=" << value;
    }
    return oss.str();
}

// eq. w/ fty_proto object
bool AutoConfigurationInfo::operator == (fty_proto_t* proto) const
{
    bool b;

    b = (operation == fty_proto_operation(proto))
        && (type == fty_proto_aux_string(proto, FTY_PROTO_ASSET_TYPE, ""))
        && (subtype == fty_proto_aux_string(proto, FTY_PROTO_ASSET_SUBTYPE, ""));
    if (!b) { return false; }

    // self is implicitly active, so we have to test it
    b = streq(fty_proto_aux_string(proto, FTY_PROTO_ASSET_STATUS, "active"), "active");
    if (!b) { return false; }

    // test all ext attributes
    std::map<std::string, std::string> msg_attributes = utils::zhash_to_map(fty_proto_ext(proto));
    return attributes.size() == msg_attributes.size()
           && std::equal(attributes.begin(), attributes.end(), msg_attributes.begin());
}
