/*
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
*/

#include "utils.h"

namespace utils {

std::map<std::string, std::string> zhash_to_map(zhash_t* hash)
{
    std::map<std::string, std::string> map;

    if (hash) {
        for (void* item = zhash_first(hash); item; item = zhash_next(hash))
        {
            const char* key = zhash_cursor(hash);
            const char* val = static_cast<const char*>(zhash_lookup(hash, key));
            if (key && val) {
                map[key] = val;
            }
        }
    }

    return map;
}

} // namespace utils
