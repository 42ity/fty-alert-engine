/*
Copyright (C) 2014 - 2025 Eaton

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

/// @brief json cxxtools utilities

#pragma once

#include "rule/outcome.h"

#include <cxxtools/serializationinfo.h>
#include <string>
#include <map>

namespace JSON {

/// returns the member object if found, else nullptr
const cxxtools::SerializationInfo* findMember(const cxxtools::SerializationInfo& si, const std::string& name);
const cxxtools::SerializationInfo* findMember(const cxxtools::SerializationInfo* p, const std::string& name);

/// check object type
bool isObject(const cxxtools::SerializationInfo* p);
bool isArray(const cxxtools::SerializationInfo* p);
bool isValue(const cxxtools::SerializationInfo* p);

/// throw on error (p modified)
void setObjectProperty(cxxtools::SerializationInfo* p, const std::string& property, const std::string& value);

/// returns the string value, empty if error
/// no throw
std::string getStringUtf8(const cxxtools::SerializationInfo* p);
std::string getString(const cxxtools::SerializationInfo* p);

/// throw on error
std::map<std::string, double> getMapDouble(const cxxtools::SerializationInfo* p);
std::vector<std::string> getActions(const cxxtools::SerializationInfo* p);
///Outcome getOutcome(const cxxtools::SerializationInfo* p);
std::map<std::string, Outcome> getMapOutcome(const cxxtools::SerializationInfo* p);

} // namespace
