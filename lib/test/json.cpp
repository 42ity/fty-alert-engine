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

#include <catch2/catch.hpp>

#include "src/misc/json.h"
#include <fty_common_json.h>

TEST_CASE("json")
{
    using namespace JSON;

    SECTION("General")
    {
        std::string json = R"x( {
            "object0": {
            },
            "array0": [
            ],
            "value0": ""
        } )x";

        cxxtools::SerializationInfo si;
        REQUIRE_NOTHROW(readFromString(json, si));

        REQUIRE(findMember(si, "object0"));
        REQUIRE(findMember(si, "array0"));
        REQUIRE(findMember(si, "value0"));
        REQUIRE(findMember(si, "fake") == nullptr);
        REQUIRE(findMember(si, "") == nullptr);

        REQUIRE(findMember(&si, "object0"));
        REQUIRE(findMember(&si, "array0"));
        REQUIRE(findMember(&si, "value0"));
        REQUIRE(findMember(&si, "fake") == nullptr);
        REQUIRE(findMember(&si, "") == nullptr);

        REQUIRE( isObject(findMember(si, "object0")));
        REQUIRE(!isObject(findMember(si, "array0")));
        REQUIRE(!isObject(findMember(si, "value0")));

        REQUIRE(!isArray(findMember(si, "object0")));
        REQUIRE( isArray(findMember(si, "array0")));
        REQUIRE(!isArray(findMember(si, "value0")));

        REQUIRE(!isValue(findMember(si, "object0")));
        REQUIRE(!isValue(findMember(si, "array0")));
        REQUIRE( isValue(findMember(si, "value0")));
    }

    SECTION("getString")
    {
        std::string json = R"x( {
            "value0": "value",
            "value0-utf8": "value 你好"
        } )x";

        cxxtools::SerializationInfo si;
        REQUIRE_NOTHROW(readFromString(json, si));

        REQUIRE(getString(findMember(si, "")) == "");
        REQUIRE(getString(findMember(si, "fake")) == "");

        REQUIRE(getString(findMember(si, "value0")) == "value");
        REQUIRE(getString(findMember(si, "value0-utf8")) != "value 你好");

        REQUIRE(getStringUtf8(findMember(si, "value0")) == "value");
        REQUIRE(getStringUtf8(findMember(si, "value0-utf8")) == "value 你好");
    }

    SECTION("getMapDouble")
    {
        std::string json = R"x( {
            "object": {},
            "value": "",

            "array0": [],
            "array1": [{"key1": "4"}, {"key2": "3"}, {"key3": "2"}, {"key4": "1"}],
            "array2": [{"key1": "i am not a number"}]
        } )x";

        cxxtools::SerializationInfo si;
        REQUIRE_NOTHROW(readFromString(json, si));

        REQUIRE_THROWS(getMapDouble(findMember(si, "object")));
        REQUIRE_THROWS(getMapDouble(findMember(si, "value")));

        std::map<std::string, double> md;

        REQUIRE_NOTHROW(md = getMapDouble(findMember(si, "array0")));
        REQUIRE(md.size() == 0);

        REQUIRE_NOTHROW(md = getMapDouble(findMember(si, "array1")));
        REQUIRE(md.size() == 4);
        REQUIRE(md["key1"] == 4);
        REQUIRE(md["key2"] == 3);
        REQUIRE(md["key3"] == 2);
        REQUIRE(md["key4"] == 1);

        REQUIRE_THROWS(getMapDouble(findMember(si, "array2"))); // NaN
    }

    SECTION("getActions")
    {
        std::string json = R"x( {
            "object": {},
            "value": "",
            "array0": [],
            "array1": ["EMAIL", "SMS"],
            "array2": [{"action" : "SMS"}, {"action" : "EMAIL"}],
            "array3": [{"action" : "GPO_INTERACTION", "asset": "A", "mode": "M"}],
            "array4": [{"hacktion" : "not an 'action' member"}]
        } )x";

        cxxtools::SerializationInfo si;
        REQUIRE_NOTHROW(readFromString(json, si));

        REQUIRE_THROWS(getActions(findMember(si, "object")));
        REQUIRE_THROWS(getActions(findMember(si, "value")));

        std::vector<std::string> vs;

        REQUIRE_NOTHROW(vs = getActions(findMember(si, "array0")));
        REQUIRE(vs.size() == 0);

        REQUIRE_NOTHROW(vs = getActions(findMember(si, "array1")));
        REQUIRE(vs.size() == 2);
        REQUIRE(vs == std::vector<std::string>{"EMAIL", "SMS"});

        REQUIRE_NOTHROW(vs = getActions(findMember(si, "array2")));
        REQUIRE(vs.size() == 2);
        REQUIRE(vs == std::vector<std::string>{"SMS", "EMAIL"});

        REQUIRE_NOTHROW(vs = getActions(findMember(si, "array3")));
        REQUIRE(vs.size() == 1);
        REQUIRE(vs == std::vector<std::string>{"GPO_INTERACTION:A:M"});

        REQUIRE_THROWS(getActions(findMember(si, "array4")));
    }

    SECTION("getMapOutcome")
    {
        std::string json = R"x( {
            "object": {},
            "value": "",

            "array0": [
                {"low_critical": { "action" : [{"action": "SMS"}], "description" : "description1" }},
                {"low_warning" : { "action" : [{"action": "EMAIL"}], "description" : "description2" }},
                {"high_warning": { "action" : [{"action": "EMAIL"}], "description" : "description3" }},
                {"high_critical":{ "action" : [{"action": "FAKE"}], "description" : "description4" }}
            ],
            "array1": [
            ],
            "array2": [
                {"bad_token": { "action" : [{"action": "EMAIL"}, {"action":"SMS"}], "description" : "description1" }},
            ],
            "array3": [
                {"low_critical": { "hacktion" : [{"action": "EMAIL"}, {"action":"SMS"}], "description" : "description1" }}
            ],
        } )x";

        cxxtools::SerializationInfo si;
        REQUIRE_NOTHROW(readFromString(json, si));

        REQUIRE_THROWS(getMapOutcome(findMember(si, "object")));
        REQUIRE_THROWS(getMapOutcome(findMember(si, "value")));

        std::map<std::string, Outcome> mo;

        REQUIRE_NOTHROW(mo = getMapOutcome(findMember(si, "array0")));
        REQUIRE(mo.size() == 4);
        CHECK(mo["low_critical"]._actions == std::vector<std::string>{"SMS"});
        CHECK(mo["low_critical"]._description == "description1");
        CHECK(mo["low_critical"]._severity == "CRITICAL");
        CHECK(mo["low_warning"]._actions == std::vector<std::string>{"EMAIL"});
        CHECK(mo["low_warning"]._description == "description2");
        CHECK(mo["low_warning"]._severity == "WARNING");
        CHECK(mo["high_warning"]._actions == std::vector<std::string>{"EMAIL"});
        CHECK(mo["high_warning"]._description == "description3");
        CHECK(mo["high_warning"]._severity == "WARNING");
        CHECK(mo["high_critical"]._actions == std::vector<std::string>{"FAKE"});
        CHECK(mo["high_critical"]._description == "description4");
        CHECK(mo["high_critical"]._severity == "CRITICAL");

        REQUIRE_NOTHROW(mo = getMapOutcome(findMember(si, "array1")));
        REQUIRE(mo.size() == 0);

        REQUIRE_THROWS(getMapOutcome(findMember(si, "array2"))); // bad token

        REQUIRE_THROWS(getMapOutcome(findMember(si, "array3"))); // bad outcome fmt
    }
}

