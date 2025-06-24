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

#include "src/misc/utils.h"

TEST_CASE("utils")
{
    using namespace utils;

    SECTION("zhash_to_map")
    {
        CHECK(zhash_to_map(nullptr).empty());

        zhash_t* hash = zhash_new();
        zhash_autofree(hash);

        CHECK(zhash_to_map(hash).empty());

        zhash_insert(hash, "key0", const_cast<char*>("value0"));
        zhash_insert(hash, "key1", const_cast<char*>("value1"));
        zhash_insert(hash, "key2", const_cast<char*>("value1"));

        auto map = zhash_to_map(hash);

        CHECK(map.size() == 3);
        CHECK((map.count("key0") == 1 && map["key0"] == "value0"));
        CHECK((map.count("key1") == 1 && map["key1"] == "value1"));
        CHECK((map.count("key2") == 1 && map["key2"] == "value1"));

        zhash_destroy(&hash);
    }

    SECTION("replaceTokens")
    {
        CHECK(replaceTokens("", {}) == "");
        CHECK(replaceTokens("a", {}) == "a");
        CHECK(replaceTokens("a", { {"a", "b"} }) == "b");
        CHECK(replaceTokens("axa", { {"a", "b"}, {"b", "c"} }) == "cxc");

        CHECK(replaceTokens("hello world", { {" world", ""} }) == "hello");
        CHECK(replaceTokens("hello world", { {"hello", "你好"}, {" world", ""} }) == "你好");

        CHECK(replaceTokens("abc", { {"a", "aa"}, {"b", "bb"}, {"c", "cc"} }) == "aabbcc");
        CHECK(replaceTokens("aabbcc", { {"aa", "a"}, {"bb", "b"}, {"cc", "c"} }) == "abc");

        CHECK(replaceTokens("xyz", { {"a", "b"} }) == "xyz");
        CHECK(replaceTokens("xyz", { {"x", "x"}, {"z", "z"} }) == "xyz");
    }
}
