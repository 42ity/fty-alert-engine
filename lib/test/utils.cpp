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
#include <iostream>
#include <iomanip>

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

    SECTION("readFile")
    {
        const std::string dir("./test/testrules/");

        CHECK(readFile("").empty());
        CHECK(readFile(".").empty());
        CHECK(readFile("fake00").empty());
        CHECK(readFile("./fake00").empty());
        CHECK(readFile("/tmp/fake00").empty());
        CHECK(readFile(dir).empty());
        CHECK(readFile(dir + "fake").empty());

        CHECK(!readFile(dir + "single.rule").empty());
        CHECK(!readFile(dir + "pattern.rule").empty());
        CHECK(!readFile(dir + "simplethreshold.rule").empty());
        CHECK(!readFile(dir + "complexthreshold.rule").empty());
    }

    SECTION("parseDouble")
    {
        double d;

        CHECK(parseDouble(nullptr, d) != 0);
        CHECK(parseDouble("", d) != 0);
        CHECK(parseDouble("a", d) != 0);

        CHECK(parseDouble("0a", d) != 0);
        CHECK(parseDouble("a0", d) != 0);
        CHECK(parseDouble("0a0", d) != 0);
        CHECK(parseDouble("a0a", d) != 0);

        CHECK(parseDouble("0 ", d) != 0); // ZZZ
        CHECK(parseDouble("0  ", d) != 0);

        CHECK(parseDouble(" 0", d) == 0);
        CHECK(parseDouble("  0", d) == 0);
        CHECK(parseDouble("+0", d) == 0);
        CHECK(parseDouble("-0", d) == 0);

        CHECK(parseDouble("-100", d) == 0);
        CHECK(parseDouble("-10", d) == 0);
        CHECK(parseDouble("-1", d) == 0);
        CHECK(parseDouble("0", d) == 0);
        CHECK(parseDouble("1", d) == 0);
        CHECK(parseDouble("10", d) == 0);
        CHECK(parseDouble("100", d) == 0);

        CHECK(parseDouble("-100.0", d) == 0);
        CHECK(parseDouble("-10.0", d) == 0);
        CHECK(parseDouble("-1.0", d) == 0);
        CHECK(parseDouble("0.0", d) == 0);
        CHECK(parseDouble("1.0", d) == 0);
        CHECK(parseDouble("10.0", d) == 0);
        CHECK(parseDouble("100.0", d) == 0);

        CHECK(parseDouble("-1e2", d) == 0);
        CHECK(parseDouble("-1e1", d) == 0);
        CHECK(parseDouble("-1e0", d) == 0);
        CHECK(parseDouble("1e0", d) == 0);
        CHECK(parseDouble("1e1", d) == 0);
        CHECK(parseDouble("1e2", d) == 0);

        CHECK(parseDouble("-1.e0", d) == 0);
        CHECK(parseDouble("1.e0", d) == 0);

        CHECK(parseDouble("-1.000001", d) == 0);
        CHECK(parseDouble("0.000001", d) == 0);
        CHECK(parseDouble("1.000001", d) == 0);
    }

    SECTION("parseDouble accuracy")
    {
        auto isCloseTo = [] (const char* s, double p, double eps /*>=0*/) {
            double val;
            int r = parseDouble(s, val);
            if (r != 0) { std::cout << "r: " << r << std::endl; return false; }
            std::cout << "r: " << r << ", s: '" << s << "', val: " << val << ", p: " << p << std::endl;
            return ((p - eps) <= val) && (val <= (p + eps));
        };

        const double eps = 1e-08;
        std::cout << std::fixed << std::setprecision(10);

        CHECK(isCloseTo("-1000", -1000, eps));
        CHECK(isCloseTo("-100", -100, eps));
        CHECK(isCloseTo("-10", -10, eps));
        CHECK(isCloseTo("-1", -1, eps));
        CHECK(isCloseTo("0", 0, eps));
        CHECK(isCloseTo("1", 1, eps));
        CHECK(isCloseTo("10", 10, eps));
        CHECK(isCloseTo("100", 100, eps));
        CHECK(isCloseTo("1000", 1000, eps));

        CHECK(isCloseTo("-100.00000001", -100.00000001, eps));
        CHECK(isCloseTo("-10.00000001", -10.00000001, eps));
        CHECK(isCloseTo("-1.00000001", -1.00000001, eps));
        CHECK(isCloseTo("0.00000001", 0.00000001, eps));
        CHECK(isCloseTo("1.00000001", 1.00000001, eps));
        CHECK(isCloseTo("10.00000001", 10.00000001, eps));
        CHECK(isCloseTo("100.00000001", 100.00000001, eps));

        CHECK(isCloseTo("-1.000000001e2", -100.0000001, eps));
        CHECK(isCloseTo( "1.000000001e2",  100.0000001, eps));

        CHECK(isCloseTo("-1.1e-08", -1.1e-8, eps));
        CHECK(isCloseTo( "1.1e-08",  1.1e-8, eps));

        CHECK(isCloseTo("-1.1e+08", -1.1e+8, eps));
        CHECK(isCloseTo( "1.1e+08",  1.1e+8, eps));
    }
}
