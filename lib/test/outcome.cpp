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

#include "src/rule/outcome.h"
#include <fty_log.h>

TEST_CASE("outcome")
{
    using namespace outcome;

    REQUIRE(RULE_RESULT_LOW_CRITICAL == -2);
    REQUIRE(RULE_RESULT_UNKNOWN == 3);

    CHECK(resultToString(RULE_RESULT_LOW_CRITICAL - 1) == resultToString(RULE_RESULT_UNKNOWN));
    CHECK(resultToString(RULE_RESULT_UNKNOWN + 1) == resultToString(RULE_RESULT_UNKNOWN));

    CHECK(resultToInt("") == RULE_RESULT_UNKNOWN);
    CHECK(resultToInt("hello") == RULE_RESULT_UNKNOWN);

    for (const auto& r : {
        RULE_RESULT_LOW_CRITICAL,
        RULE_RESULT_LOW_WARNING,
        RULE_RESULT_OK,
        RULE_RESULT_HIGH_WARNING,
        RULE_RESULT_HIGH_CRITICAL,
        RULE_RESULT_UNKNOWN
    }
    ) {
        CHECK(r == resultToInt(resultToString(r)));
    }

    for (const auto& s : {
        "low_critical",
        "low_warning",
        "ok",
        "high_warning",
        "high_critical",
        "unknown"
    }
    ) {
        CHECK(s == resultToString(resultToInt(s)));
    }
}
